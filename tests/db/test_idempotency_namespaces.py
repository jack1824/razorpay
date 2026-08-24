"""Idempotency namespaces: the security property, not the tidiness one.

Client keys are prefixed `rsv:` server-side. Without that, an agent submits
`idempotency_key = "release:1234"`, and when the system later releases ledger entry 1234
its derived key collides with the agent's existing row. The insert is absorbed as a
duplicate, **the release silently no-ops, and that reservation leaks permanently** — budget
consumed forever against nothing.

Prefixing makes the namespaces disjoint by construction, so no validation of agent input is
required. That distinction matters: validation is a rule someone can forget at a new call
site; a namespace that cannot overlap is a property of the data.
"""

from __future__ import annotations

import psycopg
import pytest

from dwaar import idempotency
from dwaar.db.repositories import budget_ledger
from tests.conftest import rand_id

pytestmark = pytest.mark.db


@pytest.fixture
async def committed_mandate(owner_dsn, make_mandate):
    conn = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(conn, max_total_paise=10_000_000, max_per_txn_paise=1_000_000)
    await conn.commit()
    await conn.close()

    yield mandate

    cleanup = await psycopg.AsyncConnection.connect(owner_dsn)
    async with cleanup.cursor() as cur:
        await cur.execute(
            "DELETE FROM budget_ledger WHERE mandate_id = %s", (mandate["mandate_id"],)
        )
        await cur.execute("DELETE FROM mandates WHERE mandate_id = %s", (mandate["mandate_id"],))
        await cur.execute("DELETE FROM agents WHERE agent_id = %s", (mandate["agent_id"],))
        await cur.execute(
            "DELETE FROM principals WHERE principal_id = %s", (mandate["principal_id"],)
        )
    await cleanup.commit()
    await cleanup.close()


# ── derivation rules ────────────────────────────────────────────────────────────────

def test_namespaces_are_disjoint():
    """No derived key can be produced by another derivation."""
    keys = {
        idempotency.genesis_key("mnd_x"),
        idempotency.reserve_key("mnd_x"),
        idempotency.release_key(1),
        idempotency.settle_key(1),
    }
    assert len(keys) == 4
    assert all(idempotency.namespace_of(k) is not None for k in keys)


def test_a_client_key_can_never_land_in_a_server_namespace():
    """The whole point. An agent choosing an adversarial string still lands in `rsv:`."""
    for hostile in ("release:1234", "settle:1234", "genesis:mnd_victim", "rsv:x", ""):
        stored = idempotency.reserve_key(hostile)
        assert idempotency.namespace_of(stored) == idempotency.RESERVE
        assert stored.startswith("rsv:")


# ── the attack, against the real ledger ─────────────────────────────────────────────

async def test_a_forged_release_key_cannot_no_op_a_real_release(app_dsn, committed_mandate):
    """THE test this namespace scheme exists for.

    The agent reserves with `idempotency_key = "release:<n>"`, guessing at the id its own
    reservation will get. Later the system releases that reservation. Without prefixing,
    the release collides with the agent's own row, is absorbed as a duplicate, and the
    budget is never returned.
    """
    mandate_id = committed_mandate["mandate_id"]

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        opening = await budget_ledger.balance(conn, mandate_id)

        # The agent reserves, naming its key after the release namespace.
        reserved = await budget_ledger.reserve(
            conn, mandate_id=mandate_id, amount_paise=100_000,
            idempotency_key=f"release:{rand_id('guess')}",
        )
        await conn.commit()
        assert reserved.balance_after == opening - 100_000

        # A second reservation whose key is *exactly* the release key of the first.
        hostile = await budget_ledger.reserve(
            conn, mandate_id=mandate_id, amount_paise=1_000,
            idempotency_key=idempotency.release_key(reserved.entry_id),
        )
        await conn.commit()
        assert hostile.duplicate is False, "the forged key must not collide with anything yet"

        # Now the system releases the first reservation. It must actually happen.
        released = await budget_ledger.release(
            conn, mandate_id=mandate_id, amount_paise=100_000,
            reserve_entry_id=reserved.entry_id,
        )
        await conn.commit()

    assert released.duplicate is False, (
        "the release was absorbed as a duplicate of an agent-supplied key. The reservation "
        "has leaked: budget consumed permanently with nothing to show for it."
    )
    assert released.balance_after == opening - 1_000


async def test_a_duplicate_release_is_absorbed(app_dsn, committed_mandate):
    """Derived keys make releases idempotent for free — no caller has to remember."""
    mandate_id = committed_mandate["mandate_id"]

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        opening = await budget_ledger.balance(conn, mandate_id)
        reserved = await budget_ledger.reserve(
            conn, mandate_id=mandate_id, amount_paise=50_000,
            idempotency_key=rand_id("k"),
        )
        first = await budget_ledger.release(
            conn, mandate_id=mandate_id, amount_paise=50_000,
            reserve_entry_id=reserved.entry_id,
        )
        second = await budget_ledger.release(
            conn, mandate_id=mandate_id, amount_paise=50_000,
            reserve_entry_id=reserved.entry_id,
        )
        await conn.commit()

    assert first.duplicate is False
    assert second.duplicate is True
    assert second.entry_id == first.entry_id
    assert second.balance_after == opening, "a double release must not double-credit"


# ── scope ───────────────────────────────────────────────────────────────────────────

async def test_the_same_client_key_on_two_mandates_is_two_entries(
    owner_dsn, app_dsn, make_mandate
):
    """Mandate-scoped, not global.

    Global uniqueness let agent A burn agent B's key on an unrelated mandate — a
    cross-tenant denial of service, and an oracle telling A that B is using that key.
    """
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    first = await make_mandate(setup, merchant_id=rand_id("mch"))
    second = await make_mandate(setup, merchant_id=rand_id("mch"))
    await setup.commit()
    await setup.close()

    shared = rand_id("shared")
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        a = await budget_ledger.reserve(
            conn, mandate_id=first["mandate_id"], amount_paise=1_000, idempotency_key=shared
        )
        b = await budget_ledger.reserve(
            conn, mandate_id=second["mandate_id"], amount_paise=1_000, idempotency_key=shared
        )
        await conn.commit()

    assert a.entry_id != b.entry_id
    assert a.duplicate is False and b.duplicate is False


async def test_every_stored_key_carries_a_known_namespace(owner_dsn, committed_mandate):
    """Nothing escapes namespacing — asserted against the whole table, not one row."""
    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        rows = await budget_ledger.history(conn, committed_mandate["mandate_id"])
        async with conn.cursor() as cur:
            await cur.execute("SELECT DISTINCT idempotency_key FROM budget_ledger")
            everything = [r[0] for r in await cur.fetchall()]

    assert rows
    unnamespaced = [k for k in everything if idempotency.namespace_of(k) is None]
    assert not unnamespaced, (
        f"stored keys without a namespace: {unnamespaced[:5]}. Migration 0012 prefixes "
        "legacy rows; a new one means a call site bypassed the derivation helpers."
    )
