"""`idempotency_key` uniqueness under concurrent insert.

The duplicate webhook is the most common real bug in payment integrations, and it is a
*race*, not a sequence: the retry usually arrives while the original is still in flight. A
test that inserts twice in a row proves the constraint exists; it does not prove the
application survives the constraint firing.
"""

from __future__ import annotations

import asyncio

import psycopg
import pytest
from psycopg.errors import UniqueViolation

from dwaar.db.repositories import budget_ledger, mandates

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


async def test_raw_concurrent_insert_of_same_key_yields_exactly_one_winner(
    app_dsn, committed_mandate
):
    """At the SQL level: N racing inserts, one commit, N-1 UniqueViolation.

    Deliberately bypasses ``reserve()``. This asserts the *constraint* is the thing
    providing safety, not the read-then-write check in application code — which is exactly
    the check a race defeats.
    """
    mandate_id = committed_mandate["mandate_id"]
    key = f"raw-{mandate_id}"
    racers = 20

    async def insert_directly() -> str:
        async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT entry_id, balance_after FROM budget_ledger "
                        "WHERE mandate_id = %s ORDER BY entry_id DESC LIMIT 1",
                        (mandate_id,),
                    )
                    tail = await cur.fetchone()
                    await cur.execute(
                        "INSERT INTO budget_ledger "
                        "(mandate_id, prev_entry_id, delta_paise, balance_after, "
                        " idempotency_key, reason) VALUES (%s,%s,%s,%s,%s,%s)",
                        (mandate_id, tail[0], -1000, tail[1] - 1000, key, "raw"),
                    )
                await conn.commit()
                return "ok"
            except UniqueViolation:
                await conn.rollback()
                return "duplicate"
            except Exception as exc:  # noqa: BLE001
                await conn.rollback()
                return f"error:{type(exc).__name__}"

    results = await asyncio.gather(*(insert_directly() for _ in range(racers)))

    assert results.count("ok") == 1, (
        f"exactly one insert must win, got {results.count('ok')}: {results}"
    )
    assert results.count("duplicate") + results.count("ok") == racers, (
        f"unexpected outcomes: {[r for r in results if r.startswith('error:')][:5]}"
    )


async def test_reserve_absorbs_the_duplicate_instead_of_raising(app_dsn, committed_mandate):
    """The application must not surface a UniqueViolation for a retried webhook.

    A retry is the network doing its job. ``reserve()`` returns the existing entry with
    ``duplicate=True`` rather than an error the caller has to special-case.
    """
    mandate_id = committed_mandate["mandate_id"]
    key = f"absorb-{mandate_id}"

    async def reserve() -> tuple[str, int, bool]:
        async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
            result = await budget_ledger.reserve(
                conn, mandate_id=mandate_id, amount_paise=25_000, idempotency_key=key
            )
            await conn.commit()
            return ("ok", result.entry_id, result.duplicate)

    outcomes = await asyncio.gather(*(reserve() for _ in range(15)), return_exceptions=True)

    raised = [o for o in outcomes if isinstance(o, Exception)]
    assert not raised, f"reserve() must absorb duplicates, not raise: {raised[:3]}"

    entry_ids = {o[1] for o in outcomes}
    assert len(entry_ids) == 1, f"all callers must see the same entry, got {entry_ids}"

    assert sum(1 for o in outcomes if not o[2]) <= 1, (
        "at most one caller may be told it created the entry"
    )


async def test_genesis_key_prevents_double_initialisation(owner_dsn, committed_mandate):
    """`genesis:<mandate_id>` doubles as the 'already initialised' guard.

    This matters more than it looks: NULLs are distinct in a PostgreSQL unique index, so
    UNIQUE (mandate_id, prev_entry_id) does NOT constrain genesis rows. The idempotency key
    is the only thing standing between a mandate and a doubled budget.
    """
    mandate_id = committed_mandate["mandate_id"]

    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        with pytest.raises(UniqueViolation):
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO budget_ledger "
                    "(mandate_id, prev_entry_id, delta_paise, balance_after, "
                    " idempotency_key, reason) VALUES (%s, NULL, %s, %s, %s, %s)",
                    (
                        mandate_id,
                        10_000_000,
                        20_000_000,
                        mandates.genesis_key(mandate_id),
                        "mandate_created",
                    ),
                )
        await conn.rollback()


async def test_release_is_a_compensating_entry_not_an_edit(app_dsn, committed_mandate):
    """Releasing restores the balance by appending, never by touching the reserving row."""
    mandate_id = committed_mandate["mandate_id"]

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        opening = await budget_ledger.balance(conn, mandate_id)
        reserved = await budget_ledger.reserve(
            conn,
            mandate_id=mandate_id,
            amount_paise=75_000,
            idempotency_key=f"rel-res-{mandate_id}",
        )
        released = await budget_ledger.release(
            conn,
            mandate_id=mandate_id,
            amount_paise=75_000,
            idempotency_key=f"rel-rel-{mandate_id}",
        )
        await conn.commit()

        assert reserved.balance_after == opening - 75_000
        assert released.balance_after == opening

        entries = await budget_ledger.history(conn, mandate_id)
        assert len(entries) == 3, "genesis + reserve + release; the reserve row is untouched"
        assert sum(e["delta_paise"] for e in entries) == opening
