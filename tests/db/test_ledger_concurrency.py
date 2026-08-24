"""50 parallel writers against one mandate. The test that matters most.

Three properties, all under maximum contention — every writer on the *same* mandate, which
is the worst case for the mandate-row lock and the case the demo's budget breacher creates:

1. ``balance_after >= 0`` always. No overspend, ever.
2. ``sum(deltas) == final balance``. The ledger reconciles.
3. Concurrent attempts to spend the same budget produce exactly the number of successes the
   arithmetic allows — not one more.

And the tripwire: ``UNIQUE (mandate_id, prev_entry_id)`` must never fire. If it does, the
mandate-row lock is not holding and the database caught an overspend the CHECK would have
missed. See ADR 0001 Q2.
"""

from __future__ import annotations

import asyncio

import psycopg
import pytest

from dwaar.db.repositories import budget_ledger
from dwaar.errors import InsufficientBudget

pytestmark = pytest.mark.db

WRITERS = 50


async def _reserve_once(dsn: str, mandate_id: str, amount: int, key: str) -> str:
    """One writer, one connection, one transaction. Returns an outcome label."""
    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        try:
            await budget_ledger.reserve(
                conn, mandate_id=mandate_id, amount_paise=amount, idempotency_key=key
            )
            await conn.commit()
            return "ok"
        except InsufficientBudget:
            await conn.rollback()
            return "denied"
        except Exception as exc:  # noqa: BLE001
            await conn.rollback()
            return f"error:{type(exc).__name__}:{exc}"


@pytest.fixture
async def committed_mandate(owner_dsn, make_mandate):
    """A mandate that really exists, so 50 separate connections can see it."""
    conn = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(conn, max_total_paise=1_000_000, max_per_txn_paise=1_000_000)
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


async def test_fifty_parallel_writers_never_overspend(app_dsn, owner_dsn, committed_mandate):
    """₹10,000 of budget, 50 writers each trying to take ₹500. Exactly 20 may succeed."""
    mandate_id = committed_mandate["mandate_id"]
    amount = 50_000  # ₹500
    budget = 1_000_000  # ₹10,000
    expected_successes = budget // amount  # 20

    results = await asyncio.gather(
        *(
            _reserve_once(app_dsn, mandate_id, amount, f"conc-{mandate_id}-{i}")
            for i in range(WRITERS)
        )
    )

    errors = [r for r in results if r.startswith("error:")]
    assert not errors, f"writers failed unexpectedly: {errors[:5]}"

    successes = results.count("ok")
    denials = results.count("denied")

    assert successes == expected_successes, (
        f"expected exactly {expected_successes} successful reservations against "
        f"{budget} paise at {amount} paise each, got {successes}. "
        "More than expected means the mandate-row lock is not serialising writers."
    )
    assert successes + denials == WRITERS

    conn = await psycopg.AsyncConnection.connect(owner_dsn)
    try:
        final = await budget_ledger.balance(conn, mandate_id)
        entries = await budget_ledger.history(conn, mandate_id)
    finally:
        await conn.close()

    assert final == 0, f"budget should be exactly exhausted, got {final} paise"
    assert final >= 0

    total_delta = sum(e["delta_paise"] for e in entries)
    assert total_delta == final, (
        f"sum(deltas)={total_delta} must equal final balance={final}"
    )

    assert all(e["balance_after"] >= 0 for e in entries), "balance_after went negative"


async def test_ledger_chain_is_unbroken_after_concurrency(
    app_dsn, owner_dsn, committed_mandate
):
    """Every non-genesis entry points at its immediate predecessor.

    The tripwire guarantees uniqueness; this asserts the chain is also *contiguous*, which
    uniqueness alone does not give you.
    """
    mandate_id = committed_mandate["mandate_id"]
    await asyncio.gather(
        *(
            _reserve_once(app_dsn, mandate_id, 10_000, f"chain-{mandate_id}-{i}")
            for i in range(WRITERS)
        )
    )

    conn = await psycopg.AsyncConnection.connect(owner_dsn)
    try:
        entries = await budget_ledger.history(conn, mandate_id)
    finally:
        await conn.close()

    assert entries[0]["prev_entry_id"] is None, "the first entry must be genesis"
    assert entries[0]["reason"] == "mandate_created"

    for previous, current in zip(entries, entries[1:], strict=False):
        assert current["prev_entry_id"] == previous["entry_id"], (
            f"ledger chain broken: entry {current['entry_id']} points at "
            f"{current['prev_entry_id']}, expected {previous['entry_id']}"
        )
        assert current["balance_after"] == previous["balance_after"] + current["delta_paise"]


async def test_duplicate_idempotency_key_under_concurrency_charges_once(
    app_dsn, owner_dsn, committed_mandate
):
    """The duplicate-webhook case, raced.

    50 concurrent deliveries of the *same* key must produce exactly one ledger entry, and
    the budget must move exactly once.
    """
    mandate_id = committed_mandate["mandate_id"]
    key = f"dupe-{mandate_id}"
    amount = 50_000

    results = await asyncio.gather(
        *(_reserve_once(app_dsn, mandate_id, amount, key) for _ in range(WRITERS))
    )
    errors = [r for r in results if r.startswith("error:")]
    assert not errors, f"duplicate-key writers failed: {errors[:5]}"

    conn = await psycopg.AsyncConnection.connect(owner_dsn)
    try:
        entries = await budget_ledger.history(conn, mandate_id)
        final = await budget_ledger.balance(conn, mandate_id)
    finally:
        await conn.close()

    charged = [e for e in entries if e["idempotency_key"] == key]
    assert len(charged) == 1, (
        f"idempotency_key {key!r} produced {len(charged)} ledger entries; "
        "a duplicate webhook must be absorbed, not charged twice"
    )
    assert final == 1_000_000 - amount


async def test_tripwire_never_fires_under_correct_locking(
    app_dsn, owner_dsn, committed_mandate
):
    """UNIQUE (mandate_id, prev_entry_id) must not fire. It is a tripwire, not a mechanism.

    A LedgerError naming the tripwire would mean two writers got past the mandate lock —
    which is the failure this whole design exists to make impossible rather than unlikely.
    """
    mandate_id = committed_mandate["mandate_id"]
    results = await asyncio.gather(
        *(
            _reserve_once(app_dsn, mandate_id, 1_000, f"trip-{mandate_id}-{i}")
            for i in range(WRITERS)
        )
    )
    tripped = [r for r in results if "tripwire" in r]
    assert not tripped, (
        "the ledger chain tripwire fired, which means the mandate row lock is not "
        f"serialising writers: {tripped[:3]}"
    )


async def test_invariants_hold_globally(owner_dsn, migrated):
    """Invariant 1 from schema.sql, computed at run time. Never hardcoded."""
    conn = await psycopg.AsyncConnection.connect(owner_dsn)
    try:
        result = await budget_ledger.check_invariants(conn)
    finally:
        await conn.close()

    assert result["negative_balances"] == 0, "balance_after < 0 exists — the hard invariant broke"
    assert result["sum_delta_drift"] == 0, "sum(deltas) != balance for at least one mandate"
