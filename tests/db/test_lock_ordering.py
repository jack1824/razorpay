"""Lock ordering is an invariant, not a preference.

    mandate row lock (stage 6)  →  chain advisory lock (stage 8)

Always this order, everywhere. Two transactions on one merchant taking them in opposite
orders deadlock, and PostgreSQL resolves that by killing one of them — a 500 on a money
decision, intermittent, load-dependent, and effectively undebuggable from the logs.

These tests do three things:

1. Prove the hazard is real by deliberately inverting the order and observing the deadlock.
   Without this, the invariant is folklore.
2. Prove the pipeline takes them in the correct order, structurally.
3. Prove concurrent pipeline runs on one mandate and one merchant never deadlock.
"""

from __future__ import annotations

import asyncio

import psycopg
import pytest

from dwaar.authorize import pipeline
from dwaar.authorize.types import AuthorizeRequest
from dwaar.crypto import http_sig
from dwaar.crypto import keys as keymod
from dwaar.crypto.signer import ensure_registered

#: The REAL detector. Needs no artifact and no session — eleven arithmetic
#: features — so a test running without one would only be exercising the
#: not-checked path, and every record it wrote would carry a NULL flag.
from dwaar.risk import injection as _injection
from tests.conftest import AGENT_SEED, rand_id

DETECTOR = _injection.load()

pytestmark = pytest.mark.db


def _signed(mandate, key: str):
    """One signed request. Signing happens outside the contended region on purpose."""
    import json
    import time
    import uuid

    request = AuthorizeRequest(
        agent_id=mandate["agent_id"], mandate_id=mandate["mandate_id"],
        action="purchase", amount_paise=1_000, idempotency_key=key, category="groceries",
    )
    body = json.dumps(
        {
            "agent_id": request.agent_id, "mandate_id": request.mandate_id,
            "action": request.action, "amount_paise": request.amount_paise,
            "idempotency_key": request.idempotency_key, "category": request.category,
        },
        separators=(",", ":"),
    ).encode()
    private = keymod.derive_private_key(AGENT_SEED, "agent", request.agent_id)
    headers = http_sig.sign_request(
        private, method="POST", path="/v1/authorize", body=body,
        keyid=request.agent_id, created=int(time.time()), nonce=uuid.uuid4().hex,
    )
    return request, headers, body


@pytest.fixture
async def locked_scenario(owner_dsn, make_mandate, signer):
    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(setup, merchant_id=merchant, max_total_paise=100_000_000)
    await ensure_registered(setup, signer)
    await setup.commit()
    await setup.close()

    yield merchant, mandate

    cleanup = await psycopg.AsyncConnection.connect(owner_dsn)
    async with cleanup.cursor() as cur:
        await cur.execute("DELETE FROM decision_records WHERE merchant_id = %s", (merchant,))
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


def test_the_pipeline_takes_the_locks_in_the_documented_order():
    """Structural: stage 6 (mandate lock) precedes stage 8 (chain lock) in STAGE_ORDER.

    Cheap, and it fails loudly if someone reorders the pipeline without thinking about
    locks — which is exactly the change that would introduce the deadlock.
    """
    order = list(pipeline.STAGE_ORDER)
    assert order.index("reserve_budget") < order.index("write_decision_record"), (
        "reserve_budget takes the mandate row lock and write_decision_record takes the "
        "chain advisory lock. Reversing them lets two concurrent requests on one merchant "
        "deadlock."
    )


async def test_inverting_the_order_actually_deadlocks(app_dsn, locked_scenario):
    """The hazard, demonstrated. Without this the invariant above is just a comment.

    Transaction A: mandate lock, then chain lock.  (the correct order)
    Transaction B: chain lock, then mandate lock.  (inverted)

    Each holds what the other wants. `lock_timeout` bounds the test so a genuine deadlock
    surfaces as an error rather than hanging the suite.
    """
    merchant, mandate = locked_scenario
    mandate_id = mandate["mandate_id"]
    both_ready = asyncio.Event()
    first_locked = asyncio.Event()

    async def correct_order() -> str:
        async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
            await conn.set_autocommit(False)
            async with conn.cursor() as cur:
                await cur.execute("SET lock_timeout = '2s'")
                await cur.execute(
                    "SELECT 1 FROM mandates WHERE mandate_id = %s FOR UPDATE", (mandate_id,)
                )
                first_locked.set()
                await both_ready.wait()
                try:
                    await cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (merchant,))
                except psycopg.Error as exc:
                    await conn.rollback()
                    return f"blocked:{type(exc).__name__}"
            await conn.rollback()
            return "ok"

    async def inverted_order() -> str:
        async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
            await conn.set_autocommit(False)
            async with conn.cursor() as cur:
                await cur.execute("SET lock_timeout = '2s'")
                await cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (merchant,))
                await first_locked.wait()
                both_ready.set()
                try:
                    await cur.execute(
                        "SELECT 1 FROM mandates WHERE mandate_id = %s FOR UPDATE", (mandate_id,)
                    )
                except psycopg.Error as exc:
                    await conn.rollback()
                    return f"blocked:{type(exc).__name__}"
            await conn.rollback()
            return "ok"

    results = await asyncio.gather(correct_order(), inverted_order(), return_exceptions=True)
    blocked = [r for r in results if isinstance(r, str) and r.startswith("blocked:")]

    assert blocked, (
        "inverting the lock order did not produce contention, so this test is not "
        f"demonstrating the hazard it claims to. Results: {results}"
    )


async def test_concurrent_pipeline_runs_never_deadlock(
    app_dsn, owner_dsn, locked_scenario, signer, settings, nonce_store
):
    """The invariant paying off: 30 concurrent requests, one mandate, one merchant.

    Maximum contention on BOTH locks simultaneously. Every one must succeed.
    """
    merchant, mandate = locked_scenario

    async def one(i: int) -> str:
        async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
            try:
                await conn.set_autocommit(False)
                async with conn.cursor() as cur:
                    await cur.execute("SET lock_timeout = '10s'")
                request, headers, body = _signed(mandate, f"lock-{i:04d}-{'x' * 8}")
                await pipeline.authorize(
                    request, conn=conn, signer=signer, settings=settings,
                    headers=headers, body=body, nonce_store=nonce_store, detector=DETECTOR,
                )
                await conn.commit()
                return "ok"
            except Exception as exc:  # noqa: BLE001
                await conn.rollback()
                return f"error:{type(exc).__name__}:{exc}"

    results = await asyncio.gather(*(one(i) for i in range(30)))
    errors = [r for r in results if r.startswith("error:")]

    assert not errors, (
        "concurrent authorize deadlocked or errored under maximum lock contention: "
        f"{errors[:3]}"
    )
    assert results.count("ok") == 30

    from dwaar.db.repositories import decision_records

    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        verified = await decision_records.verify_chain(conn, merchant)
    assert verified["ok"] is True, verified
    assert verified["records"] == 30
