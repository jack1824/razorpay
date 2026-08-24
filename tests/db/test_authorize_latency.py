"""Latency gates, in CI, from day 3.

The strategy package puts this on day 12. That is far too late: discovering we are at
300ms on day 11 is how this project dies, because by then the pipeline has nine stages and
no one knows which one did it.

**Two gates, deliberately asymmetric:**

    pipeline p99 < 25ms    TIGHT. Measured in-process, excluding HTTP framing and network.
                           This is what the stage budgets in ARCHITECTURE.md sum to, and it
                           is the number the pitch may quote — with that clause attached,
                           every time.

    HTTP p99 < 150ms       LOOSE. Cannot flake on shared-runner variance, but catches a
                           catastrophic regression — a blocking call in middleware, a
                           connection acquired per request, an accidental sync driver.

Gating only the pipeline would let a blocking call in middleware sail through. Gating HTTP
tightly would flake on a noisy runner, and a flaky gate gets disabled, which returns us to
discovering 300ms on day 11. Hence one of each.

**Requests are signed outside every timed region.** Ed25519 signing is the *agent's* cost,
not the gateway's; folding it in would inflate a number we then quote as ours. Signature
*verification* is inside, because stage 1 is inside.
"""

from __future__ import annotations

import json
import statistics
import time
import uuid

import psycopg
import pytest

from dwaar.authorize import pipeline
from dwaar.authorize.types import AuthorizeRequest
from dwaar.crypto import http_sig
from dwaar.crypto import keys as keymod
from dwaar.crypto.signer import ensure_registered
from tests.conftest import AGENT_SEED, REDIS_URL, rand_id

pytestmark = pytest.mark.db

REQUESTS = 1_000
PIPELINE_P99_BUDGET_MS = 25.0
HTTP_P99_GUARD_RAIL_MS = 150.0


def _signed(mandate, key: str):
    """Build one signed request. Called outside timed regions on purpose."""
    request = AuthorizeRequest(
        agent_id=mandate["agent_id"],
        mandate_id=mandate["mandate_id"],
        action="purchase",
        amount_paise=1_000,
        idempotency_key=key,
        category="groceries",
    )
    body = json.dumps(
        {
            "agent_id": request.agent_id,
            "mandate_id": request.mandate_id,
            "action": request.action,
            "amount_paise": request.amount_paise,
            "idempotency_key": request.idempotency_key,
            "category": request.category,
        },
        separators=(",", ":"),
    ).encode()
    private = keymod.derive_private_key(AGENT_SEED, "agent", request.agent_id)
    headers = http_sig.sign_request(
        private,
        method="POST",
        path="/v1/authorize",
        body=body,
        keyid=request.agent_id,
        created=int(time.time()),
        nonce=uuid.uuid4().hex,
    )
    return request, headers, body


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    index = min(int(len(ordered) * p), len(ordered) - 1)
    return ordered[index]


def report(label: str, samples_ms: list[float]) -> str:
    return (
        f"{label}: n={len(samples_ms)} "
        f"p50={percentile(samples_ms, 0.50):.2f}ms "
        f"p95={percentile(samples_ms, 0.95):.2f}ms "
        f"p99={percentile(samples_ms, 0.99):.2f}ms "
        f"max={max(samples_ms):.2f}ms mean={statistics.mean(samples_ms):.2f}ms"
    )


@pytest.fixture
async def bench_mandate(owner_dsn, make_mandate, signer):
    """A mandate with headroom for 1,000 requests, on its own merchant chain."""
    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(
        setup,
        merchant_id=merchant,
        max_total_paise=10_000_000_000,
        max_per_txn_paise=500_000,
    )
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


async def test_pipeline_p99_under_25ms(
    app_dsn, bench_mandate, signer, settings, nonce_store, capsys
):
    """THE gate. 1,000 requests through the full pipeline including the chain write."""
    _merchant, mandate = bench_mandate
    warmup = [_signed(mandate, f"warm-{i:04d}-{'x' * 8}") for i in range(20)]
    prepared = [_signed(mandate, f"bench-{i:06d}-{'x' * 8}") for i in range(REQUESTS)]
    samples: list[float] = []

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        # Warm the pool, the prepared statements and the chain tail before measuring.
        for request, headers, body in warmup:
            await pipeline.authorize(
                request, conn=conn, signer=signer, settings=settings,
                headers=headers, body=body, nonce_store=nonce_store,
            )
            await conn.commit()

        for request, headers, body in prepared:
            started = time.perf_counter()
            await pipeline.authorize(
                request, conn=conn, signer=signer, settings=settings,
                headers=headers, body=body, nonce_store=nonce_store,
            )
            await conn.commit()
            samples.append((time.perf_counter() - started) * 1000)

    line = report("pipeline", samples)
    with capsys.disabled():
        print(f"\n  {line}")

    p99 = percentile(samples, 0.99)
    assert p99 < PIPELINE_P99_BUDGET_MS, (
        f"p99 {p99:.2f}ms exceeds the {PIPELINE_P99_BUDGET_MS}ms budget. {line}\n"
        "Per-stage timings are on every log line — find the stage before optimising."
    )


async def test_no_single_stage_dominates(
    app_dsn, bench_mandate, signer, settings, nonce_store, capsys
):
    """The stage split exists to make a regression attributable, so assert it stays so.

    A p99 that passes while one stage eats most of it is a p99 that will fail next week for
    a reason nobody can locate.
    """
    _merchant, mandate = bench_mandate
    prepared = [_signed(mandate, f"stage-{i:05d}-{'x' * 8}") for i in range(200)]
    per_stage: dict[str, list[int]] = {}

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        for request, headers, body in prepared:
            outcome = await pipeline.authorize(
                request, conn=conn, signer=signer, settings=settings,
                headers=headers, body=body, nonce_store=nonce_store,
            )
            await conn.commit()
            for stage, micros in outcome.stage_timings_us.items():
                per_stage.setdefault(stage, []).append(micros)

    with capsys.disabled():
        print()
        for stage in pipeline.STAGE_ORDER:
            if stage in per_stage:
                values = per_stage[stage]
                print(f"  {stage:<24} p99={percentile(values, 0.99) / 1000:7.3f}ms")

    total_p99 = sum(percentile(v, 0.99) for v in per_stage.values())
    for stage, values in per_stage.items():
        share = percentile(values, 0.99) / total_p99
        assert share < 0.80, (
            f"{stage} accounts for {share:.0%} of p99. A single dominant stage makes every "
            "future regression unattributable."
        )


async def test_http_p99_guard_rail(app_dsn, migrate_dsn_for_http, bench_mandate, capsys):
    """LOOSE, on purpose.

    A tight HTTP gate flakes on shared-runner variance, and a flaky gate gets disabled.
    This one only catches catastrophe. The real p99 is printed so variance data accumulates
    before anyone tightens it.
    """
    from fastapi.testclient import TestClient

    from dwaar.api.app import create_app
    from dwaar.config import Settings

    _merchant, mandate = bench_mandate
    # LOG_LEVEL=WARNING deliberately: 300 JSON log lines emitted inside the measurement
    # would be a confound, not just noise.
    app = create_app(
        Settings(
            DATABASE_URL_APP=app_dsn,
            DATABASE_URL_MIGRATE=migrate_dsn_for_http,
            REDIS_URL=REDIS_URL,
            LOG_LEVEL="WARNING",
        )
    )

    warm = [_signed(mandate, f"httpwarm-{i:04d}-{'x' * 8}") for i in range(50)]
    measured = [_signed(mandate, f"http-{i:05d}-{'x' * 8}") for i in range(300)]
    samples: list[float] = []

    with TestClient(app) as client:
        for _request, headers, body in warm:
            client.post(
                "/v1/authorize",
                content=body,
                headers={**headers, "Content-Type": "application/json"},
            )

        for _request, headers, body in measured:
            started = time.perf_counter()
            response = client.post(
                "/v1/authorize",
                content=body,
                headers={**headers, "Content-Type": "application/json"},
            )
            samples.append((time.perf_counter() - started) * 1000)
            assert response.status_code == 200, response.text

    line = report("http (NOT GATED — reported for variance data)", samples)
    with capsys.disabled():
        print(f"\n  {line}")

    p99 = percentile(samples, 0.99)
    assert p99 < HTTP_P99_GUARD_RAIL_MS, (
        f"HTTP p99 {p99:.2f}ms blew the {HTTP_P99_GUARD_RAIL_MS}ms guard rail. This gate is "
        f"deliberately loose, so exceeding it means something structural — a blocking call "
        f"in an async handler, a connection per request, or a sync driver. {line}"
    )


async def test_recorded_latency_is_less_than_measured_total(
    app_dsn, bench_mandate, signer, settings, nonce_store
):
    """`decision_records.latency_us` excludes its own INSERT, and must say so honestly.

    The column cannot contain the write that stores it. What matters is that the number is
    an UNDER-statement of the measured total, never an over-statement — a latency figure
    that flatters itself is worse than no figure.
    """
    from dwaar.db.repositories import decision_records

    _merchant, mandate = bench_mandate
    request, headers, body = _signed(mandate, f"honest-{rand_id('x')}-xxxxxxxx")

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        started = time.perf_counter()
        outcome = await pipeline.authorize(
            request, conn=conn, signer=signer, settings=settings,
            headers=headers, body=body, nonce_store=nonce_store,
        )
        measured_us = (time.perf_counter() - started) * 1_000_000
        await conn.commit()
        record = await decision_records.get(conn, outcome.record_id)

    assert record["latency_us"] <= outcome.latency_us <= measured_us, (
        "the recorded latency must be an under-statement of the measured total"
    )
