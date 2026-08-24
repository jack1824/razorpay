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

**The benchmark runs on a SIMULATED CLOCK, and that is load-bearing.**

A thousand identical requests fired in a tight loop is, to the risk model, a card tester —
same amount, same card, same SKU, hundreds per second. The model denied them, correctly, and
the benchmark quietly stopped measuring the allow path: a denial short-circuits the ledger,
so stage 6 never ran and the reported p99 was for a cheaper pipeline than the one the 25ms
budget was set for. `assert_complete` caught it on its first run.

So each request carries a `created` timestamp and a pipeline `now` five simulated seconds
after the last. Nothing about the work is faked — real Ed25519 verification, real Redis round
trip, real ONNX inference, real chain write. Only the *spacing* the feature window sees is
synthetic, which is what makes the benchmark measure an ordinary agent's request rather than
an attack. The p99 quoted is deliberately the **allow** path, because it runs every stage and
is the expensive one.

**The measured pipeline must be the COMPLETE pipeline.** These tests originally called
`pipeline.authorize` without an observation store and without a scorer, which meant Redis was
never touched and ONNX Runtime was never invoked — `record_observation` came back at 0.000ms
and `score_risk` at 0.002ms, and the gate passed with the two most expensive new stages
absent. A number that does not measure what its label says is the same defect as a hardcoded
one.

So the real scorer and a real Redis store are required, the test SKIPS rather than measuring
a degraded path when either is missing, and every run asserts `degraded_mode` came back empty.
"""

from __future__ import annotations

import json
import random
import statistics
import time
import uuid

import psycopg
import pytest

from dwaar.authorize import pipeline
from dwaar.authorize.stages import authority
from dwaar.authorize.types import AuthorizeRequest
from dwaar.crypto import http_sig
from dwaar.crypto import keys as keymod
from dwaar.crypto.signer import ensure_registered

#: The REAL detector. Needs no artifact and no session — eleven arithmetic
#: features — so a test running without one would only be exercising the
#: not-checked path, and every record it wrote would carry a NULL flag.
from dwaar.risk import injection as _injection
from tests.conftest import AGENT_SEED, REDIS_URL, rand_id

DETECTOR = _injection.load()

pytestmark = pytest.mark.db

REQUESTS = 1_000
PIPELINE_P99_BUDGET_MS = 25.0
HTTP_P99_GUARD_RAIL_MS = 150.0


#: Seeded, so two runs of the benchmark send the same traffic and a p99 difference between
#: them is a difference in the code rather than in the workload.
_BENCH_RNG = random.Random(20260828)

_BENCH_SKUS = ("SKU1000", "SKU1004", "SKU9002")


def _signed(mandate, key: str, *, created: int | None = None):
    """Build one signed request. Called outside timed regions on purpose.

    Amount and SKU vary, and `next_gap` jitters the spacing, because a benchmark of a
    thousand IDENTICAL requests at a perfectly regular cadence is — to the risk model — a
    card tester, and it was denied as one. Zero amount entropy, zero cadence entropy and zero
    inter-arrival variance is the exact profile the top feature keys on.

    The model was correct and the benchmark was wrong. What this file wants to measure is an
    ordinary agent's request travelling every stage, so the traffic is shaped like an ordinary
    agent's rather than tuned until the model stops objecting.
    """
    request = AuthorizeRequest(
        agent_id=mandate["agent_id"],
        mandate_id=mandate["mandate_id"],
        action="purchase",
        amount_paise=_BENCH_RNG.randint(20_000, 180_000),
        idempotency_key=key,
        category="groceries",
        sku=_BENCH_RNG.choice(_BENCH_SKUS),
        instrument_bin="411111",
        cart_id=f"cart-bench-{_BENCH_RNG.getrandbits(16):04x}",
    )
    body = json.dumps(
        {
            "agent_id": request.agent_id,
            "mandate_id": request.mandate_id,
            "action": request.action,
            "amount_paise": request.amount_paise,
            "idempotency_key": request.idempotency_key,
            "category": request.category,
            "sku": request.sku,
            "instrument_bin": request.instrument_bin,
            "cart_id": request.cart_id,
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
        created=created if created is not None else int(time.time()),
        nonce=uuid.uuid4().hex,
    )
    return request, headers, body


#: Simulated seconds between benchmark requests, jittered. Wide and ragged enough that the
#: feature window reads an ordinary agent rather than a machine, so the model permits and
#: every stage actually runs.
SIMULATED_GAP_RANGE = (3, 25)


def _clock():
    """Timestamps advancing in simulated time, starting near now so signature skew holds.

    The signature's `created` and the pipeline's `now` move together — a simulated clock on
    one and a wall clock on the other would fail the 120-second skew check, which is a real
    control and is not being bypassed here.

    Nothing about the WORK is simulated: real Ed25519 verification, real Redis round trip,
    real ONNX inference, real chain write. Only the spacing the feature window sees.
    """
    from datetime import UTC, datetime, timedelta

    at = datetime.now(UTC)
    while True:
        at = at + timedelta(seconds=_BENCH_RNG.randint(*SIMULATED_GAP_RANGE))
        yield at


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


@pytest.fixture(scope="module")
def scorer():
    """The REAL model, or a skip. Never a fake.

    A fixed-score double returns in microseconds and would make the risk stage's budget
    unmeasurable. Skipping is the honest failure: the alternative is a green latency gate
    over a pipeline that never ran inference.
    """
    from dwaar.risk import model as riskmodel

    loaded = riskmodel.load()
    if loaded is None:
        pytest.skip(
            "no model bundle in models/risk — the latency gate would measure a pipeline "
            "with stage 4 short-circuited. Train one with `python -m tools.train_risk`."
        )
    return loaded


@pytest.fixture
async def observation_store():
    """A REAL Redis store, or a skip. Same reasoning as `scorer`."""
    from redis.asyncio import Redis

    from dwaar.risk.observations import Observation, RedisObservationStore

    client = Redis.from_url(REDIS_URL)
    store = RedisObservationStore(client)
    probe = await store.observe(
        agent_id="latency-probe",
        principal_id="latency-probe",
        observation=Observation(0.0, 1, None, None, None, None),
    )
    if not probe.available:
        await client.aclose()
        pytest.skip(f"no Redis at {REDIS_URL} — stage 3 would not touch the network")
    try:
        yield store
    finally:
        await client.aclose()


def assert_complete(outcome) -> None:
    """The control that keeps every number in this file honest.

    Rule 4 says every number is computed at run time. That rules out fabrication; it does not
    rule out measuring the wrong thing. F-033 was exactly that — a green gate over a pipeline
    where `record_observation` cost 0.000ms and `score_risk` cost 0.002ms, because neither
    collaborator had been supplied and both stages short-circuited before doing any work. The
    number was computed. It was computing a different quantity than its label claimed.

    So the label's PRECONDITIONS are asserted, not just its value. Three of them:

        no stubs in the pipeline at all
        no runtime degradation on the request that was measured
        every stage in the registry actually cost something

    A stage that costs zero is either not running or not being timed. Neither is acceptable
    in a figure this project quotes.
    """
    assert pipeline.STUB_STAGES == {}, (
        f"stubs remain in the pipeline: {pipeline.STUB_STAGES}. A latency figure measured "
        "with a stage stubbed is a figure for a system we do not ship."
    )
    assert outcome.degraded_mode == [], (
        f"the measured pipeline was DEGRADED ({outcome.degraded_mode}); this latency number "
        "describes a pipeline with stages missing and must not be reported"
    )

    assert outcome.decision.decision in ("allow", "bound"), (
        f"the measured request was {outcome.decision.decision} "
        f"({outcome.decision.rule_fired}). A denial short-circuits the ledger, so this "
        "number is for a cheaper pipeline than the one the 25ms budget was set for. The "
        "benchmark must measure the ALLOW path, which runs every stage."
    )

    measured = set(outcome.stage_timings_us)
    missing = set(pipeline.STAGE_ORDER) - measured
    assert not missing, f"stages never timed: {sorted(missing)}"

    # `check_authority` and `render_decision` are pure and sub-microsecond, so they can
    # legitimately round to zero on a fast machine. Every stage that does I/O or real
    # computation cannot.
    PURE = {authority.STAGE_NAME, "render_decision"}
    free = sorted(
        stage
        for stage, micros in outcome.stage_timings_us.items()
        if micros == 0 and stage not in PURE
    )
    assert not free, (
        f"stages reporting 0us: {free}. A stage that costs nothing is either not running or "
        "not being timed — F-033 was both, and the gate was green throughout."
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
    app_dsn, bench_mandate, signer, settings, nonce_store, scorer, observation_store, capsys
):
    """THE gate. 1,000 requests through the full pipeline including the chain write."""
    _merchant, mandate = bench_mandate
    clock = _clock()
    warmup = [
        (*_signed(mandate, f"warm-{i:04d}-{'x' * 8}", created=int(at.timestamp())), at)
        for i, at in ((i, next(clock)) for i in range(20))
    ]
    prepared = [
        (*_signed(mandate, f"bench-{i:06d}-{'x' * 8}", created=int(at.timestamp())), at)
        for i, at in ((i, next(clock)) for i in range(REQUESTS))
    ]
    samples: list[float] = []

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        # Warm the pool, the prepared statements and the chain tail before measuring.
        for request, headers, body, at in warmup:
            outcome = await pipeline.authorize(
                request, conn=conn, signer=signer, settings=settings,
                headers=headers, body=body, nonce_store=nonce_store, detector=DETECTOR,
                observation_store=observation_store, scorer=scorer, now=at,
            )
            await conn.commit()
        assert_complete(outcome)

        for request, headers, body, at in prepared:
            started = time.perf_counter()
            outcome = await pipeline.authorize(
                request, conn=conn, signer=signer, settings=settings,
                headers=headers, body=body, nonce_store=nonce_store, detector=DETECTOR,
                observation_store=observation_store, scorer=scorer, now=at,
            )
            await conn.commit()
            samples.append((time.perf_counter() - started) * 1000)
    assert_complete(outcome)

    line = report("pipeline", samples)
    with capsys.disabled():
        print(f"\n  {line}")

    p99 = percentile(samples, 0.99)
    assert p99 < PIPELINE_P99_BUDGET_MS, (
        f"p99 {p99:.2f}ms exceeds the {PIPELINE_P99_BUDGET_MS}ms budget. {line}\n"
        "Per-stage timings are on every log line — find the stage before optimising."
    )


async def test_no_single_stage_dominates(
    app_dsn, bench_mandate, signer, settings, nonce_store, scorer, observation_store, capsys
):
    """The stage split exists to make a regression attributable, so assert it stays so.

    A p99 that passes while one stage eats most of it is a p99 that will fail next week for
    a reason nobody can locate.
    """
    _merchant, mandate = bench_mandate
    clock = _clock()
    prepared = [
        (*_signed(mandate, f"stage-{i:05d}-{'x' * 8}", created=int(at.timestamp())), at)
        for i, at in ((i, next(clock)) for i in range(200))
    ]
    per_stage: dict[str, list[int]] = {}

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        for request, headers, body, at in prepared:
            outcome = await pipeline.authorize(
                request, conn=conn, signer=signer, settings=settings,
                headers=headers, body=body, nonce_store=nonce_store, detector=DETECTOR,
                observation_store=observation_store, scorer=scorer, now=at,
            )
            await conn.commit()
            for stage, micros in outcome.stage_timings_us.items():
                per_stage.setdefault(stage, []).append(micros)
    assert_complete(outcome)

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
            headers=headers, body=body, nonce_store=nonce_store, detector=DETECTOR,
        )
        measured_us = (time.perf_counter() - started) * 1_000_000
        await conn.commit()
        record = await decision_records.get(conn, outcome.record_id)

    assert record["latency_us"] <= outcome.latency_us <= measured_us, (
        "the recorded latency must be an under-statement of the measured total"
    )
