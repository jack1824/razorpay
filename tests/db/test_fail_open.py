"""The risk model is down. Commerce continues, and the record says so.

`FAIL_MATRIX.md` calls the risk model **fail-open**, and that word is doing a lot of work.
It does not mean "ignore the outage". It means:

    the deterministic layer is untouched          gate, policy and ledger all still bound
    the request is not refused for the outage     a blind model is not evidence of anything
    the limits TIGHTEN                            velocity alone becomes enough to throttle
    the record says which of those happened       `degraded_mode`, not silence

The last one is what separates fail-open from fail-oblivious. A system that degrades without
recording it produces an audit trail in which the outage is invisible, and every decision
made during it looks like a decision made with full information.
"""

from __future__ import annotations

import psycopg
import pytest

from dwaar.authorize.stages import risk as risk_stage
from dwaar.crypto.signer import ensure_registered
from dwaar.db.repositories import budget_ledger, decision_records
from dwaar.policy import baseline
from dwaar.risk import injection as _injection
from dwaar.risk.observations import InMemoryObservationStore
from tests._support.fakes import ExplodingScorer
from tests.conftest import rand_id

pytestmark = pytest.mark.db

DETECTOR = _injection.load()


@pytest.fixture
async def mandate(owner_dsn, make_mandate, signer):
    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    row = await make_mandate(
        setup, merchant_id=merchant, max_total_paise=50_000_000, max_per_txn_paise=2_000_000
    )
    await ensure_registered(setup, signer)
    await setup.commit()
    await setup.close()
    return row


def request_for(row, **kw):
    from dwaar.authorize.types import AuthorizeRequest

    return AuthorizeRequest(
        agent_id=row["agent_id"],
        mandate_id=row["mandate_id"],
        action="purchase",
        amount_paise=kw.pop("amount_paise", 120_000),
        idempotency_key=f"{rand_id('k')}-xxxxxxxx",
        category="groceries",
        sku="SKU1000",
        instrument_bin="411111",
        cart_id="cart-failopen",
        **kw,
    )


# ── no bundle on disk ────────────────────────────────────────────────────────────────


async def test_commerce_continues_with_no_model_loaded(
    app_dsn, mandate, signer, settings, nonce_store, authorize_signed
):
    """The headline claim. A missing model must not stop a legitimate purchase."""
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await authorize_signed(
            conn, request_for(mandate), scorer=None,
            observation_store=InMemoryObservationStore(), detector=DETECTOR,
        )
        record = await decision_records.get(conn, outcome.record_id)
        balance = await budget_ledger.balance(conn, mandate["mandate_id"])

    assert outcome.decision.decision == "allow", (
        "a missing risk model refused a legitimate payment. That is fail-CLOSED, and the "
        "fail matrix says otherwise — the gate, the policy engine and the ledger are all "
        "unaffected by the model being absent."
    )
    assert balance == 50_000_000 - 120_000, "the ledger did not reserve; commerce stopped"

    # And the record says what happened, rather than looking like an ordinary decision.
    assert record["risk_score"] is None
    assert record["model_version"] is None
    assert risk_stage.DEGRADED_TOKEN in record["degraded_mode"]


async def test_a_broken_model_is_the_same_as_an_absent_one(
    app_dsn, mandate, signer, settings, nonce_store, authorize_signed
):
    """An exception from inference cannot become a 500.

    Refusing a legitimate payment because an ONNX graph threw is a self-inflicted outage,
    and it is the failure mode that turns one bad deploy into a revenue incident.
    """
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await authorize_signed(
            conn, request_for(mandate), scorer=ExplodingScorer(),
            observation_store=InMemoryObservationStore(), detector=DETECTOR,
        )
        record = await decision_records.get(conn, outcome.record_id)

    assert outcome.decision.decision == "allow"
    assert record["risk_score"] is None
    assert risk_stage.DEGRADED_TOKEN in record["degraded_mode"]


async def test_the_arithmetic_gate_is_unaffected_by_the_outage(
    app_dsn, mandate, signer, settings, nonce_store, authorize_signed
):
    """Fail-open on JUDGMENT, never on AUTHORITY.

    A per-transaction breach is denied whether or not the model is up, because the gate runs
    before the model and needs nothing from it. If a model outage could turn a cap breach
    into an allow, the cap would be a suggestion.
    """
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await authorize_signed(
            conn, request_for(mandate, amount_paise=9_000_000), scorer=None,
            observation_store=InMemoryObservationStore(), detector=DETECTOR,
        )
        record = await decision_records.get(conn, outcome.record_id)

    assert outcome.decision.decision == "deny"
    assert outcome.decision.rule_fired == "mandate.max_per_txn"
    # NULL because the gate short-circuited, not because the model was down. The
    # distinguisher is `degraded_mode`, which carries no risk token on this record at all —
    # the stage never ran, so it never degraded.
    assert record["risk_score"] is None
    assert risk_stage.DEGRADED_TOKEN not in record["degraded_mode"]
    assert "score_risk" not in record["stages_executed"]


# ── the tightened limit ──────────────────────────────────────────────────────────────


async def test_velocity_alone_throttles_while_the_model_is_blind(
    app_dsn, mandate, signer, settings, nonce_store, authorize_signed
):
    """"Tightened limits", concretely.

    With no score, the baseline's degraded rule lowers the bar at which velocity by itself is
    enough to slow an agent down. It THROTTLES rather than denies: a blind model is not
    evidence of anything, so the cost of being wrong is a retry.
    """
    store = InMemoryObservationStore()
    threshold = baseline.DEGRADED_VELOCITY_PER_MINUTE

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcomes = []
        for _ in range(threshold + 4):
            outcomes.append(
                await authorize_signed(
                    conn, request_for(mandate, amount_paise=1_000), scorer=None,
                    observation_store=store, detector=DETECTOR,
                )
            )

    decisions = [o.decision.decision for o in outcomes]
    rules = [o.decision.rule_fired for o in outcomes]

    assert decisions[0] == "allow", "an agent's first request must not be throttled"
    assert "throttle" in decisions, (
        f"{threshold + 4} requests inside one minute with no model produced no throttle; "
        "the tightened limit is not applying"
    )
    assert "policy.baseline.degraded_velocity" in rules
    assert "deny" not in decisions, (
        "the degraded path DENIED. Fail-open means the model being blind cannot refuse a "
        "payment — only slow one down."
    )


async def test_the_same_velocity_is_permitted_while_the_model_is_up(
    app_dsn, mandate, signer, settings, nonce_store, authorize_signed
):
    """Otherwise the "tightened" limit is just a rate limit wearing a degradation's name,
    and a busy legitimate agent is throttled on a healthy system."""
    from tests._support.fakes import FixedScorer

    store = InMemoryObservationStore()
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        decisions = []
        for _ in range(baseline.DEGRADED_VELOCITY_PER_MINUTE + 4):
            outcome = await authorize_signed(
                conn, request_for(mandate, amount_paise=1_000),
                scorer=FixedScorer(0.02), observation_store=store, detector=DETECTOR,
            )
            decisions.append(outcome.decision.decision)

    assert "throttle" not in decisions
    assert set(decisions) == {"allow"}


# ── the console and /health can see it ───────────────────────────────────────────────


async def test_health_reports_the_model_down_without_reporting_the_service_down(
    migrate_dsn_for_http, app_dsn
):
    """A degraded model is not a dead service, and `/health` has to say which.

    Returning 503 here would make Compose restart the container on a missing JSON file, and
    a Postgres blip would become a crash loop — the opposite of what the fail matrix asks
    for.
    """
    from fastapi.testclient import TestClient

    from dwaar.api.app import create_app
    from dwaar.config import Settings
    from tests.conftest import REDIS_URL

    app = create_app(
        Settings(
            DATABASE_URL_APP=app_dsn,
            DATABASE_URL_MIGRATE=migrate_dsn_for_http,
            REDIS_URL=REDIS_URL,
            LOG_LEVEL="WARNING",
            DWAAR_MODEL_DIR="models/does-not-exist",
        )
    )
    with TestClient(app) as client:
        body = client.get("/health").json()

    assert client is not None
    component = body["components"]["risk_model"]
    assert component["status"] == "down"
    assert component["fail_mode"] == "fail_open"
    assert component["severity"] == "degraded", (
        "a fail-open component that is down must be amber, not red — red is for the "
        "components whose absence stops decisions"
    )
    assert body["status"] == "degraded"
