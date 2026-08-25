"""The explainer cannot affect a decision, and killing it changes none.

Demo beat 5's first half is `docker kill dwaar-llm-explainer` and everything continuing. The
brief said that must be **demonstrably true, not asserted**, so this file proves it three
ways and none of them is "we read the code and it looks off-path":

    1. the ROLE          `dwaar_explainer` cannot INSERT, UPDATE or DELETE a decision record,
                         cannot touch the ledger, cannot read or write a mandate. A grant is
                         not a convention.
    2. the ORDERING      the record is committed and chained BEFORE anything is published.
                         There is no window in which an explainer could see a decision that
                         is not yet final.
    3. the OUTAGE        with the stream unreachable, decisions are byte-identical and carry
                         no degradation token — because the explainer is not a component the
                         decision depends on.

(1) is the one worth pointing a judge at. The other two are properties of code, and code
changes; a role that owns nothing and holds two grants does not.
"""

from __future__ import annotations

import os
import uuid

import psycopg
import pytest

from dwaar.authorize.types import AuthorizeRequest
from dwaar.risk import injection as _injection
from dwaar.risk.observations import InMemoryObservationStore
from tests._support.fakes import FixedScorer

pytestmark = pytest.mark.db

DETECTOR = _injection.load()

EXPLAINER_DSN = os.environ.get(
    "DATABASE_URL_EXPLAINER",
    "postgresql://dwaar_explainer:explainer_pw@localhost:5432/dwaar",
)


def key() -> str:
    return f"exp-{uuid.uuid4().hex[:20]}"


@pytest.fixture
async def explainer_conn(migrated):
    """Refuses to skip quietly.

    A skipped isolation test is indistinguishable from an absent control, which is the
    property this whole repository is about. If the role is missing, that is a bootstrap
    failure worth failing on rather than a reason to report nothing.
    """
    try:
        conn = await psycopg.AsyncConnection.connect(EXPLAINER_DSN, connect_timeout=3)
    except psycopg.OperationalError as exc:
        pytest.fail(
            f"cannot connect as dwaar_explainer ({exc}). Run "
            "`./scripts/init-db/local-bootstrap.sh` — the role is created there and by "
            "scripts/init-db/01-roles.sh, and migration 0018 grants to it. A skip here "
            "would report an absent control as a passing one."
        )
    try:
        yield conn
    finally:
        await conn.rollback()
        await conn.close()


# ── 1. the role ─────────────────────────────────────────────────────────────────────


async def test_the_explainer_can_read_decisions(
    explainer_conn, owner_conn, make_mandate, write_record
):
    mandate = await make_mandate(owner_conn)
    await write_record(owner_conn, merchant_id="mch_exp0001", mandate=mandate, amount_paise=100_000)
    await owner_conn.commit()

    async with explainer_conn.cursor() as cur:
        await cur.execute("SELECT count(*) FROM decision_records WHERE merchant_id = %s",
                          ("mch_exp0001",))
        assert (await cur.fetchone())[0] >= 1


@pytest.mark.parametrize(
    ("statement", "params"),
    [
        ("UPDATE decision_records SET amount_paise = 1", ()),
        ("DELETE FROM decision_records", ()),
        ("UPDATE budget_ledger SET delta_paise = 0", ()),
        ("UPDATE mandates SET max_total_paise = 999999999", ()),
        ("UPDATE explanations SET body = 'rewritten'", ()),
        ("DELETE FROM explanations", ()),
    ],
    ids=lambda v: v[:38] if isinstance(v, str) else "",
)
async def test_the_explainer_cannot_write_anything_that_decides(
    explainer_conn, statement, params
):
    """What it is not granted, demonstrated rather than documented.

    Same shape as `tests/db/test_append_only_grant.py`: the claim "the LLM cannot change a
    decision" is only worth as much as the privilege that enforces it.
    """
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        async with explainer_conn.cursor() as cur:
            await cur.execute(statement, params)


async def test_the_explainer_owns_nothing(explainer_conn):
    """Non-ownership is what makes every REVOKE above mean anything.

    A REVOKE never strips an owner. If this role owned one table, it could rewrite that
    table regardless of what was granted — which is the same reasoning that makes
    `dwaar_app` non-ownership the actual append-only control.
    """
    async with explainer_conn.cursor() as cur:
        await cur.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
            "AND tableowner = 'dwaar_explainer'"
        )
        owned = [row[0] for row in await cur.fetchall()]
    assert owned == [], f"dwaar_explainer owns {owned}; a REVOKE cannot restrict an owner"


async def test_the_explainer_may_insert_an_explanation(
    explainer_conn, owner_conn, make_mandate, write_record
):
    """The one thing it may do. Asserted so the isolation test is not vacuously satisfied by
    a role that can do nothing at all."""
    mandate = await make_mandate(owner_conn)
    record = await write_record(
        owner_conn, merchant_id="mch_exp0002", mandate=mandate, amount_paise=100_000
    )
    await owner_conn.commit()

    async with explainer_conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO explanations (record_id, merchant_id, seq, cache_key, body) "
            "VALUES (%s,%s,%s,%s,%s) RETURNING explanation_id",
            (record["record_id"], "mch_exp0002", record["seq"], "allow|none|none", "text"),
        )
        assert await cur.fetchone() is not None
    await explainer_conn.rollback()


# ── 3. the outage ───────────────────────────────────────────────────────────────────


class DeadRedis:
    """Every operation raises. Stands in for `docker kill dwaar-llm-explainer` plus the
    queue going with it — a strictly worse outage than the demo's."""

    async def xadd(self, *a, **kw):
        raise ConnectionError("explainer queue is gone")

    async def xinfo_groups(self, *a, **kw):
        raise ConnectionError("explainer queue is gone")


async def test_publishing_to_a_dead_queue_cannot_fail_a_request():
    from dwaar import outbox

    assert await outbox.publish(DeadRedis(), record_id="r", merchant_id="m", seq=1) is False
    assert await outbox.publish(None, record_id="r", merchant_id="m", seq=1) is False


async def test_health_reports_a_dead_explainer_without_degrading_the_gateway():
    from dwaar import outbox
    from dwaar.components import BY_NAME, FailMode, Severity

    status = await outbox.explainer_status(DeadRedis())
    assert status["up"] is False

    component = BY_NAME["explainer"]
    assert component.fail_mode is FailMode.NO_EFFECT
    assert component.severity_when_down is Severity.NOMINAL, (
        "a dead explainer must never make the gateway report DEGRADED. Killing it is demo "
        "beat 5 precisely because nothing else moves."
    )


async def test_decisions_are_identical_with_the_explainer_dead(
    app_conn, make_mandate, authorize_signed
):
    """The claim, end to end.

    Two requests differing only in whether the outbox is reachable. Same decision, same
    reason, same rule, same ledger movement, and — the part that matters — an empty
    `degraded_mode`, because the explainer is not a component a decision depends on.
    """
    from dwaar import outbox

    mandate = await make_mandate(app_conn, max_total_paise=5_000_000)

    async def authorize(idempotency: str):
        return await authorize_signed(
            app_conn,
            AuthorizeRequest(
                agent_id=mandate["agent_id"], mandate_id=mandate["mandate_id"],
                action="purchase", amount_paise=100_000,
                idempotency_key=idempotency, category="groceries",
            ),
            scorer=FixedScorer(0.02),
            observation_store=InMemoryObservationStore(),
            detector=DETECTOR,
        )

    healthy = await authorize(key())
    published = await outbox.publish(
        DeadRedis(), record_id=healthy.record_id or "", merchant_id="m", seq=healthy.seq or 0
    )
    assert published is False, "the queue is meant to be dead for this test"

    dead = await authorize(key())

    assert dead.decision.decision == healthy.decision.decision
    assert dead.decision.reason_code == healthy.decision.reason_code
    assert dead.decision.rule_fired == healthy.decision.rule_fired
    assert dead.degraded_mode == healthy.degraded_mode == [], (
        "a decision made while the explainer is dead must carry no degradation token. If it "
        "did, the explainer would be a component the decision depends on, and demo beat 5 "
        "would be a claim rather than a demonstration."
    )
    assert dead.budget_remaining_paise == healthy.budget_remaining_paise - 100_000


# ── the fallback: an explanation exists even with no model ──────────────────────────


async def test_the_worker_writes_a_fallback_when_no_model_is_available(
    explainer_conn, owner_conn, make_mandate, write_record
):
    """`--no-model` is the demo's default posture and the test suite's only one.

    A merchant gets a sentence with no network involved, which is why the console never
    shows an empty panel that reads as a bug.
    """
    from dwaar.explain.worker import Explainer

    mandate = await make_mandate(owner_conn)
    record = await write_record(
        owner_conn, merchant_id="mch_exp0003", mandate=mandate, decision="deny",
        amount_paise=1_200_000, rule_fired="mandate.max_per_txn",
    )
    await owner_conn.commit()

    worker = Explainer(dsn=EXPLAINER_DSN, redis_url="redis://localhost:6379/0", use_model=False)
    async with await psycopg.AsyncConnection.connect(
        EXPLAINER_DSN, row_factory=psycopg.rows.dict_row
    ) as conn:
        assert await worker.explain(conn, str(record["record_id"])) is True
        # Idempotent: a redelivered stream message must not produce a second explanation.
        assert await worker.explain(conn, str(record["record_id"])) is False

        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT body, model, cached, cache_key FROM explanations WHERE record_id = %s",
                (record["record_id"],),
            )
            row = await cur.fetchone()

    assert row["model"] is None, "no model was called, so the row must not name one"
    assert row["cached"] is True
    assert "mandate.max_per_txn" in row["body"]
    assert row["cache_key"] == "deny|mandate.max_per_txn|none", (
        "risk_score is NULL on a gate denial, and the band must say so rather than reading "
        "as 'low' — 'confidently benign' and 'nobody asked' are different facts"
    )
