"""The money invariant, reached: the trigger, the write path, and the pipeline.

`tests/test_amount_invariant.py` proves the RULE is right. This proves it is REACHED —
three separate ways, because each covers a gap the others leave:

    the trigger      nothing can insert a non-conserving row, including a future code path
                     and including a superuser
    the write path   stage 8 raises before the insert, so the error names the problem and
                     fires even against a database where migration 0017 was not applied
    the pipeline     F-043 specifically: a `throttle` and a `step_up` reserve nothing

A test proves the invariant held on the cases someone thought of. The trigger proves it
holds on the ones nobody did — which is the whole reason it is an assertion in the write
path rather than an assertion in this file.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest

from dwaar.authorize.types import AuthorizeRequest
from dwaar.errors import AmountInvariantViolation
from dwaar.risk import injection as _injection
from dwaar.risk.observations import InMemoryObservationStore
from tests._support.fakes import FixedScorer

pytestmark = pytest.mark.db

DETECTOR = _injection.load()


def key(prefix: str = "inv") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


# ── the trigger ─────────────────────────────────────────────────────────────────────


async def _insert_copy(conn, template, **overrides):
    """Re-insert an existing record with fields changed. Reaches the trigger and nothing
    else — the row is otherwise byte-identical to one the database already accepted, so a
    refusal can only be about what was changed."""
    from psycopg.types.json import Jsonb

    row = dict(template)
    row["features"] = Jsonb(row["features"])
    row.pop("record_id")
    row.update(overrides)
    row["seq"] = template["seq"] + 1_000_000
    row["request_idempotency_key"] = f"rsv:{uuid.uuid4().hex[:16]}"
    columns = list(row)
    await conn.execute(
        f"INSERT INTO decision_records ({','.join(columns)}) "  # noqa: S608
        f"VALUES ({','.join(['%s'] * len(columns))})",
        [row[c] for c in columns],
    )


@pytest.fixture
async def template(owner_conn, make_mandate, write_record):
    mandate = await make_mandate(owner_conn)
    record = await write_record(
        owner_conn, merchant_id="mch_inv0001", mandate=mandate,
        decision="allow", amount_paise=100_000,
    )
    return dict(record)


@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("half a reservation", {"budget_after": None}),
        ("balance rose", {"budget_before": 1_000, "budget_after": 5_000}),
        ("F-043 throttle moved money",
         {"decision": "throttle", "amount_paise": 500,
          "budget_before": 5_000, "budget_after": 4_500}),
        ("F-043 step_up moved money",
         {"decision": "step_up", "amount_paise": 500,
          "budget_before": 5_000, "budget_after": 4_500}),
        ("bound with no stated amount",
         {"decision": "bound", "amount_paise": 180_000, "bounded_amount_paise": None,
          "budget_before": 500_000, "budget_after": 320_000}),
        ("F-038 bound reserved the full request",
         {"decision": "bound", "amount_paise": 180_000, "bounded_amount_paise": 50_000,
          "budget_before": 500_000, "budget_after": 320_000}),
        ("a bound that increased the amount",
         {"decision": "bound", "amount_paise": 50_000, "bounded_amount_paise": 180_000,
          "budget_before": 500_000, "budget_after": 320_000}),
        ("permit that never reached the ledger",
         {"decision": "allow", "amount_paise": 4_000,
          "budget_before": None, "budget_after": None}),
    ],
)
async def test_the_database_refuses_every_non_conserving_insert(
    owner_conn, template, label, overrides
):
    with pytest.raises(psycopg.errors.RaiseException, match="amount invariant"):
        await _insert_copy(owner_conn, template, **overrides)


@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("bound, correctly reserved",
         {"decision": "bound", "amount_paise": 180_000, "bounded_amount_paise": 50_000,
          "budget_before": 500_000, "budget_after": 450_000}),
        ("deny with the balance reported and nothing moved",
         {"decision": "deny", "amount_paise": 900_000,
          "budget_before": 1_000, "budget_after": 1_000}),
        ("deny short-circuited at the gate, no ledger",
         {"decision": "deny", "amount_paise": 1_200_000,
          "budget_before": None, "budget_after": None}),
        ("throttle that reserved nothing — the fix",
         {"decision": "throttle", "amount_paise": 4_000,
          "budget_before": None, "budget_after": None}),
        ("read-only MCP tool: zero amount, no ledger",
         {"decision": "allow", "amount_paise": 0, "budget_before": None, "budget_after": None,
          "tool": "fetch_payment"}),
    ],
)
async def test_the_database_still_accepts_every_correct_shape(
    owner_conn, template, label, overrides
):
    await _insert_copy(owner_conn, template, **overrides)


async def test_the_trigger_does_not_block_an_update(superuser_dsn, owner_conn, template):
    """Demo beat 6's precondition, and the reason this is a BEFORE INSERT trigger.

    Migration 0007: a superuser MUST be able to tamper, because the control being
    demonstrated is detection by cryptography and not prevention by DBMS. The first version
    of this invariant was a CHECK constraint, which governs UPDATE as well — and
    `UPDATE decision_records SET amount_paise = 999999` is literally demo beat 6.
    """
    await owner_conn.commit()
    async with await psycopg.AsyncConnection.connect(superuser_dsn) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE decision_records SET amount_paise = 999999 WHERE record_id = %s",
                (template["record_id"],),
            )
            assert cur.rowcount == 1, "the tamper must succeed or beat 6 has nothing to show"
        await conn.rollback()


# ── the write path ──────────────────────────────────────────────────────────────────


async def test_stage_eight_refuses_before_it_writes(owner_conn, make_mandate, signer):
    """The assertion fires ahead of the trigger, so the error names the invariant rather
    than surfacing as a plpgsql RAISE. It also fires against a database where migration 0017
    was never applied, which the trigger by definition cannot."""
    from dwaar import clock
    from dwaar.authorize.stages import record as record_stage
    from dwaar.authorize.types import (
        AuthorityResult,
        Decision,
        LedgerResult,
        MandateResult,
    )

    mandate = await make_mandate(owner_conn)
    with pytest.raises(AmountInvariantViolation, match="conserve money"):
        await record_stage.write_decision_record(
            conn=owner_conn,
            signer=signer,
            started_at=0.0,
            created_at=clock.now(),
            request_digest=b"\x00" * 32,
            # F-038 exactly: bound to 50,000 and the ledger moved 180,000.
            decision=Decision(
                decision="bound", reason_code="allowed", internal_reason="policy_bound",
                rule_fired="policy.cap", bounded_amount_paise=50_000,
            ),
            mandate=MandateResult(
                merchant_id="mch_inv0002",
                principal_id=mandate["principal_id"],
                mandate_hash=bytes(mandate["mandate_hash"]),
                mandate=dict(mandate),
            ),
            authority=AuthorityResult(ok=True, permitted=True),
            features=None, injection=None, risk=None, policy=None,
            ledger=LedgerResult(
                ok=True, reserved=True, budget_before=500_000, budget_after=320_000
            ),
            degraded=[], stages_executed=["render_decision"],
            agent_id=mandate["agent_id"], amount_paise=180_000,
            request_idempotency_key=None,
        )


# ── the pipeline ────────────────────────────────────────────────────────────────────


async def test_F043_a_step_up_reserves_nothing(app_conn, make_mandate, authorize_signed):
    """The defect: stage 6 ran on any verdict that was not `deny`, and stage 7 returns
    `step_up` before it ever looks at the ledger. The agent was told to prove itself and its
    budget was debited for a purchase that never happened."""
    mandate = await make_mandate(app_conn, max_total_paise=5_000_000)
    before = await _balance(app_conn, mandate["mandate_id"])

    outcome = await authorize_signed(
        app_conn,
        AuthorizeRequest(
            agent_id=mandate["agent_id"], mandate_id=mandate["mandate_id"],
            action="purchase", amount_paise=100_000, idempotency_key=key(),
            category="groceries",
        ),
        # Above the step-up band and below the deny band. See dwaar/policy/baseline.py.
        scorer=FixedScorer(0.60),
        observation_store=InMemoryObservationStore(),
        detector=DETECTOR,
    )

    assert outcome.decision.decision == "step_up"
    assert await _balance(app_conn, mandate["mandate_id"]) == before, (
        "a step_up debited the mandate. The agent was refused and charged for it — F-043."
    )
    row = await _record(app_conn, outcome.record_id)
    assert row["budget_before"] is None and row["budget_after"] is None, (
        "nothing moved, so recording a balance would imply the ledger was consulted"
    )


async def test_a_bound_records_what_it_was_bound_to(
    owner_dsn, app_dsn, make_mandate, signer, authorize_signed
):
    """F-038's positive form, end to end with a real policy bound.

    The reduced figure is in the record, it is the figure the ledger moved, and it is not
    the figure the agent asked for. Before migration 0017 it existed nowhere but the
    response — which is why the defect survived four phases with every visible surface
    agreeing.
    """
    from dwaar.db.repositories import policies as policy_repo
    from dwaar.policy.store import PolicyStore
    from tests.conftest import rand_id

    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(
        setup, merchant_id=merchant, max_total_paise=50_000_000, max_per_txn_paise=2_000_000
    )
    from dwaar.crypto.signer import ensure_registered

    await ensure_registered(setup, signer)
    policy_id = rand_id("pol")
    await policy_repo.create(
        setup, policy_id=policy_id, merchant_id=merchant, version=1,
        source_nl="Cap groceries at Rs 500.",
        compiled_rules={"rules": [{
            "id": "grocery_bound",
            "when": {">": [{"var": "request.amount_paise"}, {"lit": 50_000}]},
            "action": "bound", "reason_code": "allowed", "bound_to_paise": 50_000,
        }]},
        generated_tests={}, tests_passed=True,
    )
    await policy_repo.approve(setup, policy_id, approved_by="arpit", signature=b"\x04" * 64)
    await setup.commit()
    await setup.close()

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await authorize_signed(
            conn,
            AuthorizeRequest(
                agent_id=mandate["agent_id"], mandate_id=mandate["mandate_id"],
                action="purchase", amount_paise=180_000,
                idempotency_key=key(), category="groceries",
            ),
            policy_store=PolicyStore(ttl_seconds=0),
            observation_store=InMemoryObservationStore(),
            scorer=FixedScorer(0.02),
            detector=DETECTOR,
        )
        assert outcome.decision.decision == "bound"
        row = await _record(conn, outcome.record_id)

    assert row["amount_paise"] == 180_000, "the record keeps what was asked for"
    assert row["bounded_amount_paise"] == 50_000, "and what it was reduced to"
    assert row["budget_before"] - row["budget_after"] == 50_000, (
        "the ledger moved the BOUND amount. F-038 moved 180,000 here and told the agent "
        "50,000, and nothing in the system compared the two."
    )
    assert row["canonical_json"].find('"bounded_amount_paise":50000') > 0, (
        "the bounded amount must be inside the SIGNED bytes, not merely a column beside "
        "them — otherwise it is the shadow copy problem F-016 was about"
    )


async def _balance(conn, mandate_id: int) -> int:
    from dwaar.db.repositories import budget_ledger

    return await budget_ledger.balance(conn, mandate_id)


async def _record(conn, record_id):
    from dwaar.db.repositories import decision_records

    return await decision_records.get(conn, record_id)
