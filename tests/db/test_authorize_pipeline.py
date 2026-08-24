"""The authorize pipeline end to end, against a real PostgreSQL.

The centrepiece is `test_beat_2_*`: demo beat 2 turned into a CI gate on day 3 instead of a
discovery on day 11. Its claim — *"denied by arithmetic, with the model never consulted"* —
is asserted three ways, because two of them can pass vacuously today and silently regress
when the model becomes real:

    risk_score IS NULL          passes today no matter what; the stub returns None anyway
    no ledger entry             real now, stays real
    score_risk never INVOKED    the structural one. Cannot pass vacuously and cannot
                                regress silently when stage 4 lands.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from dwaar.authorize import pipeline
from dwaar.authorize.stages import authority
from dwaar.authorize.types import AuthorizeRequest
from dwaar.crypto.signer import ensure_registered
from dwaar.db.repositories import budget_ledger, decision_records
from tests.conftest import rand_id

pytestmark = pytest.mark.db

MERCHANT = "mch_pipeline"


@pytest.fixture
async def scenario(owner_dsn, app_dsn, make_mandate, signer):
    """A committed mandate plus a registered signing key, on its own merchant chain.

    Its own merchant so the chain starts at seq 1 and assertions about ordering are not
    contaminated by other tests.
    """
    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(
        setup, merchant_id=merchant, max_total_paise=5_000_000, max_per_txn_paise=500_000
    )
    await ensure_registered(setup, signer)
    await setup.commit()
    await setup.close()

    yield {"merchant": merchant, "mandate": mandate}

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


def make_request(mandate, *, amount=124_000, category="groceries", key=None):
    return AuthorizeRequest(
        agent_id=mandate["agent_id"],
        mandate_id=mandate["mandate_id"],
        action="purchase",
        amount_paise=amount,
        idempotency_key=key or f"{rand_id('idem')}-{'x' * 8}",
        category=category,
    )


# Every call signs for real. See conftest.authorize_signed.
async def run(conn, request, authorize_signed, **kw):
    return await authorize_signed(conn, request, **kw)


# ── the happy path ──────────────────────────────────────────────────────────────────

async def test_a_permitted_request_is_allowed_and_chained(app_dsn, scenario, authorize_signed
):
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(conn, make_request(scenario["mandate"]), authorize_signed)

    assert outcome.decision.decision == "allow"
    assert outcome.seq == 1
    assert outcome.record_id
    assert outcome.budget_remaining_paise == 5_000_000 - 124_000
    assert outcome.latency_us > 0


async def test_every_stage_is_timed(app_dsn, scenario, authorize_signed
):
    """Per-stage timings are what make the latency story legible rather than asserted."""
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(conn, make_request(scenario["mandate"]), authorize_signed)

    assert set(outcome.stage_timings_us) == set(pipeline.STAGE_ORDER)
    assert all(v >= 0 for v in outcome.stage_timings_us.values())


async def test_every_stub_declares_itself_on_the_record(app_dsn, scenario, authorize_signed
):
    """Phase 3 records must be self-labelling. A stub that does not appear in
    degraded_mode is a stub that can be demoed as working."""
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(conn, make_request(scenario["mandate"]), authorize_signed)
        record = await decision_records.get(conn, outcome.record_id)

    assert set(record["degraded_mode"]) == set(pipeline.STUB_STAGES.values())
    assert record["degraded_mode"] == sorted(record["degraded_mode"]), (
        "degraded_mode is inside the signed payload, so its order is part of the hash"
    )


# ── DEMO BEAT 2, as a CI gate ───────────────────────────────────────────────────────

async def test_beat_2_per_txn_breach_denies_with_null_risk_score(
    app_dsn, scenario, authorize_signed
):
    """₹12,000 against a ₹5,000 per-transaction cap, with ₹50,000 still available.

    The budget is NOT the reason. If `reserve_budget` were the only arithmetic in the
    system this would be ALLOWED, because the cumulative balance covers it easily.
    """
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(
            conn,
            make_request(scenario["mandate"], amount=1_200_000, category="groceries"),
            authorize_signed,
        )
        record = await decision_records.get(conn, outcome.record_id)

    assert outcome.decision.decision == "deny"
    assert outcome.decision.rule_fired == authority.RULE_MAX_PER_TXN
    assert record["risk_score"] is None
    assert record["model_version"] is None


async def test_beat_2_touches_no_ledger_entry(app_dsn, scenario, authorize_signed
):
    """A refusal on the mandate's own terms must not move the ledger at all."""
    mandate_id = scenario["mandate"]["mandate_id"]
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        before = await budget_ledger.history(conn, mandate_id)
        await run(
            conn,
            make_request(scenario["mandate"], amount=1_200_000, category="groceries"),
            authorize_signed,
        )
        after = await budget_ledger.history(conn, mandate_id)

    assert len(after) == len(before) == 1, "only the genesis entry should exist"


async def test_beat_2_never_invokes_the_risk_model(
    app_dsn, scenario, signer, authorize_signed, monkeypatch
):
    """THE assertion. The other two pass vacuously while stage 4 is stubbed.

    `risk_score IS NULL` is true today whatever the pipeline does, because the stub returns
    None. It would silently become false the day the model lands and starts scoring before
    the cap is checked — and we would find out in the dress rehearsal.

    This spies on the actual call. It cannot pass vacuously and it cannot regress quietly.
    """
    calls = []
    original = pipeline.risk_stage.score_risk

    async def spy(*args, **kwargs):
        calls.append(1)
        return await original(*args, **kwargs)

    monkeypatch.setattr(pipeline.risk_stage, "score_risk", spy)

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        breach = await run(
            conn,
            make_request(scenario["mandate"], amount=1_200_000, category="groceries"),
            authorize_signed,
        )
        assert breach.decision.decision == "deny"
        assert calls == [], (
            "score_risk was invoked for a request that breaches the per-transaction cap. "
            "The arithmetic gate must short-circuit BEFORE scoring, or demo beat 2's claim "
            "— 'the model was never consulted' — is false."
        )

        # And the control: a permitted request DOES reach the model.
        allowed = await run(conn, make_request(scenario["mandate"]), authorize_signed)
        assert allowed.decision.decision == "allow"
        assert calls == [1], "a permitted request must still be scored"


async def test_beat_2_record_says_which_stages_ran(app_dsn, scenario, authorize_signed
):
    """`features={}` alone is indistinguishable from a computed-and-empty feature set."""
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(
            conn,
            make_request(scenario["mandate"], amount=1_200_000, category="groceries"),
            authorize_signed,
        )
        record = await decision_records.get(conn, outcome.record_id)

    executed = record["stages_executed"]
    assert "check_authority" in executed
    assert "score_risk" not in executed
    assert "compute_features" not in executed
    assert "reserve_budget" not in executed
    assert record["policy_version"] is None, (
        "NULL means the policy engine was never consulted; 0 would mean consulted with no "
        "compiled policy, which is a different fact"
    )


# ── the other side of the distinction ───────────────────────────────────────────────

async def test_cumulative_exhaustion_denies_after_being_scored(
    owner_dsn, app_dsn, make_mandate, authorize_signed, signer
):
    """The counterpart to beat 2, and the reason the distinction needs stating.

    Both are arithmetic denials. This one needed the ledger to know, so it sits after
    scoring and its record carries whatever the model said. Beat 2 needed only the mandate,
    so it sits before scoring and its record carries NULL.
    """
    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(
        setup, merchant_id=merchant, max_total_paise=100_000, max_per_txn_paise=100_000
    )
    await ensure_registered(setup, signer)
    await setup.commit()
    await setup.close()

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        first = await run(conn, make_request(mandate, amount=100_000), authorize_signed)
        assert first.decision.decision == "allow"

        second = await run(conn, make_request(mandate, amount=1_000), authorize_signed)
        record = await decision_records.get(conn, second.record_id)

    assert second.decision.decision == "deny"
    assert second.decision.rule_fired == "mandate.max_total"
    assert "reserve_budget" in record["stages_executed"]
    assert "score_risk" in record["stages_executed"], (
        "a cumulative denial IS scored first — that is what distinguishes it from beat 2"
    )


@pytest.mark.parametrize(
    ("category", "rule"),
    [
        ("gift_cards", authority.RULE_CATEGORY_DENIED),
        ("electronics", authority.RULE_CATEGORY_NOT_ALLOWED),
    ],
)
async def test_category_denials_also_short_circuit(
    app_dsn, scenario, signer, authorize_signed, category, rule
):
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(
            conn,
            make_request(scenario["mandate"], amount=1_000, category=category),
            authorize_signed,
        )
        record = await decision_records.get(conn, outcome.record_id)

    assert outcome.decision.decision == "deny"
    assert outcome.decision.rule_fired == rule
    assert record["risk_score"] is None
    assert "score_risk" not in record["stages_executed"]


async def test_an_expired_mandate_denies_before_scoring(app_dsn, scenario, authorize_signed
):
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(
            conn, make_request(scenario["mandate"]), authorize_signed,
            now=datetime.now(UTC) + timedelta(days=365),
        )
        record = await decision_records.get(conn, outcome.record_id)

    assert outcome.decision.decision == "deny"
    assert record["risk_score"] is None


# ── what does and does not get chained ──────────────────────────────────────────────

async def test_an_unknown_mandate_is_never_chained(app_dsn, scenario, authorize_signed
):
    """No resolved merchant means no chain to write to.

    Chaining unattributable requests would hand anyone with an HTTP client write access to
    the evidence the design exists to protect.
    """
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        before = len(await decision_records.iter_chain(conn, scenario["merchant"]))
        with pytest.raises(pipeline.Unresolvable):
            await authorize_signed(
                conn,
                AuthorizeRequest(
                    agent_id=scenario["mandate"]["agent_id"],
                    mandate_id="mnd_doesnotexist",
                    action="purchase",
                    amount_paise=1_000,
                    idempotency_key=f"{rand_id('k')}-xxxxxxxx",
                    category="groceries",
                ),
                commit=False,
            )
        await conn.rollback()
        after = len(await decision_records.iter_chain(conn, scenario["merchant"]))

    assert after == before


async def test_a_mandate_presented_by_the_wrong_agent_does_not_resolve(
    app_dsn, scenario, signer, authorize_signed, owner_dsn, make_agent
):
    """Not a lookup miss — an attempt to exercise someone else's authority."""
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    intruder = await make_agent(setup, merchant_id=scenario["merchant"])
    await setup.commit()
    await setup.close()

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        with pytest.raises(pipeline.Unresolvable):
            await authorize_signed(
                conn,
                AuthorizeRequest(
                    agent_id=intruder["agent_id"],
                    mandate_id=scenario["mandate"]["mandate_id"],
                    action="purchase",
                    amount_paise=1_000,
                    idempotency_key=f"{rand_id('k')}-xxxxxxxx",
                    category="groceries",
                ),
                commit=False,
            )
        await conn.rollback()


async def test_a_revoked_mandate_is_denied_and_chained(
    owner_dsn, app_dsn, make_mandate, authorize_signed, signer
):
    """Resolved but withdrawn: we know exactly whose authority ended, so it is evidence."""
    from dwaar.db.repositories import mandates as mandate_repo

    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(setup, merchant_id=merchant)
    await ensure_registered(setup, signer)
    await mandate_repo.revoke(setup, mandate["mandate_id"])
    await setup.commit()
    await setup.close()

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(conn, make_request(mandate), authorize_signed)
        record = await decision_records.get(conn, outcome.record_id)

    assert outcome.decision.decision == "deny"
    assert outcome.decision.reason_code == "not_authorized"
    assert record is not None, "a revoked mandate IS chained — we know who"


# ── the chain, now that records are genuinely signed ────────────────────────────────

async def test_the_chain_verifies_end_to_end(app_dsn, owner_dsn, scenario, authorize_signed
):
    """Earned early: stage 8 signs for real from Phase 3, so verification lands now."""
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        for i in range(12):
            await run(
                conn, make_request(scenario["mandate"], amount=1_000 + i), authorize_signed
)

    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        result = await decision_records.verify_chain(conn, scenario["merchant"])

    assert result["ok"] is True, result
    assert result["records"] == 12
    assert result["broken_at_seq"] is None
    assert result["gaps"] == []


async def test_tampering_breaks_the_chain_and_names_the_seq(
    app_dsn, superuser_dsn, owner_dsn, scenario, authorize_signed
):
    """Demo beat 6, as a test.

    The tamper is performed as SUPERUSER and it succeeds at the storage layer — that is
    required, not tolerated. The control being demonstrated is detection by cryptography,
    not prevention by DBMS.
    """
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        for i in range(5):
            await run(conn, make_request(scenario["mandate"], amount=1_000 + i), authorize_signed)

    async with await psycopg.AsyncConnection.connect(superuser_dsn) as su:
        async with su.cursor() as cur:
            await cur.execute(
                "UPDATE decision_records SET amount_paise = 999999 "
                "WHERE merchant_id = %s AND seq = 3",
                (scenario["merchant"],),
            )
            assert cur.rowcount == 1, (
                "the tamper must succeed; there is nothing to detect otherwise"
            )
        await su.commit()

    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        result = await decision_records.verify_chain(conn, scenario["merchant"])

    # The tamper changed a column but not canonical_json, so the record now disagrees with
    # the bytes that were signed. Verification must notice and name the row.
    assert result["ok"] is False
    assert result["broken_at_seq"] == 3


async def test_tampering_with_the_signed_bytes_is_also_caught(
    app_dsn, superuser_dsn, owner_dsn, scenario, authorize_signed
):
    """The smarter attacker: rewrite canonical_json to match the new column value.

    Then payload_hash no longer matches, and forging that requires the signing key.
    """
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        for i in range(3):
            await run(conn, make_request(scenario["mandate"], amount=1_000 + i), authorize_signed)

    async with await psycopg.AsyncConnection.connect(superuser_dsn) as su:
        async with su.cursor() as cur:
            await cur.execute(
                "UPDATE decision_records "
                "SET canonical_json = replace(canonical_json, '\"allow\"', '\"deny\"') "
                "WHERE merchant_id = %s AND seq = 2",
                (scenario["merchant"],),
            )
        await su.commit()

    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        result = await decision_records.verify_chain(conn, scenario["merchant"])

    assert result["ok"] is False
    assert result["broken_at_seq"] == 2


async def test_concurrent_requests_produce_a_contiguous_chain(
    app_dsn, owner_dsn, scenario, authorize_signed
):
    """What BIGSERIAL would have broken. 25 concurrent requests, one merchant."""
    async def one(i: int) -> str:
        async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
            try:
                await run(
                    conn,
                    make_request(
                        scenario["mandate"], amount=1_000, key=f"conc-{i:04d}-{'x' * 8}"
                    ), authorize_signed)
                return "ok"
            except Exception as exc:  # noqa: BLE001
                return f"error:{type(exc).__name__}:{exc}"

    results = await asyncio.gather(*(one(i) for i in range(25)))
    errors = [r for r in results if r.startswith("error:")]
    assert not errors, f"concurrent authorize failed: {errors[:3]}"

    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        chain = await decision_records.iter_chain(conn, scenario["merchant"])
        verified = await decision_records.verify_chain(conn, scenario["merchant"])

    assert [r["seq"] for r in chain] == list(range(1, 26))
    assert verified["ok"] is True, verified
    assert verified["gaps"] == []


async def test_a_replayed_request_returns_the_original_decision_verbatim(
    app_dsn, owner_dsn, scenario, authorize_signed
):
    """One logical decision, one record. Previously this minted a phantom second record.

    The replay returns the ORIGINAL — same decision_id, same chain_seq, same verdict —
    because the question was already answered and answering it differently the second time
    would make the record a worse account of what happened.
    """
    key = f"{rand_id('dupe')}-xxxxxxxx"
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        first = await run(conn, make_request(scenario["mandate"], key=key), authorize_signed)
        second = await run(conn, make_request(scenario["mandate"], key=key), authorize_signed)

    assert second.record_id == first.record_id
    assert second.seq == first.seq
    assert second.decision.decision == first.decision.decision
    assert second.budget_remaining_paise == first.budget_remaining_paise
    assert second.replayed is True and first.replayed is False

    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        rows = await decision_records.iter_chain(conn, scenario["merchant"])
    matching = [
        r for r in rows
        if r["request_idempotency_key"] == f"rsv:{key}"
    ]
    assert len(matching) == 1, (
        f"exactly one record per logical decision, found {len(matching)}"
    )


async def test_a_replay_short_circuits_before_any_work(
    app_dsn, scenario, signer, authorize_signed, monkeypatch
):
    """The replay lookup runs after stage 2 and before the gate, so a replay costs one
    indexed hit rather than the whole pipeline."""
    key = f"{rand_id('fast')}-xxxxxxxx"
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        await run(conn, make_request(scenario["mandate"], key=key), authorize_signed)

        calls = []
        original = pipeline.risk_stage.score_risk

        async def spy(*args, **kwargs):
            calls.append(1)
            return await original(*args, **kwargs)

        monkeypatch.setattr(pipeline.risk_stage, "score_risk", spy)
        replay = await run(conn, make_request(scenario["mandate"], key=key), authorize_signed)

    assert replay.replayed is True
    assert calls == [], "a replay must not re-run the judgment stages"
    assert "reserve_budget" not in replay.stage_timings_us


async def test_the_same_key_on_a_different_mandate_is_not_a_replay(
    owner_dsn, app_dsn, make_mandate, authorize_signed, signer
):
    """Idempotency is scoped to the mandate, not global.

    Two mandates are separate budgets and separate authorities. A global scope let one
    agent burn another agent's key — a cross-tenant denial of service and an oracle.
    """
    key = f"{rand_id('shared')}-xxxxxxxx"
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    first_mandate = await make_mandate(setup, merchant_id=rand_id("mch"))
    second_mandate = await make_mandate(setup, merchant_id=rand_id("mch"))
    await ensure_registered(setup, signer)
    await setup.commit()
    await setup.close()

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        a = await run(conn, make_request(first_mandate, key=key), authorize_signed)
        b = await run(conn, make_request(second_mandate, key=key), authorize_signed)

    assert a.record_id != b.record_id
    assert a.replayed is False and b.replayed is False
