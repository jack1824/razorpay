"""The authorize pipeline: eight stages plus the arithmetic gate, with per-stage timing.

Stage order and what each one may do:

    1  verify_signature   STUB  fail-closed     identity
    2  resolve_mandate    REAL  fail-closed     authority
   2.5 check_authority    REAL  pure, no I/O    authority — short-circuits 3-6
    3  compute_features   STUB  degrade         judgment
    4  score_risk         STUB  fail-open       judgment
    5  evaluate_policy    STUB  last-signed     deterministic rules
    6  reserve_budget     REAL  fail-closed     authority (cumulative cap)
    7  render_decision    REAL  pure            the answer
    8  write_decision_record REAL fail-closed   the evidence

Stages 6 and 8 share one transaction. Lock order is always mandate row → chain advisory,
never the reverse.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from psycopg import AsyncConnection

from dwaar import idempotency
from dwaar.authorize.stages import authority as authority_stage
from dwaar.authorize.stages import decision as decision_stage
from dwaar.authorize.stages import features as features_stage
from dwaar.authorize.stages import ledger as ledger_stage
from dwaar.authorize.stages import mandate as mandate_stage
from dwaar.authorize.stages import policy as policy_stage
from dwaar.authorize.stages import record as record_stage
from dwaar.authorize.stages import risk as risk_stage
from dwaar.authorize.stages import signature as signature_stage
from dwaar.authorize.types import AuthorizeRequest, Decision
from dwaar.config import Settings
from dwaar.crypto.signer import Signer
from dwaar.db.repositories import decision_records
from dwaar.errors import ChainError
from dwaar.logging import get_logger
from dwaar.metrics import authorize_duration, decisions_total, stage_duration
from dwaar.nonce import NonceStore
from dwaar.policy.store import PolicyStore

log = get_logger("dwaar.authorize")

# Not a stage in the ARCHITECTURE table: it is a short-circuit that runs before the work,
# so it is named separately and still timed.
REPLAY_STAGE = "replay_lookup"

# Process-wide fallback so a caller that does not manage one still gets caching rather
# than a database round trip per request. The API supplies its own via app.state.
_DEFAULT_POLICY_STORE = PolicyStore()

# The stage names, in order. `tests/test_stub_contracts.py` enumerates this rather than a
# hand-written list, so a stage added without a degradation token cannot slip through.
STAGE_ORDER: tuple[str, ...] = (
    signature_stage.STAGE_NAME,
    mandate_stage.STAGE_NAME,
    REPLAY_STAGE,
    authority_stage.STAGE_NAME,
    features_stage.STAGE_NAME,
    risk_stage.STAGE_NAME,
    policy_stage.STAGE_NAME,
    ledger_stage.STAGE_NAME,
    decision_stage.STAGE_NAME,
    record_stage.STAGE_NAME,
)

# Stage 1 became real on 25 Aug and stage 5 on 26 Aug, so `signature_unverified` and
# `policy_stubbed` no longer appear on any record.
STUB_STAGES: dict[str, str] = {
    features_stage.STAGE_NAME: features_stage.DEGRADED_TOKEN,
    risk_stage.STAGE_NAME: risk_stage.DEGRADED_TOKEN,
}


class Unauthenticated(Exception):
    """Stage 1 refused. 401, counter and log — never a chained record.

    An unattributable request is a security event, not an authorization decision. Chaining
    it would hand anyone with an HTTP client write access to the evidence chain: a storage
    amplification and denial-of-service attack against the one artifact the whole design
    exists to protect.
    """


class Unresolvable(Exception):
    """Stage 2 could not resolve the mandate at all. 403, no record.

    ``merchant_id`` is the chain's shard key and comes from the mandate, so an unresolvable
    mandate has no chain to be written to. This is a property of the design, not a
    limitation worked around.
    """


@dataclass
class PipelineOutcome:
    decision: Decision
    record_id: str | None = None
    seq: int | None = None
    budget_remaining_paise: int | None = None
    latency_us: int = 0
    stage_timings_us: dict[str, int] = field(default_factory=dict)
    degraded_mode: list[str] = field(default_factory=list)
    stages_executed: list[str] = field(default_factory=list)
    replayed: bool = False
    """True when this outcome was read back from an existing record, not decided afresh."""


def _replayed(row, timer: _Timer, started: float) -> PipelineOutcome:
    """Rebuild the outcome from a stored record.

    The verdict returned to the caller is the one that was actually chained. `latency_us`
    is the CURRENT call's latency, not the original's: the caller waited this long, and
    reporting the first request's timing would be a measurement of something that did not
    happen. The record keeps the original.
    """
    return PipelineOutcome(
        decision=Decision(
            decision=row["decision"],
            reason_code=row["reason_code"],
            internal_reason="replayed",
            rule_fired=row["rule_fired"],
        ),
        record_id=str(row["record_id"]),
        seq=row["seq"],
        budget_remaining_paise=row["budget_after"],
        latency_us=int((time.perf_counter() - started) * 1_000_000),
        stage_timings_us=timer.timings,
        degraded_mode=list(row["degraded_mode"]),
        stages_executed=list(row["stages_executed"]),
        replayed=True,
    )


class _Timer:
    """Per-stage wall time, in insertion order."""

    def __init__(self) -> None:
        self.timings: dict[str, int] = {}

    async def run(self, name: str, coro):
        start = time.perf_counter()
        try:
            return await coro
        finally:
            self.timings[name] = int((time.perf_counter() - start) * 1_000_000)

    def sync(self, name: str, fn, *args, **kwargs):
        start = time.perf_counter()
        try:
            return fn(*args, **kwargs)
        finally:
            self.timings[name] = int((time.perf_counter() - start) * 1_000_000)


async def authorize(
    request: AuthorizeRequest,
    *,
    conn: AsyncConnection,
    signer: Signer,
    settings: Settings,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    method: str = "POST",
    path: str = "/v1/authorize",
    nonce_store: NonceStore | None = None,
    policy_store: PolicyStore | None = None,
    now: datetime | None = None,
) -> PipelineOutcome:
    """Run the pipeline. The caller owns the transaction and commits on success."""
    started = time.perf_counter()
    now = now or datetime.now(UTC)
    timer = _Timer()
    degraded: list[str] = []
    executed: list[str] = []

    # ── 1. signature ────────────────────────────────────────────────────────────────
    signature = await timer.run(
        signature_stage.STAGE_NAME,
        signature_stage.verify_signature(
            request,
            headers or {},
            settings=settings,
            conn=conn,
            body=body,
            method=method,
            path=path,
            nonce_store=nonce_store,
            now=now,
        ),
    )
    executed.append(signature_stage.STAGE_NAME)
    if signature.degraded:
        degraded.append(signature.degraded)
    if not signature.ok:
        raise Unauthenticated(signature.internal_reason or "signature_invalid")

    # ── 2. mandate ──────────────────────────────────────────────────────────────────
    mandate = await timer.run(
        mandate_stage.STAGE_NAME, mandate_stage.resolve_mandate(request, conn=conn, now=now)
    )
    executed.append(mandate_stage.STAGE_NAME)
    if mandate.merchant_id is None:
        raise Unresolvable(mandate.internal_reason or "mandate_unresolvable")

    # ── 2.1 replay. One indexed lookup, before any work. ────────────────────────────
    #
    # Checked HERE rather than at stage 8 so a replay costs a single index hit instead of
    # the whole pipeline. Returning the original verbatim — same decision_id, same
    # chain_seq, same verdict — is correct for every outcome including throttle and
    # step_up: the question was already answered, and answering it differently the second
    # time would make the record a worse account of what happened.
    request_key = idempotency.reserve_key(request.idempotency_key)
    if mandate.mandate_hash is not None:
        prior = await timer.run(
            REPLAY_STAGE,
            decision_records.get_by_request_key(conn, mandate.mandate_hash, request_key),
        )
        if prior is not None:
            return _replayed(prior, timer, started)

    features = risk = policy = ledger = None

    if mandate.ok:
        # ── 2.5 arithmetic gate. Pure, no I/O. ──────────────────────────────────────
        gate = timer.sync(
            authority_stage.STAGE_NAME,
            authority_stage.check_authority,
            request,
            mandate.mandate,
            now=now,
        )
        executed.append(authority_stage.STAGE_NAME)

        if gate.permitted:
            # ── 3-5 judgment ────────────────────────────────────────────────────────
            features = await timer.run(
                features_stage.STAGE_NAME,
                features_stage.compute_features(request, mandate.mandate),
            )
            executed.append(features_stage.STAGE_NAME)
            if features.degraded:
                degraded.append(features.degraded)

            risk = await timer.run(
                risk_stage.STAGE_NAME, risk_stage.score_risk(request, features.features)
            )
            executed.append(risk_stage.STAGE_NAME)
            if risk.degraded:
                degraded.append(risk.degraded)

            policy = await timer.run(
                policy_stage.STAGE_NAME,
                policy_stage.evaluate_policy(
                    request,
                    mandate.mandate,
                    risk,
                    conn=conn,
                    store=policy_store or _DEFAULT_POLICY_STORE,
                    merchant_id=mandate.merchant_id,
                    features=features.features,
                ),
            )
            executed.append(policy_stage.STAGE_NAME)
            if policy.degraded:
                degraded.append(policy.degraded)

            # ── 6. budget. Only if 1-5 permit. ──────────────────────────────────────
            if policy.verdict != "deny" and not risk.injection_flag:
                ledger = await timer.run(
                    ledger_stage.STAGE_NAME,
                    ledger_stage.reserve_budget(request, mandate.mandate, conn=conn),
                )
                executed.append(ledger_stage.STAGE_NAME)
                if ledger.degraded:
                    degraded.append(ledger.degraded)
    else:
        # Resolved but revoked or expired: still an authorization decision about a known
        # principal, so it is rendered and chained rather than returned as a bare error.
        gate = authority_stage.AuthorityResult(
            ok=True, permitted=False, rule_fired="mandate.invalid"
        )

    # ── 7. decide. Pure. ────────────────────────────────────────────────────────────
    decision = timer.sync(
        decision_stage.STAGE_NAME,
        decision_stage.render_decision,
        request,
        signature,
        mandate,
        gate,
        risk,
        policy,
        ledger,
    )
    executed.append(decision_stage.STAGE_NAME)

    # ── 8. record. Fail-closed: rolls stage 6 back if it fails. ─────────────────────
    written = await timer.run(
        record_stage.STAGE_NAME,
        record_stage.write_decision_record(
            conn=conn,
            signer=signer,
            started_at=started,
            created_at=now,
            request_digest=record_stage.compute_request_digest(body),
            decision=decision,
            mandate=mandate,
            authority=gate,
            features=features,
            risk=risk,
            policy=policy,
            ledger=ledger,
            degraded=degraded,
            stages_executed=executed + [record_stage.STAGE_NAME],
            agent_id=request.agent_id,
            amount_paise=request.amount_paise,
            request_idempotency_key=request_key,
        ),
    )
    executed.append(record_stage.STAGE_NAME)

    total_us = int((time.perf_counter() - started) * 1_000_000)

    # The COMPLETE duration, including the insert that `decision_records.latency_us`
    # structurally cannot contain. Both numbers are honest; only one of them fits in the
    # row. See dwaar/metrics.py.
    authorize_duration.labels(decision=decision.decision).observe(total_us / 1_000_000)
    for stage_name, micros in timer.timings.items():
        stage_duration.labels(stage=stage_name).observe(micros / 1_000_000)
    decisions_total.labels(
        decision=decision.decision, rule_fired=decision.rule_fired or "none"
    ).inc()

    outcome = PipelineOutcome(
        decision=decision,
        record_id=written.record_id,
        seq=written.seq,
        budget_remaining_paise=ledger.budget_after if ledger else None,
        latency_us=total_us,
        stage_timings_us=timer.timings,
        degraded_mode=sorted(degraded),
        stages_executed=executed,
    )

    log.info(
        "authorize",
        agent_id=request.agent_id,
        mandate_id=request.mandate_id,
        merchant_id=mandate.merchant_id,
        decision=decision.decision,
        reason_code=decision.reason_code,
        rule_fired=decision.rule_fired,
        risk_score=risk.risk_score if risk else None,
        chain_seq=written.seq,
        latency_us=total_us,
        stage_timings_us=timer.timings,
        degraded_mode=outcome.degraded_mode,
        stages_executed=executed,
    )
    return outcome


__all__ = [
    "authorize",
    "risk_stage",
    "signature_stage",
    "features_stage",
    "policy_stage",
    "ledger_stage",
    "PipelineOutcome",
    "Unauthenticated",
    "Unresolvable",
    "STAGE_ORDER",
    "STUB_STAGES",
    "ChainError",
    "Any",
]
