"""The authorize pipeline: eight stages plus the arithmetic gate, with per-stage timing.

Stage order and what each one may do:

    1  verify_signature   REAL  fail-closed     identity
    2  resolve_mandate    REAL  fail-closed     authority
   2.2 record_observation REAL  degrade         the rolling window — see below
   2.5 check_authority    REAL  pure, no I/O    authority — short-circuits 3-6
    3  compute_features   REAL  degrade         judgment
   3.5 detect_injection   REAL  rules-only      judgment — sees TEXT, produces a boolean
    4  score_risk         REAL  fail-open       judgment — sees NUMBERS, produces a score
    5  evaluate_policy    REAL  last-signed     deterministic rules
    6  reserve_budget     REAL  fail-closed     authority (cumulative cap)
    7  render_decision    REAL  pure            the answer
    8  write_decision_record REAL fail-closed   the evidence

Stages 6 and 8 share one transaction. Lock order is always mandate row → chain advisory,
never the reverse.

── Why the observation is recorded BEFORE the gate ─────────────────────────────────────

The gate short-circuits stages 3-6 on a per-transaction breach, which is what makes
`risk_score IS NULL` on such a record a structural property. If the rolling window were only
written by stage 3, it would then contain **only requests the gate permitted** — every
feature would be conditioned on the gate's own decision, and a budget breacher whose
requests all die at the gate would look like a quiet agent with almost no history.

So the window is written between the replay check and the gate. Every attempt is observed;
only permitted attempts are scored. It costs one Redis round trip on the deny path and it is
what lets `dwaar/risk/features.py` claim its vector is a function of behaviour rather than of
authority.

Replays are not observed: `_replayed` returns before this point, because a retried webhook is
one attempt that was delivered twice, not two attempts.
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
from dwaar.authorize.stages import injection as injection_stage
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
from dwaar.risk import observations as obsmod
from dwaar.risk.observations import (
    InMemoryObservationStore,
    RedisObservationStore,
    WindowSnapshot,
)

log = get_logger("dwaar.authorize")

# Not a stage in the ARCHITECTURE table: it is a short-circuit that runs before the work,
# so it is named separately and still timed.
REPLAY_STAGE = "replay_lookup"

#: Also not a stage in the ARCHITECTURE table. It writes the rolling window that stage 3
#: reads, and it runs before the gate so the window is not conditioned on the gate's own
#: decision. Named and timed like everything else.
OBSERVE_STAGE = "record_observation"

# Process-wide fallback so a caller that does not manage one still gets caching rather
# than a database round trip per request. The API supplies its own via app.state.
_DEFAULT_POLICY_STORE = PolicyStore()

ObservationStore = RedisObservationStore | InMemoryObservationStore

# The stage names, in order. `tests/test_stub_contracts.py` enumerates this rather than a
# hand-written list, so a stage added without a degradation token cannot slip through.
STAGE_ORDER: tuple[str, ...] = (
    signature_stage.STAGE_NAME,
    mandate_stage.STAGE_NAME,
    REPLAY_STAGE,
    OBSERVE_STAGE,
    authority_stage.STAGE_NAME,
    features_stage.STAGE_NAME,
    injection_stage.STAGE_NAME,
    risk_stage.STAGE_NAME,
    policy_stage.STAGE_NAME,
    ledger_stage.STAGE_NAME,
    decision_stage.STAGE_NAME,
    record_stage.STAGE_NAME,
)

# EMPTY, as of 27 August. Stage 1 became real on the 25th, stage 5 on the 26th, and stages
# 3 and 4 on the 27th — so no record carries a token meaning "this component does not exist".
#
# Every remaining token in `degraded_mode` now names a RUNTIME condition: Redis unreachable,
# a model bundle that would not load. `tests/test_stub_contracts.py` enumerates this dict
# rather than a hand-written list, so a stub reintroduced without a token cannot slip
# through, and `tests/db/test_authorize_pipeline.py` asserts a normal request carries an
# empty `degraded_mode` — the milestone that says the pipeline is no longer a scaffold.
STUB_STAGES: dict[str, str] = {}


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
    observation_store: ObservationStore | None = None,
    scorer: risk_stage.ScorerLike | None = None,
    detector: Any | None = None,
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

    features = risk = policy = ledger = injection = None

    # ── 2.2 observe. Before the gate, deliberately — see the module docstring. ───────
    window = await timer.run(
        OBSERVE_STAGE,
        _observe(observation_store, request, mandate.principal_id, now),
    )
    executed.append(OBSERVE_STAGE)

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
            # No mandate parameter, and that is the enforcement rather than the style:
            # a feature that cannot see an authority limit cannot encode one.
            features = timer.sync(
                features_stage.STAGE_NAME,
                features_stage.compute_features_from_window,
                request,
                window,
                now.timestamp(),
            )
            executed.append(features_stage.STAGE_NAME)
            if features.degraded:
                degraded.append(features.degraded)

            # The ONLY stage that reads agent-supplied text. It produces a boolean, never
            # a score, and nothing downstream of it sees the text — which is what keeps the
            # behavioural model out of reach of anything an attacker can write.
            # Guarded, because "the stage ran" and "the flag is not NULL" have to agree —
            # migration 0014 constrains the record to it. A stage that runs without a
            # detector would appear in `stages_executed` while reporting NOT CHECKED, which
            # is precisely the contradiction the tristate exists to prevent. The application
            # always supplies one; `dwaar.risk.injection.load()` never returns None.
            if detector is not None:
                injection = timer.sync(
                    injection_stage.STAGE_NAME,
                    injection_stage.detect_injection,
                    request,
                    detector=detector,
                )
                executed.append(injection_stage.STAGE_NAME)
                if injection.degraded:
                    degraded.append(injection.degraded)

            # The scorer sees the feature vector and nothing else — not the request, not
            # the mandate, not a connection. So a stored row can be replayed against the
            # named model version and produce the same number.
            risk = await timer.run(
                risk_stage.STAGE_NAME,
                risk_stage.score_risk(features.features, scorer=scorer),
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
                    injection=injection,
                ),
            )
            executed.append(policy_stage.STAGE_NAME)
            if policy.degraded:
                degraded.append(policy.degraded)

            # ── 6. budget. Only if 1-5 permit. ──────────────────────────────────────
            if policy.verdict != "deny" and not (injection and injection.flagged):
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
        injection,
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
            injection=injection,
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
        injection_flag=injection.flagged if injection else None,
        risk_band=risk.band if risk else None,
        supervised_score=risk.supervised_score if risk else None,
        anomaly_score=risk.anomaly_score if risk else None,
        model_version=risk.model_version if risk else None,
        top_features=[name for name, _ in (risk.top_features if risk else ())],
        chain_seq=written.seq,
        latency_us=total_us,
        stage_timings_us=timer.timings,
        degraded_mode=outcome.degraded_mode,
        stages_executed=executed,
    )
    return outcome


async def _observe(
    store: ObservationStore | None,
    request: AuthorizeRequest,
    principal_id: str | None,
    now: datetime,
) -> WindowSnapshot:
    """Read the rolling window and append this attempt to it, in one round trip.

    Returns the EMPTY snapshot when there is no store or no resolved principal. Empty is
    distinguishable from "no history" — `WindowSnapshot.available` is False — so stage 3 can
    tell a degradation from a first-time agent rather than reporting one as the other.
    """
    if store is None or principal_id is None:
        return obsmod.EMPTY
    return await store.observe(
        agent_id=request.agent_id,
        principal_id=principal_id,
        observation=obsmod.observation_from_request(request, now=now.timestamp()),
    )


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
