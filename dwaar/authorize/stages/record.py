"""Stage 8 — canonicalise, hash, chain, sign, insert.  [REAL]

Budget 3ms. **Fail-closed**: we do not write a decision we cannot sign into the chain.

Runs in the same transaction as stage 6, so a failure here rolls the reservation back. That
is the only arrangement in which "a committed reservation always has a record" and "no
record exists that we could not chain" are both true.

── Lock ordering, which is an invariant and not a preference ───────────────────────────

    mandate row lock (stage 6)  →  chain advisory lock (stage 8)

Always this order, everywhere. Two requests on one merchant taking them in opposite orders
deadlock. `tests/db/test_lock_ordering.py` runs both orderings concurrently to assert the
codebase only ever uses this one.

── What `latency_us` measures ──────────────────────────────────────────────────────────

Request start → immediately before the payload is built, which is *after* the chain lock is
acquired and the tail is read. It therefore includes lock wait (real latency the caller
experienced) and excludes only canonicalisation, signing and the INSERT itself.

It cannot include its own write: it is a column in the row being inserted, and patching it
afterwards would need an UPDATE grant on an append-only table — the one thing this design
refuses. The p99 gate measures the *whole* pipeline including the insert, so the gate is
strictly stricter than the number the record carries, and a Prometheus histogram carries
the complete figure for operations.
"""

from __future__ import annotations

import time
from datetime import datetime

from psycopg import AsyncConnection

from dwaar.authorize.types import (
    AuthorityResult,
    Decision,
    FeatureResult,
    InjectionResult,
    LedgerResult,
    MandateResult,
    PolicyResult,
    RecordResult,
    RiskResult,
)
from dwaar.crypto import record as recordmod
from dwaar.crypto.signer import Signer
from dwaar.db.repositories import decision_records
from dwaar.errors import AmountInvariantViolation, ChainError
from dwaar.invariants import AmountFacts, check_amount_conserved

STAGE_NAME = "write_decision_record"


async def write_decision_record(
    *,
    conn: AsyncConnection,
    signer: Signer,
    started_at: float,
    created_at: datetime,
    request_digest: bytes,
    decision: Decision,
    mandate: MandateResult,
    authority: AuthorityResult,
    features: FeatureResult | None,
    injection: InjectionResult | None,
    risk: RiskResult | None,
    policy: PolicyResult | None,
    ledger: LedgerResult | None,
    degraded: list[str],
    stages_executed: list[str],
    agent_id: str,
    amount_paise: int | None,
    request_idempotency_key: str | None,
    tool: str | None = None,
) -> RecordResult:
    if mandate.merchant_id is None or mandate.mandate_hash is None:
        # No resolved merchant means no chain to write to — merchant_id is the shard key.
        # This is why an unknown mandate is a bare 403 and not a chained deny.
        raise ChainError(
            "cannot write a decision record without a resolved merchant; an unattributable "
            "request is a security event, not an authorization decision"
        )

    # ── The money invariant, BEFORE anything is written ─────────────────────────────
    #
    # What the ledger moved must equal what the decision stated, with the BOUND amount —
    # not the requested one — as the stated amount. Checked here rather than in a test
    # because a test proves it held on the cases someone thought of, and an assertion
    # proves it holds on the cases nobody did. F-038 was in the second set for four phases:
    # a `bound` told the agent ₹500 and debited ₹1,800, and every surface except these two
    # numbers agreed.
    #
    # A violation is a FAILED REQUEST, not a logged warning. Stage 8 shares its transaction
    # with stage 6, so raising here rolls the reservation back — nothing moved and nothing
    # was written, which is the only safe answer when the system cannot say what it just
    # did. `migrations/0017` carries the same rule as a CHECK constraint; this raises first
    # because it produces an error a reader can act on and because it still fires against a
    # database where the migration has not been applied.
    violation = check_amount_conserved(
        AmountFacts(
            decision=decision.decision,
            requested_paise=amount_paise,
            stated_paise=decision.bounded_amount_paise,
            budget_before=ledger.budget_before if ledger else None,
            budget_after=ledger.budget_after if ledger else None,
        )
    )
    if violation is not None:
        raise AmountInvariantViolation(
            f"refusing to record a decision that does not conserve money: {violation}"
        )

    await decision_records.lock_chain(conn, mandate.merchant_id)
    position = await decision_records.next_position(conn, mandate.merchant_id)

    latency_us = int((time.perf_counter() - started_at) * 1_000_000)

    payload = recordmod.build_payload(
        seq=position.seq,
        merchant_id=mandate.merchant_id,
        prev_hash=position.prev_hash,
        signing_key_id=signer.key_id,
        agent_id=agent_id,
        principal_id=mandate.principal_id,
        mandate_hash=mandate.mandate_hash,
        request_digest=request_digest,
        request_idempotency_key=request_idempotency_key,
        decision=decision.decision,
        reason_code=decision.reason_code,
        rule_fired=decision.rule_fired,
        risk_score=risk.risk_score if risk else None,
        model_version=risk.model_version if risk else None,
        # TRISTATE. `None` when stage 3.5 never ran, which is exactly when a gate denial
        # short-circuited it. Migration 0014 constrains this to agree with
        # `stages_executed`, so a record cannot claim a check it did not perform.
        injection_flag=injection.flagged if injection else None,
        features=features.features if features else {},
        policy_version=policy.policy_version if policy else None,
        amount_paise=amount_paise,
        # The amount the decision STATED. Present in the signed payload only when a
        # bound applied; without it the invariant above has one side missing and a
        # reader has no way to check the order that was created against the decision.
        bounded_amount_paise=decision.bounded_amount_paise,
        # The MCP tool named, when the request arrived through dwaar/mcp/. A record
        # saying `mcp.scope.money.outbound` without naming the tool is evidence of a
        # category of refusal rather than of a refusal.
        tool=tool,
        budget_before=ledger.budget_before if ledger else None,
        budget_after=ledger.budget_after if ledger else None,
        degraded_mode=degraded,
        stages_executed=stages_executed,
        latency_us=latency_us,
        created_at=created_at,
    )

    canonical = recordmod.canonical_json(payload)
    payload_hash = recordmod.payload_hash(payload)
    signature = signer.sign(canonical.encode("utf-8"))

    row = await decision_records.append_signed(
        conn,
        merchant_id=mandate.merchant_id,
        position=position,
        payload=payload,
        canonical_json=canonical,
        payload_hash=payload_hash,
        signature=signature,
        created_at=created_at,
    )

    return RecordResult(
        ok=True,
        record_id=str(row["record_id"]),
        seq=row["seq"],
        payload_hash=payload_hash,
    )


def compute_request_digest(body: bytes) -> bytes:
    """sha256 of the exact request body.

    A digest proves what the bytes were; only a signature proves the agent produced them.
    Day 4's RFC 9421 verification is what turns this from provenance into attribution.
    """
    import hashlib

    return hashlib.sha256(body).digest()
