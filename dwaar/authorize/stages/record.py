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
    LedgerResult,
    MandateResult,
    PolicyResult,
    RecordResult,
    RiskResult,
)
from dwaar.crypto import record as recordmod
from dwaar.crypto.signer import Signer
from dwaar.db.repositories import decision_records
from dwaar.errors import ChainError

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
    risk: RiskResult | None,
    policy: PolicyResult | None,
    ledger: LedgerResult | None,
    degraded: list[str],
    stages_executed: list[str],
    agent_id: str,
    amount_paise: int | None,
) -> RecordResult:
    if mandate.merchant_id is None or mandate.mandate_hash is None:
        # No resolved merchant means no chain to write to — merchant_id is the shard key.
        # This is why an unknown mandate is a bare 403 and not a chained deny.
        raise ChainError(
            "cannot write a decision record without a resolved merchant; an unattributable "
            "request is a security event, not an authorization decision"
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
        decision=decision.decision,
        reason_code=decision.reason_code,
        rule_fired=decision.rule_fired,
        risk_score=risk.risk_score if risk else None,
        model_version=risk.model_version if risk else None,
        injection_flag=risk.injection_flag if risk else False,
        features=features.features if features else {},
        policy_version=policy.policy_version if policy else None,
        amount_paise=amount_paise,
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
