"""Decision records. Append-only, hash-chained, signed, per-merchant.

── Why there is no update() or delete() in this module ─────────────────────────────────

Not because writing one would be poor style — because the app role could not execute one.
``dwaar_app`` holds ``SELECT, INSERT`` on this table and nothing else. The absence here
mirrors a grant, and ``tests/db/test_append_only_grant.py`` asserts the grant rather than
trusting the absence.

── Chain append (ADR 0001 Q4) ─────────────────────────────────────────────────────────

``seq`` is allocated as ``max(seq)+1`` inside ``pg_advisory_xact_lock(hashtext(merchant_id))``,
never by a sequence. ``BIGSERIAL`` allocates outside transaction control: concurrent workers
commit out of order, and a rollback burns a value permanently. Since ``prev_hash`` must be
the ``payload_hash`` of ``seq-1``, either behaviour breaks the chain irrecoverably — and it
would have broken on day 6, under the first concurrent load, not on day 2 where it would
have been cheap to find.

The advisory lock is transaction-scoped, so it releases on commit or rollback with no
explicit unlock and no way to leak it.

Keying on ``merchant_id`` rather than globally shards the chain for the cost of one
``hashtext`` call. The verifier iterates chains. With one merchant it is identical in
practice, and the answer to "does this scale" is a fact about the schema rather than a
promise about the roadmap.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from psycopg import AsyncConnection

from dwaar.db.repositories.base import (
    HASH_BYTES,
    SIG_BYTES,
    fetch_all,
    fetch_one,
    from_hex,
    to_hex,
)
from dwaar.errors import ChainError
from dwaar.money import Paise

GENESIS_PREV_HASH: bytes = b"\x00" * HASH_BYTES
"""Genesis link. 32 zero bytes; 64 zeros in hex at any JSON boundary."""

_COLUMNS = (
    "record_id, merchant_id, seq, prev_hash, payload_hash, signature, signing_key_id, "
    "agent_id, principal_id, mandate_hash, request_digest, decision, rule_fired, "
    "risk_score, injection_flag, amount_paise, budget_before, budget_after, features, "
    "policy_version, latency_us, degraded_mode, created_at"
)

VALID_DECISIONS = frozenset({"allow", "bound", "throttle", "step_up", "deny"})


@dataclass(frozen=True)
class ChainPosition:
    seq: int
    prev_hash: bytes


async def lock_chain(conn: AsyncConnection, merchant_id: str) -> None:
    """Take the per-merchant chain lock for the rest of this transaction.

    Must be called before ``next_position`` and the insert, in the same transaction, or
    the chain is not serialised and ``seq`` allocation races.
    """
    async with conn.cursor() as cur:
        await cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (merchant_id,))


async def tail(conn: AsyncConnection, merchant_id: str) -> dict[str, Any] | None:
    return await fetch_one(
        conn,
        f"SELECT {_COLUMNS} FROM decision_records WHERE merchant_id = %s "
        f"ORDER BY seq DESC LIMIT 1",
        (merchant_id,),
    )


async def next_position(conn: AsyncConnection, merchant_id: str) -> ChainPosition:
    """The seq and prev_hash the next record must use. Requires the chain lock."""
    row = await tail(conn, merchant_id)
    if row is None:
        return ChainPosition(seq=1, prev_hash=GENESIS_PREV_HASH)
    return ChainPosition(seq=row["seq"] + 1, prev_hash=bytes(row["payload_hash"]))


async def append(
    conn: AsyncConnection,
    *,
    merchant_id: str,
    payload_hash: str | bytes,
    signature: str | bytes,
    signing_key_id: str,
    agent_id: str,
    principal_id: str,
    mandate_hash: str | bytes,
    request_digest: str | bytes,
    decision: str,
    features: dict[str, Any],
    policy_version: int,
    latency_us: int,
    rule_fired: str | None = None,
    risk_score: float | None = None,
    injection_flag: bool = False,
    amount_paise: Paise | None = None,
    budget_before: Paise | None = None,
    budget_after: Paise | None = None,
    degraded_mode: str | None = None,
    expect_position: ChainPosition | None = None,
) -> dict[str, Any]:
    """Append one record to the merchant's chain.

    Takes the chain lock itself, so the caller does not have to remember to. Everything
    runs in the caller's transaction; on rollback the lock releases and no ``seq`` is
    burned — which is the whole reason ``seq`` is not a sequence.

    ``expect_position`` lets a caller that computed ``payload_hash`` over a specific
    ``(seq, prev_hash)`` assert it still holds. It always will, because the lock is held —
    but the signature covers those fields, so a mismatch would produce a record that
    verifies against nothing, and failing loudly beats writing it.
    """
    if decision not in VALID_DECISIONS:
        raise ValueError(
            f"invalid decision {decision!r}; expected one of {sorted(VALID_DECISIONS)}"
        )

    await lock_chain(conn, merchant_id)
    position = await next_position(conn, merchant_id)

    if expect_position is not None and (
        expect_position.seq != position.seq
        or expect_position.prev_hash != position.prev_hash
    ):
        raise ChainError(
            f"chain position moved under the lock for merchant {merchant_id}: "
            f"expected seq={expect_position.seq} prev={to_hex(expect_position.prev_hash)}, "
            f"found seq={position.seq} prev={to_hex(position.prev_hash)}"
        )

    return await fetch_one(
        conn,
        f"INSERT INTO decision_records ("
        f"  merchant_id, seq, prev_hash, payload_hash, signature, signing_key_id, "
        f"  agent_id, principal_id, mandate_hash, request_digest, decision, rule_fired, "
        f"  risk_score, injection_flag, amount_paise, budget_before, budget_after, "
        f"  features, policy_version, latency_us, degraded_mode"
        f") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        f"RETURNING {_COLUMNS}",
        (
            merchant_id,
            position.seq,
            position.prev_hash,
            from_hex(payload_hash, expect_len=HASH_BYTES),
            from_hex(signature, expect_len=SIG_BYTES),
            signing_key_id,
            agent_id,
            principal_id,
            from_hex(mandate_hash, expect_len=HASH_BYTES),
            from_hex(request_digest, expect_len=HASH_BYTES),
            decision,
            rule_fired,
            risk_score,
            injection_flag,
            amount_paise,
            budget_before,
            budget_after,
            json.dumps(features, sort_keys=True, separators=(",", ":")),
            policy_version,
            latency_us,
            degraded_mode,
        ),
    )


async def get(conn: AsyncConnection, record_id: str) -> dict[str, Any] | None:
    return await fetch_one(
        conn, f"SELECT {_COLUMNS} FROM decision_records WHERE record_id = %s", (record_id,)
    )


async def get_by_seq(
    conn: AsyncConnection, merchant_id: str, seq: int
) -> dict[str, Any] | None:
    return await fetch_one(
        conn,
        f"SELECT {_COLUMNS} FROM decision_records WHERE merchant_id = %s AND seq = %s",
        (merchant_id, seq),
    )


async def merchants(conn: AsyncConnection) -> list[str]:
    """Every merchant with a chain. The verifier iterates these."""
    rows = await fetch_all(
        conn, "SELECT DISTINCT merchant_id FROM decision_records ORDER BY merchant_id"
    )
    return [r["merchant_id"] for r in rows]


async def iter_chain(
    conn: AsyncConnection, merchant_id: str, *, from_seq: int = 1, limit: int = 1000
) -> list[dict[str, Any]]:
    """A page of one merchant's chain in seq order, for the verifier."""
    return await fetch_all(
        conn,
        f"SELECT {_COLUMNS} FROM decision_records "
        f"WHERE merchant_id = %s AND seq >= %s ORDER BY seq LIMIT %s",
        (merchant_id, from_seq, limit),
    )


async def check_contiguity(conn: AsyncConnection, merchant_id: str) -> list[int]:
    """Return the seq values that are missing from a merchant's chain.

    A gap is not automatically a tamper. `FAIL_MATRIX.md` records that a Postgres outage
    produces denials that cannot be chained, and those show up here as absence. The
    verifier reports gaps; it does not silently treat them as breaks.
    """
    rows = await fetch_all(
        conn,
        "SELECT s AS missing FROM generate_series("
        "  (SELECT min(seq) FROM decision_records WHERE merchant_id = %s), "
        "  (SELECT max(seq) FROM decision_records WHERE merchant_id = %s)"
        ") s "
        "WHERE NOT EXISTS ("
        "  SELECT 1 FROM decision_records d WHERE d.merchant_id = %s AND d.seq = s"
        ") ORDER BY s",
        (merchant_id, merchant_id, merchant_id),
    )
    return [r["missing"] for r in rows]
