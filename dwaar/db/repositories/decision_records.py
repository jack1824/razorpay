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
    fetch_all,
    fetch_one,
    from_hex,
)
from dwaar.errors import ChainError

GENESIS_PREV_HASH: bytes = b"\x00" * HASH_BYTES
"""Genesis link. 32 zero bytes; 64 zeros in hex at any JSON boundary."""

_COLUMNS = (
    "record_id, merchant_id, seq, prev_hash, payload_hash, signature, signing_key_id, "
    "agent_id, principal_id, mandate_hash, request_digest, decision, reason_code, "
    "rule_fired, risk_score, model_version, injection_flag, amount_paise, budget_before, "
    "budget_after, features, policy_version, latency_us, degraded_mode, stages_executed, "
    "canonical_json, request_idempotency_key, created_at"
)

VALID_DECISIONS = frozenset({"allow", "bound", "throttle", "step_up", "deny"})

# There is deliberately ONE insert path — `append_signed` — and it requires a signature.
# An unsigned `append()` existed during Phase 2 and was removed when stage 8 became real:
# a second way to write a record, which happens not to sign, is precisely the lie-shaped
# artifact the stub rule exists to prevent. Someone would eventually have used it.


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


async def get(conn: AsyncConnection, record_id: str) -> dict[str, Any] | None:
    return await fetch_one(
        conn, f"SELECT {_COLUMNS} FROM decision_records WHERE record_id = %s", (record_id,)
    )


async def get_by_request_key(
    conn: AsyncConnection, mandate_hash: bytes | str, request_idempotency_key: str
) -> dict[str, Any] | None:
    """The replay lookup. One indexed hit, sub-millisecond.

    Scoped to the mandate rather than global, for the same reason the ledger is: a global
    lookup would let one agent observe and collide with another agent's key.
    """
    return await fetch_one(
        conn,
        f"SELECT {_COLUMNS} FROM decision_records "
        f"WHERE mandate_hash = %s AND request_idempotency_key = %s",
        (from_hex(mandate_hash, expect_len=HASH_BYTES), request_idempotency_key),
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


async def append_signed(
    conn: AsyncConnection,
    *,
    merchant_id: str,
    position: ChainPosition,
    payload: dict[str, Any],
    canonical_json: str,
    payload_hash: bytes,
    signature: bytes,
    created_at: Any,
) -> dict[str, Any]:
    """Insert a record whose payload was already canonicalised and signed.

    Separate from ``append`` because the signed form has a different contract: the caller
    has already taken the chain lock, read the position, and computed a hash over that
    exact ``(seq, prev_hash)``. Re-deriving anything here would risk signing one position
    and inserting at another, producing a record that verifies against nothing.

    Every column value is read back out of ``payload`` rather than taken as a separate
    argument — including ``signing_key_id``, which was briefly a parameter until a test
    proved the two could disagree. A column that differs from the bytes signed over it
    produces a record that verifies against nothing, which is indistinguishable from a
    forgery.
    """
    if payload["seq"] != position.seq:
        raise ChainError(
            f"signed payload is for seq {payload['seq']} but the chain position is "
            f"{position.seq}; inserting would store a signature over the wrong position"
        )

    # ON CONFLICT DO NOTHING on the request key, then re-SELECT.
    #
    # Two identical requests both miss the early replay lookup and race to here. The loser
    # gets zero rows back and reads the winner's record. Deliberately NOT a bare
    # `ON CONFLICT DO NOTHING`: that would also swallow a chain-uniqueness violation, which
    # must never be absorbed silently — it would mean the advisory lock is not holding.
    #
    # No savepoint needed, because the transaction never enters a failed state.
    row = await fetch_one(
        conn,
        f"INSERT INTO decision_records ("
        f"  merchant_id, seq, prev_hash, payload_hash, signature, signing_key_id, "
        f"  agent_id, principal_id, mandate_hash, request_digest, decision, reason_code, "
        f"  rule_fired, risk_score, model_version, injection_flag, amount_paise, "
        f"  budget_before, budget_after, features, policy_version, latency_us, "
        f"  degraded_mode, stages_executed, canonical_json, request_idempotency_key, "
        f"  created_at"
        f") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
        f"        %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        f"ON CONFLICT (mandate_hash, request_idempotency_key) "
        f"  WHERE request_idempotency_key IS NOT NULL DO NOTHING "
        f"RETURNING {_COLUMNS}",
        (
            merchant_id,
            payload["seq"],
            position.prev_hash,
            payload_hash,
            signature,
            payload["signing_key_id"],
            payload["agent_id"],
            payload["principal_id"],
            from_hex(payload["mandate_hash"], expect_len=HASH_BYTES),
            from_hex(payload["request_digest"], expect_len=HASH_BYTES),
            payload["decision"],
            payload["reason_code"],
            payload["rule_fired"],
            payload["risk_score"],
            payload["model_version"],
            payload["injection_flag"],
            payload["amount_paise"],
            payload["budget_before"],
            payload["budget_after"],
            json.dumps(payload["features"], sort_keys=True, separators=(",", ":")),
            payload["policy_version"],
            payload["latency_us"],
            payload["degraded_mode"],
            payload["stages_executed"],
            canonical_json,
            payload["request_idempotency_key"],
            created_at,
        ),
    )
    if row is not None:
        return row

    # Lost the race. The winner's record is authoritative and is returned verbatim.
    winner = await get_by_request_key(
        conn, payload["mandate_hash"], payload["request_idempotency_key"]
    )
    if winner is None:
        raise ChainError(
            "decision record insert was absorbed as a duplicate but the original could not "
            "be read back; the request-idempotency index and the insert disagree"
        )
    return winner


async def verify_chain(
    conn: AsyncConnection, merchant_id: str, *, from_seq: int = 1, limit: int = 10_000
) -> dict[str, Any]:
    """Walk a merchant's chain and verify links and signatures.

    A *walk*, not `seq - 1` arithmetic: each record's ``prev_hash`` is compared against its
    immediate predecessor in seq order. Gaps are reported separately rather than treated as
    breaks, because `FAIL_MATRIX.md` records that a Postgres outage produces denials that
    cannot be chained, and an outage must not read as a tamper.

    Returns ``{ok, records, broken_at_seq, reason, gaps}``.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from dwaar.crypto import record as recordmod

    rows = await iter_chain(conn, merchant_id, from_seq=from_seq, limit=limit)
    if not rows:
        return {"ok": True, "records": 0, "broken_at_seq": None, "reason": None, "gaps": []}

    keys = {
        r["key_id"]: bytes(r["public_key"])
        for r in await fetch_all(conn, "SELECT key_id, public_key FROM signing_keys")
    }

    expected_prev = GENESIS_PREV_HASH if from_seq == 1 else None
    for row in rows:
        # 0. THE COLUMNS MUST AGREE WITH THE BYTES THAT WERE SIGNED.
        #
        #    Without this, an attacker edits `amount_paise` and leaves canonical_json
        #    alone: every hash still matches, the signature still verifies, and the row
        #    everyone actually reads now says something the principal never authorised.
        #    Demo beat 6 is exactly that UPDATE.
        try:
            rebuilt = recordmod.canonical_json(recordmod.payload_from_row(row))
        except Exception as exc:  # noqa: BLE001
            return _broken(row, f"columns cannot be canonicalised: {exc}", rows)
        if rebuilt != row["canonical_json"]:
            return _broken(row, "columns do not match the signed canonical_json", rows)

        # 1. The stored canonical form must actually hash to the stored payload_hash.
        recomputed = __import__("hashlib").sha256(row["canonical_json"].encode()).digest()
        if recomputed != bytes(row["payload_hash"]):
            return _broken(row, "payload_hash does not match canonical_json", rows)

        # 2. The canonical form must be the canonical form — a re-canonicalisation that
        #    differs means the stored bytes were hand-edited into something JCS would
        #    never have produced.
        import json as _json

        if recordmod.canonical_json(_json.loads(row["canonical_json"])) != row["canonical_json"]:
            return _broken(row, "canonical_json is not in canonical form", rows)

        # 3. The chain link.
        if expected_prev is not None and bytes(row["prev_hash"]) != expected_prev:
            return _broken(row, "prev_hash does not match the preceding payload_hash", rows)

        # 4. The signature, resolved through the key the record names.
        public = keys.get(row["signing_key_id"])
        if public is None:
            return _broken(row, f"unknown signing_key_id {row['signing_key_id']}", rows)
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(
                bytes(row["signature"]), row["canonical_json"].encode("utf-8")
            )
        except InvalidSignature:
            return _broken(row, "signature does not verify", rows)

        expected_prev = bytes(row["payload_hash"])

    return {
        "ok": True,
        "records": len(rows),
        "broken_at_seq": None,
        "reason": None,
        "gaps": await check_contiguity(conn, merchant_id),
    }


def _broken(row: dict[str, Any], reason: str, rows: list) -> dict[str, Any]:
    return {
        "ok": False,
        "records": len(rows),
        "broken_at_seq": row["seq"],
        "reason": reason,
        "gaps": [],
    }
