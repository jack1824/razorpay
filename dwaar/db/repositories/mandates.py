"""Mandates repository. The mandate is the capability token *and* the intent receipt.

``create()`` writes the mandate **and its genesis ledger entry in one transaction**
(ADR 0001 Q3). A mandate without an opening balance is not a usable mandate: ``reserve()``
computes from the ledger tail, and with no tail there is nothing to compute from. Doing it
here rather than lazily on first reserve means ``balance == sum(deltas)`` is literally true
from the first row — which is exactly what the Hypothesis property test asserts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from psycopg import AsyncConnection

from dwaar import idempotency
from dwaar.db.repositories.base import (
    HASH_BYTES,
    SIG_BYTES,
    execute,
    fetch_all,
    fetch_one,
    from_hex,
)

_COLUMNS = (
    "mandate_id, principal_id, agent_id, max_total_paise, max_per_txn_paise, "
    "allow_categories, deny_categories, substitution_tolerance, expires_at, nonce, "
    "canonical_json, signature, mandate_hash, created_at, revoked_at"
)

GENESIS_REASON = "mandate_created"

# Re-exported so callers do not reimplement the derivation. The rules live in one module
# (dwaar/idempotency.py) because a key derived one way here and another way in
# budget_ledger.release is a collision waiting for traffic.
genesis_key = idempotency.genesis_key


async def create(
    conn: AsyncConnection,
    *,
    mandate_id: str,
    principal_id: str,
    agent_id: str,
    max_total_paise: int,
    max_per_txn_paise: int,
    expires_at: datetime,
    nonce: str,
    canonical_json: str,
    signature: str | bytes,
    mandate_hash: str | bytes,
    allow_categories: list[str] | None = None,
    deny_categories: list[str] | None = None,
    substitution_tolerance: str = "none",
) -> dict[str, Any]:
    """Insert the mandate and its genesis ledger entry atomically.

    The caller controls the transaction; both statements land in whatever transaction is
    open on ``conn``. Do not commit between them.
    """
    row = await fetch_one(
        conn,
        f"INSERT INTO mandates ("
        f"  mandate_id, principal_id, agent_id, max_total_paise, max_per_txn_paise, "
        f"  allow_categories, deny_categories, substitution_tolerance, expires_at, "
        f"  nonce, canonical_json, signature, mandate_hash"
        f") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING {_COLUMNS}",
        (
            mandate_id,
            principal_id,
            agent_id,
            max_total_paise,
            max_per_txn_paise,
            allow_categories or [],
            deny_categories or [],
            substitution_tolerance,
            expires_at,
            nonce,
            canonical_json,
            from_hex(signature, expect_len=SIG_BYTES),
            from_hex(mandate_hash, expect_len=HASH_BYTES),
        ),
    )

    # Genesis entry: the opening balance IS the mandate's total. prev_entry_id is NULL,
    # which the UNIQUE (mandate_id, prev_entry_id) tripwire does not constrain — NULLs are
    # distinct in a PostgreSQL unique index. Single-genesis is guaranteed by the
    # idempotency key instead. See migrations/0003 and ADR 0001.
    await execute(
        conn,
        "INSERT INTO budget_ledger "
        "(mandate_id, prev_entry_id, delta_paise, balance_after, idempotency_key, reason) "
        "VALUES (%s, NULL, %s, %s, %s, %s)",
        (
            mandate_id,
            max_total_paise,
            max_total_paise,
            idempotency.genesis_key(mandate_id),
            GENESIS_REASON,
        ),
    )
    return row


async def get(conn: AsyncConnection, mandate_id: str) -> dict[str, Any] | None:
    return await fetch_one(
        conn, f"SELECT {_COLUMNS} FROM mandates WHERE mandate_id = %s", (mandate_id,)
    )


async def get_by_hash(conn: AsyncConnection, mandate_hash: str | bytes) -> dict[str, Any] | None:
    """Resolve a decision record back to the authority that was exercised."""
    return await fetch_one(
        conn,
        f"SELECT {_COLUMNS} FROM mandates WHERE mandate_hash = %s",
        (from_hex(mandate_hash, expect_len=HASH_BYTES),),
    )


async def list_active_for_agent(
    conn: AsyncConnection, agent_id: str, *, now: datetime | None = None
) -> list[dict[str, Any]]:
    """Unrevoked and unexpired only. Uses idx_mandates_agent_active."""
    return await fetch_all(
        conn,
        f"SELECT {_COLUMNS} FROM mandates "
        f"WHERE agent_id = %s AND revoked_at IS NULL AND expires_at > COALESCE(%s, now()) "
        f"ORDER BY created_at DESC",
        (agent_id, now),
    )


async def revoke(conn: AsyncConnection, mandate_id: str) -> bool:
    """Revoke. Idempotent — re-revoking does not move ``revoked_at``."""
    return await execute(
        conn,
        "UPDATE mandates SET revoked_at = now() "
        "WHERE mandate_id = %s AND revoked_at IS NULL",
        (mandate_id,),
    ) == 1
