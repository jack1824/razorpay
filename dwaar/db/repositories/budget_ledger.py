"""Budget ledger. Enforcement is arithmetic, never a model score.

``if amount > balance: deny``. There is no score in this file and there never will be. A
99%-accurate spend cap is a broken spend cap.

── Concurrency (ADR 0001 Q2) ──────────────────────────────────────────────────────────

The mechanism is a **mandate-row lock**::

    SELECT max_total_paise FROM mandates WHERE mandate_id = %s FOR UPDATE

then read the tail, compute, insert. One transaction, no retry loop.

Why not lock the tail ledger row, as ``TECH_STACK.md`` advises? Because ``FOR UPDATE``
locks rows *that exist*, and the race is two transactions each **inserting** a new tail
computed from the same predecessor. Both see entry N, both insert N+1 and N+2 with balances
derived from N, and both satisfy ``CHECK (balance_after >= 0)`` individually. That is a
phantom, not a row conflict, and no amount of locking the predecessor prevents it. The
advice is wrong against this schema and is corrected here rather than silently ignored.

``prev_entry_id`` + ``UNIQUE (mandate_id, prev_entry_id)`` is a **tripwire, not the
mechanism**. Under correct locking it can never fire. If it ever does, the locking is
broken and the database caught an overspend that the CHECK would have missed — which is
the entire point of paying one column for it.

── Idempotency ────────────────────────────────────────────────────────────────────────

``idempotency_key UNIQUE`` absorbs duplicate webhooks, the single most common real bug in
payment integrations. ``reserve()`` returns the *existing* entry on a duplicate key rather
than raising, because a retried webhook is not an error — it is the network doing its job.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from psycopg import AsyncConnection
from psycopg.errors import UniqueViolation

from dwaar import idempotency
from dwaar.db.repositories.base import fetch_all, fetch_one
from dwaar.errors import InsufficientBudget, LedgerError
from dwaar.money import Paise

_COLUMNS = (
    "entry_id, mandate_id, prev_entry_id, delta_paise, balance_after, "
    "idempotency_key, reason, created_at"
)


@dataclass(frozen=True)
class ReserveResult:
    entry_id: int
    balance_before: Paise
    balance_after: Paise
    duplicate: bool
    """True when an existing entry was returned for a repeated idempotency key."""


async def _tail(conn: AsyncConnection, mandate_id: str) -> dict[str, Any] | None:
    """Most recent entry for a mandate. Caller must already hold the mandate row lock."""
    return await fetch_one(
        conn,
        f"SELECT {_COLUMNS} FROM budget_ledger WHERE mandate_id = %s "
        f"ORDER BY entry_id DESC LIMIT 1",
        (mandate_id,),
    )


async def balance(conn: AsyncConnection, mandate_id: str) -> Paise:
    """Current balance. Read-only, unlocked — a snapshot, not a reservation."""
    row = await _tail(conn, mandate_id)
    if row is None:
        raise LedgerError(f"no ledger entries for mandate {mandate_id}; genesis missing")
    return row["balance_after"]


async def get_by_idempotency_key(
    conn: AsyncConnection, mandate_id: str, idempotency_key: str
) -> dict[str, Any] | None:
    """Look up a STORED (already namespaced) key, scoped to its mandate.

    Mandate-scoped, not global: a global lookup would let one agent observe and collide
    with another agent's key on an unrelated mandate.
    """
    return await fetch_one(
        conn,
        f"SELECT {_COLUMNS} FROM budget_ledger "
        f"WHERE mandate_id = %s AND idempotency_key = %s",
        (mandate_id, idempotency_key),
    )


async def _append(
    conn: AsyncConnection,
    *,
    mandate_id: str,
    delta_paise: Paise,
    idempotency_key: str,
    reason: str,
) -> ReserveResult:
    """Lock the mandate, read the tail, compute, insert. The whole mechanism.

    Everything here runs in the caller's transaction. The mandate lock is released on
    commit or rollback, never before.
    """
    if not isinstance(delta_paise, int) or isinstance(delta_paise, bool):
        raise TypeError(f"delta must be int paise, got {type(delta_paise).__name__}")

    # 1. Serialise every writer for this mandate. THIS is the mechanism.
    locked = await fetch_one(
        conn,
        "SELECT mandate_id, max_total_paise FROM mandates WHERE mandate_id = %s FOR UPDATE",
        (mandate_id,),
    )
    if locked is None:
        raise LedgerError(f"unknown mandate {mandate_id}")

    # 2. Re-check the idempotency key, now that writers are serialised.
    #
    # The caller's pre-check runs unlocked and can miss a writer that had not committed
    # yet. This one cannot, for any key on this mandate — which keeps the duplicate
    # webhook on the ordinary path rather than the exception path. The exception path
    # below still matters, because idempotency_key is globally unique and two different
    # mandates can collide on one, where no mandate lock helps.
    duplicate = await get_by_idempotency_key(conn, mandate_id, idempotency_key)
    if duplicate is not None:
        return ReserveResult(
            entry_id=duplicate["entry_id"],
            balance_before=duplicate["balance_after"] - duplicate["delta_paise"],
            balance_after=duplicate["balance_after"],
            duplicate=True,
        )

    # 3. Read the tail. Safe now: no other writer for this mandate can be past step 1.
    tail = await _tail(conn, mandate_id)
    if tail is None:
        raise LedgerError(
            f"mandate {mandate_id} has no genesis entry; it was not created through "
            "mandates.create()"
        )

    balance_before: Paise = tail["balance_after"]
    balance_after: Paise = balance_before + delta_paise

    # 4. Arithmetic. Not a threshold, not a score.
    if balance_after < 0:
        raise InsufficientBudget(
            f"mandate {mandate_id}: requested {-delta_paise} paise against "
            f"{balance_before} paise remaining",
            public_reason="denied",
        )

    # 5. Append, inside a SAVEPOINT.
    #
    # The savepoint is load-bearing, not tidiness. In PostgreSQL a failed statement aborts
    # the WHOLE transaction: every subsequent command returns InFailedSqlTransaction until
    # a rollback. Without the savepoint, a UniqueViolation here would leave the connection
    # unusable and the duplicate-recovery SELECT below could never run — so the duplicate
    # webhook, the single most common real payment-integration bug, would surface to the
    # caller as an unrelated transaction error.
    try:
        async with conn.transaction():
            row = await fetch_one(
                conn,
                f"INSERT INTO budget_ledger "
                f"(mandate_id, prev_entry_id, delta_paise, balance_after, idempotency_key, "
                f" reason) VALUES (%s, %s, %s, %s, %s, %s) RETURNING {_COLUMNS}",
                (
                    mandate_id,
                    tail["entry_id"],
                    delta_paise,
                    balance_after,
                    idempotency_key,
                    reason,
                ),
            )
    except UniqueViolation as exc:
        constraint = getattr(getattr(exc, "diag", None), "constraint_name", "") or ""
        if "budget_ledger_chain_unique" in constraint:
            # The tripwire fired. This is NOT a duplicate request — it means two writers
            # got past the mandate lock, which should be impossible. Do not absorb it.
            raise LedgerError(
                f"ledger chain tripwire fired for mandate {mandate_id}: two entries share "
                f"prev_entry_id={tail['entry_id']}. The mandate row lock is not holding. "
                "See migrations/0003_budget_ledger.sql and ADR 0001 Q2."
            ) from exc

        # Idempotency key collision: another connection committed this key between our
        # pre-check and our insert. The transaction is still usable because of the
        # savepoint, so the winning entry can be read and returned.
        winner = await get_by_idempotency_key(conn, mandate_id, idempotency_key)
        if winner is None:
            raise
        return ReserveResult(
            entry_id=winner["entry_id"],
            balance_before=winner["balance_after"] - winner["delta_paise"],
            balance_after=winner["balance_after"],
            duplicate=True,
        )

    return ReserveResult(
        entry_id=row["entry_id"],
        balance_before=balance_before,
        balance_after=balance_after,
        duplicate=False,
    )


async def reserve(
    conn: AsyncConnection,
    *,
    mandate_id: str,
    amount_paise: Paise,
    idempotency_key: str,
    reason: str = "reserve",
) -> ReserveResult:
    """Reserve ``amount_paise`` against a mandate. Atomic and idempotent.

    Raises ``InsufficientBudget`` when the arithmetic says no. Returns the existing entry
    with ``duplicate=True`` when the idempotency key has been seen.
    """
    if amount_paise <= 0:
        raise ValueError(f"reserve amount must be positive, got {amount_paise}")

    # The agent's key is ALWAYS prefixed before it touches storage. Without this an agent
    # could submit "release:1234" and silently no-op the real release of entry 1234,
    # leaking that reservation permanently. See dwaar/idempotency.py.
    stored_key = idempotency.reserve_key(idempotency_key)

    existing = await get_by_idempotency_key(conn, mandate_id, stored_key)
    if existing is not None:
        return ReserveResult(
            entry_id=existing["entry_id"],
            balance_before=existing["balance_after"] - existing["delta_paise"],
            balance_after=existing["balance_after"],
            duplicate=True,
        )

    # _append re-checks the key under the mandate lock and absorbs a lost race via its
    # savepoint, so there is no UniqueViolation to handle here.
    return await _append(
        conn,
        mandate_id=mandate_id,
        delta_paise=-amount_paise,
        idempotency_key=stored_key,
        reason=reason,
    )


async def release(
    conn: AsyncConnection,
    *,
    mandate_id: str,
    amount_paise: Paise,
    reserve_entry_id: int,
    reason: str = "release",
) -> ReserveResult:
    """Release a held reservation with a **compensating entry**, never an UPDATE.

    The key is derived from ``reserve_entry_id`` rather than supplied by the caller, which
    makes a duplicate release idempotent for free.

    The app role holds no UPDATE on this table, so this is the only way it could be done —
    which is deliberate. Editing the reserving row would break ``balance == sum(deltas)``
    and make the property test vacuous.
    """
    if amount_paise <= 0:
        raise ValueError(f"release amount must be positive, got {amount_paise}")

    # Derived from the entry being reversed, never supplied. Releasing the same
    # reservation twice therefore collides and is absorbed instead of double-crediting.
    stored_key = idempotency.release_key(reserve_entry_id)

    existing = await get_by_idempotency_key(conn, mandate_id, stored_key)
    if existing is not None:
        return ReserveResult(
            entry_id=existing["entry_id"],
            balance_before=existing["balance_after"] - existing["delta_paise"],
            balance_after=existing["balance_after"],
            duplicate=True,
        )

    return await _append(
        conn,
        mandate_id=mandate_id,
        delta_paise=amount_paise,
        idempotency_key=stored_key,
        reason=reason,
    )


async def history(conn: AsyncConnection, mandate_id: str) -> list[dict[str, Any]]:
    return await fetch_all(
        conn,
        f"SELECT {_COLUMNS} FROM budget_ledger WHERE mandate_id = %s ORDER BY entry_id",
        (mandate_id,),
    )


async def check_invariants(conn: AsyncConnection) -> dict[str, int]:
    """Invariant 1 from schema.sql, plus the sum check the property test asserts.

    Both MUST be zero. Run by the verifier and by the eval harness — never hardcoded.
    """
    negative = await fetch_one(
        conn, "SELECT count(*) AS n FROM budget_ledger WHERE balance_after < 0"
    )
    drift = await fetch_one(
        conn,
        "SELECT count(*) AS n FROM ("
        "  SELECT mandate_id, "
        "         sum(delta_paise) AS total, "
        "         (array_agg(balance_after ORDER BY entry_id DESC))[1] AS tail "
        "  FROM budget_ledger GROUP BY mandate_id"
        ") s WHERE s.total <> s.tail",
    )
    return {"negative_balances": negative["n"], "sum_delta_drift": drift["n"]}
