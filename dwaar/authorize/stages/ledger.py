"""Stage 6 — budget reservation.  [REAL]

Budget 8ms. **Fail-closed**: never permit unbounded spend. The system stops selling rather
than sell without a limit.

Conditional, not unconditional. Reserving before the decision is rendered would mean every
policy-denied request takes a write and then needs a compensating release — a worse failure
surface for no benefit. Stages 1-5 gather; this runs only if they permit.

The per-transaction cap is **not** checked here — the arithmetic gate at stage 2.5 already
refused it before anything was scored. What this enforces is the *cumulative* cap, which
needs the ledger and therefore cannot move earlier. Both are arithmetic; they sit at
different points because they need different inputs.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from psycopg import AsyncConnection

from dwaar.authorize.types import AuthorizeRequest, LedgerResult
from dwaar.db.repositories import budget_ledger
from dwaar.errors import InsufficientBudget, LedgerError

STAGE_NAME = "reserve_budget"

RULE_BUDGET_EXHAUSTED = "mandate.max_total"


async def reserve_budget(
    request: AuthorizeRequest, mandate: Mapping[str, Any], *, conn: AsyncConnection
) -> LedgerResult:
    """Reserve, in the caller's transaction. The caller commits, not this function.

    Sharing the transaction with stage 8 is what makes "we do not write a decision we
    cannot chain" true in both directions: a failed record write rolls the reservation back,
    and a committed reservation always has a record.
    """
    try:
        balance_before = await budget_ledger.balance(conn, request.mandate_id)
    except LedgerError as exc:
        return LedgerResult(ok=False, internal_reason=str(exc))

    try:
        result = await budget_ledger.reserve(
            conn,
            mandate_id=request.mandate_id,
            amount_paise=request.amount_paise,
            idempotency_key=request.idempotency_key,
            reason="authorize",
        )
    except InsufficientBudget as exc:
        return LedgerResult(
            ok=True,
            reserved=False,
            budget_before=balance_before,
            budget_after=balance_before,
            rule_fired=RULE_BUDGET_EXHAUSTED,
            internal_reason=str(exc),
        )
    except LedgerError as exc:
        # Authority is unavailable rather than exceeded. Fail-closed, and distinctly so:
        # "you cannot afford this" and "we cannot tell whether you can" are different
        # answers and the record must not conflate them.
        return LedgerResult(ok=False, internal_reason=str(exc))

    return LedgerResult(
        ok=True,
        reserved=True,
        entry_id=result.entry_id,
        budget_before=result.balance_before,
        budget_after=result.balance_after,
        internal_reason="duplicate_absorbed" if result.duplicate else None,
    )
