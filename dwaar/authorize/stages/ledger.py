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


def nothing_to_reserve() -> LedgerResult:
    """For an action that moves no money.

    A read-only MCP tool is delegated, permitted and free. Calling `reserve()` with zero
    raises — correctly, because a zero reservation is meaningless — so the pipeline does not
    call it, and this says why in the result rather than leaving stage 7 to infer it from a
    `None`.
    """
    return LedgerResult(ok=True, reserved=False, not_required=True)


async def reserve_budget(
    request: AuthorizeRequest,
    mandate: Mapping[str, Any],
    *,
    conn: AsyncConnection,
    amount_paise: int | None = None,
) -> LedgerResult:
    """Reserve, in the caller's transaction. The caller commits, not this function.

    Sharing the transaction with stage 8 is what makes "we do not write a decision we
    cannot chain" true in both directions: a failed record write rolls the reservation back,
    and a committed reservation always has a record.

    ── Why there is an `amount_paise` parameter at all ─────────────────────────────────

    Because the amount the principal AUTHORISED is not always the amount the agent asked
    for. When the policy engine returns `bound`, it has reduced the request — and this stage
    used to reserve `request.amount_paise` regardless, because it ran before the bound was
    known to anyone.

    The consequence was a real one: a decision that told the agent "you may spend 500" while
    debiting 1,800 from the mandate's budget. The principal's remaining balance would fall
    by money that was never authorised to move, and any collection created from that
    reservation would charge the larger figure. It was caught by a test that asked the
    reservation to be the source of truth for an order.

    `None` means "the amount the agent asked for", which is the ordinary case. The caller
    passes an explicit figure only when a bound applies, and never a larger one — the ledger
    is the record of what authority was consumed, and consuming more than was granted is
    the one direction that cannot be corrected afterwards.
    """
    effective = request.amount_paise if amount_paise is None else amount_paise
    if effective > request.amount_paise:
        raise LedgerError(
            f"refusing to reserve {effective} paise against a request for "
            f"{request.amount_paise}. A bound may only ever reduce."
        )
    try:
        balance_before = await budget_ledger.balance(conn, request.mandate_id)
    except LedgerError as exc:
        return LedgerResult(ok=False, internal_reason=str(exc))

    try:
        result = await budget_ledger.reserve(
            conn,
            mandate_id=request.mandate_id,
            amount_paise=effective,
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
        reservation=result,
    )
