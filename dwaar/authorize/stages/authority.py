"""Stage 2.5 — the arithmetic authority gate.  [REAL, pure, no I/O]

Everything here is derivable from the mandate alone: per-transaction cap, category
allow/deny, expiry. No database, no Redis, no model. Sub-millisecond.

── Why this stage exists ───────────────────────────────────────────────────────────────

Without it, `score_risk` runs before anything checks the per-transaction cap. Once the
model is real, a request breaching `max_per_txn_paise` would be *scored first* and its
record would carry a non-null `risk_score` — quietly falsifying the claim the demo's
sharpest beat rests on: *"denied by arithmetic, in under 5ms, with the model not even
consulted."*

That failure would not have shown up until the model landed, because until then the stub
returns `None` anyway and every test passes. It would have been discovered in the dress
rehearsal.

So the gate makes the claim **structural rather than incidental**. It is also better
engineering on its own terms: there is no reason to spend 2ms scoring a request that is
arithmetically impossible.

── The distinction a judge may probe ───────────────────────────────────────────────────

    per-txn cap, category, expiry  →  this gate, before scoring  →  risk_score NULL
    cumulative budget exhaustion   →  stage 6, after scoring     →  risk_score present

Both are arithmetic denials. They sit at different points because one needs only the
mandate and the other needs the ledger. Say exactly that.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from dwaar.authorize.types import AuthorityResult, AuthorizeRequest

STAGE_NAME = "check_authority"

# Stable `mandate.*` constants. The prefix is what lets a record distinguish mandate
# arithmetic from merchant policy — `rule_fired` starting with `mandate.` means the
# principal's own grant refused this, not a merchant rule layered on top.
RULE_EXPIRED = "mandate.expired"
RULE_CATEGORY_DENIED = "mandate.category_denied"
RULE_CATEGORY_NOT_ALLOWED = "mandate.category_not_allowed"
RULE_MAX_PER_TXN = "mandate.max_per_txn"


def check_authority(
    request: AuthorizeRequest, mandate: Mapping[str, Any], *, now: datetime
) -> AuthorityResult:
    """Pure. Same inputs, same answer, forever — which is what makes it testable exhaustively.

    Checks run in order of how completely the principal failed to authorise the action:
    expired (the authority no longer exists) → category (it never covered this) → amount
    (it covered less than this). The order is fixed so `rule_fired` is deterministic.
    """
    if mandate["expires_at"] <= now:
        return AuthorityResult(
            ok=True, permitted=False, rule_fired=RULE_EXPIRED, internal_reason="mandate_expired"
        )

    deny_categories = set(mandate["deny_categories"] or ())
    allow_categories = set(mandate["allow_categories"] or ())

    if request.category is not None and request.category in deny_categories:
        return AuthorityResult(
            ok=True,
            permitted=False,
            rule_fired=RULE_CATEGORY_DENIED,
            internal_reason=f"category_denied:{request.category}",
        )

    # A request with no category cannot be shown to be inside a non-empty allow list.
    # Fail closed: "we could not prove it was allowed" and "it was allowed" are not the
    # same, and only one of them is authority.
    if allow_categories and (
        request.category is None or request.category not in allow_categories
    ):
        return AuthorityResult(
            ok=True,
            permitted=False,
            rule_fired=RULE_CATEGORY_NOT_ALLOWED,
            internal_reason=f"category_not_allowed:{request.category}",
        )

    if request.amount_paise > mandate["max_per_txn_paise"]:
        return AuthorityResult(
            ok=True,
            permitted=False,
            rule_fired=RULE_MAX_PER_TXN,
            internal_reason=(
                f"amount {request.amount_paise} exceeds max_per_txn "
                f"{mandate['max_per_txn_paise']}"
            ),
        )

    return AuthorityResult(ok=True, permitted=True)
