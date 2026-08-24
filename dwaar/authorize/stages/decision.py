"""Stage 7 — render the decision.  [REAL, pure, synchronous]

No connection, no await, no clock. This is the only place the five-way decision is chosen,
so it can be tested exhaustively over the cross-product of stage outcomes without a
database — which matters, because this function is the system's actual answer to the
question the product exists to ask.

Reason codes are **coarse outbound, fine-grained inbound** (threat 10). Telling an agent
precisely which limit it hit lets it binary-search the mandate, so the agent gets a category
and the record keeps the detail.
"""

from __future__ import annotations

from dwaar.authorize.types import (
    AuthorityResult,
    AuthorizeRequest,
    Decision,
    InjectionResult,
    LedgerResult,
    MandateResult,
    PolicyResult,
    RiskResult,
    SignatureResult,
)

STAGE_NAME = "render_decision"

# Coarse codes. The whole outbound vocabulary — deliberately small.
REASON_ALLOWED = "allowed"
REASON_DENIED = "denied"
REASON_NOT_AUTHORIZED = "not_authorized"
REASON_UNAVAILABLE = "unavailable"
REASON_STEP_UP = "step_up_required"
REASON_THROTTLED = "throttled"


def render_decision(
    request: AuthorizeRequest,
    signature: SignatureResult,
    mandate: MandateResult,
    authority: AuthorityResult,
    injection: InjectionResult | None,
    risk: RiskResult | None,
    policy: PolicyResult | None,
    ledger: LedgerResult | None,
) -> Decision:
    """Choose the decision. ``risk``/``policy``/``ledger`` are None when short-circuited."""

    # Authority first, and unconditionally. Nothing downstream can grant what the principal
    # did not, so no later stage gets a chance to overturn these.
    if not mandate.ok:
        return Decision(
            decision="deny",
            reason_code=REASON_NOT_AUTHORIZED,
            internal_reason=mandate.internal_reason or "mandate_invalid",
            rule_fired="mandate.invalid",
        )

    if not authority.permitted:
        return Decision(
            decision="deny",
            reason_code=REASON_DENIED,
            internal_reason=authority.internal_reason or "authority_denied",
            rule_fired=authority.rule_fired,
        )

    # Judgment stages. A policy deny beats any score, always — deterministic rules override
    # probabilistic ones (FAIL_MATRIX.md, "conflicting signals").
    if policy is not None and policy.verdict == "deny":
        return Decision(
            decision="deny",
            reason_code=REASON_DENIED,
            internal_reason=policy.internal_reason or "policy_deny",
            rule_fired=policy.rule_fired,
        )
    if policy is not None and policy.verdict == "step_up":
        return Decision(
            decision="step_up",
            reason_code=REASON_STEP_UP,
            internal_reason=policy.internal_reason or "policy_step_up",
            rule_fired=policy.rule_fired,
        )
    if policy is not None and policy.verdict == "throttle":
        return Decision(
            decision="throttle",
            reason_code=REASON_THROTTLED,
            internal_reason=policy.internal_reason or "policy_throttle",
            rule_fired=policy.rule_fired,
            retry_after_ms=1000,
        )

    if injection is not None and injection.flagged:
        return Decision(
            decision="deny",
            reason_code=REASON_DENIED,
            internal_reason="injection_detected",
            rule_fired="injection.detected",
        )

    # Ledger. Unavailable and exceeded are different answers.
    if ledger is None or not ledger.ok:
        return Decision(
            decision="deny",
            reason_code=REASON_UNAVAILABLE,
            internal_reason=(ledger.internal_reason if ledger else "ledger_not_reached"),
            rule_fired="ledger.unavailable",
        )
    if not ledger.reserved:
        return Decision(
            decision="deny",
            reason_code=REASON_DENIED,
            internal_reason=ledger.internal_reason or "insufficient_budget",
            rule_fired=ledger.rule_fired,
        )

    if policy is not None and policy.verdict == "bound":
        return Decision(
            decision="bound",
            reason_code=REASON_ALLOWED,
            internal_reason=policy.internal_reason or "policy_bound",
            rule_fired=policy.rule_fired,
            bounded_amount_paise=policy.bounded_amount_paise,
        )

    return Decision(
        decision="allow",
        reason_code=REASON_ALLOWED,
        internal_reason=None,
        rule_fired=None,
    )
