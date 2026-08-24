"""Stage 5 — compiled policy evaluation.  [REAL]

Budget 1ms. Deterministic rule DSL, compiled offline by an LLM and human-approved.
**Fail behaviour**: the last signed version continues serving; compilation is a build-time
activity that never touches a request.

── Policy beats the model. Always. ─────────────────────────────────────────────────────

When the policy verdict and the risk score disagree, **policy wins** — asserted by
`tests/test_render_decision.py::test_policy_deny_beats_a_confidently_benign_risk_score`
rather than left to rule ordering.

The reason is not that rules are more accurate. It is that a deterministic rule is a
*commitment* the merchant made and can be shown afterwards, while a score is an opinion
formed at request time. When the two disagree, the one that can be defended in a dispute is
the rule.

Note what this stage cannot do: it runs AFTER the arithmetic gate, so it can never permit
something the mandate forbade. Its verdicts only ever tighten.

── policy_version semantics, carried into every record ─────────────────────────────────

    NULL  the engine was never consulted — the arithmetic gate short-circuited
    0     consulted; no approved policy exists for this merchant
    >0    the approved version that decided

Three different facts about how a decision was reached. The audit trail keeps them apart
rather than collapsing all three to "no policy".
"""

from __future__ import annotations

from typing import Any

from psycopg import AsyncConnection

from dwaar.authorize.types import (
    AuthorizeRequest,
    InjectionResult,
    PolicyResult,
    RiskResult,
)
from dwaar.policy import baseline, engine
from dwaar.policy.store import NO_COMPILED_POLICY, PolicyStore

STAGE_NAME = "evaluate_policy"

#: Actions the DSL can produce, mapped to the pipeline's verdict vocabulary. `allow` from a
#: rule means "this rule explicitly permits", which is a permit, not a decision.
_ACTION_TO_VERDICT = {
    "allow": "permit",
    "deny": "deny",
    "bound": "bound",
    "step_up": "step_up",
    "throttle": "throttle",
}


async def evaluate_policy(
    request: AuthorizeRequest,
    mandate: dict[str, Any],
    risk: RiskResult | None,
    *,
    conn: AsyncConnection,
    store: PolicyStore,
    merchant_id: str,
    budget_remaining_paise: int | None = None,
    agent_verified: bool | None = None,
    features: dict[str, Any] | None = None,
    injection: InjectionResult | None = None,
) -> PolicyResult:
    live = await store.get(conn, merchant_id)

    namespace = engine.build_namespace(
        request=request,
        mandate=mandate,
        budget_remaining_paise=budget_remaining_paise,
        risk_score=risk.risk_score if risk else None,
        injection_flag=injection.flagged if injection else None,
        injection_checked=injection is not None and injection.flagged is not None,
        agent_verified=agent_verified,
        features=features,
    )

    # The baseline always runs. It is what turns a risk score into a decision, and it runs
    # even for a merchant with no compiled policy — otherwise a model scoring 0.97 would
    # change nothing at all for exactly the merchants least likely to have written rules.
    base = engine.evaluate(baseline.RULESET, namespace)
    base_verdict = _ACTION_TO_VERDICT[base.action]

    if not live.exists:
        # Consulted, nothing approved. NOT a degradation: a merchant with no compiled policy
        # is a normal state, and the mandate, the baseline and the ledger still bound
        # everything.
        return PolicyResult(
            ok=True,
            verdict=base_verdict,
            rule_fired=_rule_name(base.rule_id, base_verdict),
            policy_version=NO_COMPILED_POLICY,
            internal_reason=base.reason_code if base_verdict != "permit" else
            "no_approved_policy",
        )

    merchant = engine.evaluate(live.ruleset, namespace)
    merchant_verdict = _ACTION_TO_VERDICT[merchant.action]

    # Most restrictive wins, rather than first-match across a concatenation. See
    # `dwaar/policy/baseline.py`: concatenation would make the order two authors happened to
    # write their rules in into an authority decision.
    winning = baseline.more_restrictive(merchant_verdict, base_verdict)
    chosen = merchant if winning == merchant_verdict else base

    return PolicyResult(
        ok=True,
        verdict=winning,
        rule_fired=_rule_name(chosen.rule_id, winning),
        policy_version=live.version,
        bounded_amount_paise=chosen.bound_to_paise,
        internal_reason=chosen.reason_code if chosen.matched else None,
    )


def _rule_name(rule_id: str | None, verdict: str) -> str | None:
    """`policy.<id>` for a merchant rule, `policy.baseline.<id>` for a baseline one.

    A permit is reported as no rule at all: "nothing objected" is not the same claim as
    "a rule affirmatively allowed this", and `rule_fired` is read as the latter.
    """
    if rule_id is None or verdict == "permit":
        return None
    return f"policy.{rule_id}"
