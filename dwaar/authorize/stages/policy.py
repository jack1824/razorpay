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

from dwaar.authorize.types import AuthorizeRequest, PolicyResult, RiskResult
from dwaar.policy import engine
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
) -> PolicyResult:
    live = await store.get(conn, merchant_id)

    if not live.exists:
        # Consulted, nothing approved. NOT a degradation: a merchant with no compiled policy
        # is a normal state, and the mandate plus the ledger still bound everything.
        return PolicyResult(
            ok=True,
            verdict="permit",
            rule_fired=None,
            policy_version=NO_COMPILED_POLICY,
            internal_reason="no_approved_policy",
        )

    namespace = engine.build_namespace(
        request=request,
        mandate=mandate,
        budget_remaining_paise=budget_remaining_paise,
        risk_score=risk.risk_score if risk else None,
        injection_flag=risk.injection_flag if risk else False,
        agent_verified=agent_verified,
        features=features,
    )
    verdict = engine.evaluate(live.ruleset, namespace)

    return PolicyResult(
        ok=True,
        verdict=_ACTION_TO_VERDICT[verdict.action],
        rule_fired=f"policy.{verdict.rule_id}" if verdict.rule_id else None,
        policy_version=live.version,
        bounded_amount_paise=verdict.bound_to_paise,
        internal_reason=verdict.reason_code if verdict.matched else None,
    )
