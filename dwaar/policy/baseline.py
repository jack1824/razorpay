"""The baseline ruleset: what the risk score does when nobody wrote a policy about it.

── The problem this solves ─────────────────────────────────────────────────────────────

A risk score changes a decision only if some rule reads it. That is the correct
architecture — there is exactly one place in this system where a number becomes a verdict,
and it is the policy engine — but taken literally it means a merchant who has compiled no
policy gets a model that scores 0.97 and then does nothing at all.

Two ways to fix that, and only one of them is acceptable.

The tempting one is a threshold in the pipeline: `if risk_score > 0.8: deny`. It is four
lines. It also puts authority logic in a second place, produces a denial with no
`rule_fired` a merchant can be shown, and creates a decision path the policy engine does not
know about — so "the policy engine decides" would become false in exactly the case where the
model is loudest.

The one taken here: **the bands are a policy.** Written in the same DSL, evaluated by the
same engine, producing the same `rule_fired`, appearing in the same audit trail. A judge
asking "where does the score turn into a decision" gets one answer and one file.

── How it composes with a merchant's policy ────────────────────────────────────────────

Both rulesets are evaluated and the **more restrictive verdict wins** — not
first-match-wins across a concatenation.

Concatenation would make ordering into authority. Put the merchant's rules first and an
`allow` rule shadows the baseline deny; put the baseline first and the merchant cannot
express any rule about a scored request at all. Taking the maximum of the two makes the
baseline a floor: a merchant policy can tighten anything, and can loosen nothing that the
baseline refuses. That is the same one-directional property the arithmetic gate has, and it
holds without depending on the order two authors happened to write their rules in.

── What this is not ────────────────────────────────────────────────────────────────────

It is not signed and it is not approved by anyone, because it is code — it ships and is
reviewed with the release, and its `rule_fired` values are prefixed `baseline.` so a record
never suggests a merchant agreed to it. A merchant's compiled policy remains the only thing
that goes through the compile / test / human-approve path.
"""

from __future__ import annotations

from dwaar.policy import dsl
from dwaar.risk.bands import DENY_BAND, STEP_UP_BAND

#: Restrictiveness, ascending. `max` over this order is the composition rule.
#:
#: `bound` sits above `permit` because reducing an amount is a refusal of part of the
#: request. `throttle` is above `bound` because it refuses the whole request for now, and
#: `step_up` above that because it refuses until a human intervenes. `deny` is final.
RESTRICTIVENESS: dict[str, int] = {
    "permit": 0,
    "allow": 0,
    "bound": 1,
    "throttle": 2,
    "step_up": 3,
    "deny": 4,
}


def more_restrictive(left: str, right: str) -> str:
    """The stricter of two verdicts. Unknown verdicts are treated as the strictest, because
    a verdict this function does not recognise is not something to resolve optimistically."""
    if left not in RESTRICTIVENESS or right not in RESTRICTIVENESS:
        return "deny"
    return left if RESTRICTIVENESS[left] >= RESTRICTIVENESS[right] else right


#: Requests per minute above which a scoreless request is throttled.
#:
#: Deliberately high. It is a backstop for a blind model, not a rate limit — a legitimate
#: shopping agent runs at roughly ten per minute and a card tester at two hundred and forty,
#: so this sits well clear of the first and well under the second. Set from the arrival rates
#: in `zoo/agents/`, and it is the one number in this file that would need revisiting against
#: real traffic.
DEGRADED_VELOCITY_PER_MINUTE = 30

#: The bands from `dwaar/risk/bands.py`, expressed as rules rather than restated as numbers.
#: Importing the constants means the console banner, the model's own `band` field and the
#: rule that actually decides can never drift apart — the failure mode where a demo asserts
#: "deny above 0.80" while the rule says 0.85.
BASELINE_DOCUMENT = {
    "rules": [
        {
            "id": "baseline.injection_detected",
            "when": {"==": [{"var": "risk.injection_flag"}, {"lit": True}]},
            "action": "deny",
            "reason_code": "denied",
            "description": "Instruction-shaped content in an agent-supplied field.",
        },
        {
            "id": "baseline.risk_deny",
            "when": {">": [{"var": "risk.score"}, {"lit": DENY_BAND}]},
            "action": "deny",
            "reason_code": "denied",
            "description": f"Behavioural risk above {DENY_BAND}.",
        },
        {
            "id": "baseline.risk_step_up",
            "when": {">=": [{"var": "risk.score"}, {"lit": STEP_UP_BAND}]},
            "action": "step_up",
            "reason_code": "step_up_required",
            "description": f"Behavioural risk in [{STEP_UP_BAND}, {DENY_BAND}].",
        },
        {
            # ── The tightened limit that applies when the model is blind ─────────────
            #
            # `risk.score IS NULL` inside the policy stage means exactly one thing: stage 4
            # produced no score. It cannot mean "the gate short-circuited", because a
            # short-circuited request never reaches the policy engine at all. So this rule
            # fires when, and only when, the model is unavailable.
            #
            # The fail matrix calls the risk model fail-OPEN, and it stays fail-open: a
            # blind model does not deny anything. What it does is lower the bar at which
            # velocity alone is enough to slow an agent down — from "the model will catch
            # it" to a flat arithmetic threshold. `DEGRADED_VELOCITY_PER_MINUTE` is far
            # above what a legitimate agent reaches and far below a card tester, so the
            # cost of being wrong is a retry rather than a refusal.
            #
            # Expressed as a rule rather than as a branch in the pipeline for the same
            # reason the bands are: there is one place where a number becomes a verdict.
            "id": "baseline.degraded_velocity",
            "when": {
                "and": [
                    {"is_null": {"var": "risk.score"}},
                    {">": [
                        {"var": "features.velocity_1m"},
                        {"lit": DEGRADED_VELOCITY_PER_MINUTE},
                    ]},
                ]
            },
            "action": "throttle",
            "reason_code": "throttled",
            "description": (
                "Model unavailable and velocity above the degraded-mode threshold. "
                "Throttle, never deny — the model being blind is not evidence of anything."
            ),
        },
        {
            # Never fires on its own. Present because `dsl.parse` rejects a ruleset with no
            # rules, and because a ruleset whose last entry is an explicit permit states its
            # default rather than leaving it to be inferred from falling off the end.
            "id": "baseline.permit",
            "when": {"lit": True},
            "action": "allow",
            "reason_code": "allowed",
            "description": "No baseline concern.",
        },
    ]
}

RULESET: dsl.Ruleset = dsl.parse(BASELINE_DOCUMENT)

#: Bumped by hand when a rule changes. Written into the log line beside the merchant's
#: `policy_version`, so a decision made under an old baseline is identifiable after the
#: fact — the same reason `model_version` exists.
BASELINE_VERSION = 1
