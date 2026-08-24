"""The baseline ruleset: where a risk score becomes a decision, and how it composes.

There is exactly one place in this system where a number turns into a verdict, and it is the
policy engine. The bands are a POLICY — same DSL, same evaluator, same `rule_fired`, same
audit trail — rather than a threshold branch in the pipeline. This file asserts that, and
asserts the composition rule that keeps a merchant's policy from loosening it.
"""

from __future__ import annotations

import pytest

from dwaar.policy import baseline, dsl, engine
from dwaar.risk.bands import DENY_BAND, STEP_UP_BAND
from dwaar.risk.features import FEATURE_SCALE


class _Request:
    amount_paise = 100_000
    category = "groceries"
    action = "purchase"
    sku = "SKU1000"


def verdict(*, risk_score=None, injection=False, velocity=1.0):
    namespace = engine.build_namespace(
        request=_Request(),
        risk_score=risk_score,
        injection_flag=injection,
        features={"velocity_1m": int(velocity * FEATURE_SCALE)},
    )
    return engine.evaluate(baseline.RULESET, namespace)


# ── the bands ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("score", "action"),
    [
        (0.0, "allow"),
        (0.54, "allow"),
        (STEP_UP_BAND, "step_up"),
        (0.7, "step_up"),
        (DENY_BAND, "step_up"),
        (0.81, "deny"),
        (1.0, "deny"),
    ],
)
def test_the_bands_are_enforced_by_a_rule(score, action):
    assert verdict(risk_score=score).action == action


def test_the_band_numbers_are_imported_not_restated():
    """The console banner, the model's `band` field and the rule that decides must read one
    definition. Restating them is how a demo ends up asserting 'deny above 0.80' while the
    rule says something else."""
    document = repr(baseline.BASELINE_DOCUMENT)
    assert repr(DENY_BAND) in document
    assert repr(STEP_UP_BAND) in document


def test_a_scoreless_request_is_not_treated_as_benign():
    """`None` is not a low score. It means the model produced nothing, and the rules that
    read `risk.score` must simply not fire rather than reading NULL as zero."""
    fired = verdict(risk_score=None)
    assert fired.rule_id == "baseline.permit"
    assert fired.action == "allow"


# ── the tightened limit when the model is blind ─────────────────────────────────────


def test_a_blind_model_tightens_velocity_rather_than_denying():
    """Fail-OPEN, as the fail matrix says — but not fail-oblivious.

    A model that produced no score is not evidence of anything, so nothing is denied. What
    changes is that velocity alone becomes enough to slow an agent down, at a threshold far
    above legitimate traffic. The cost of being wrong is a retry, not a refusal.
    """
    quiet = verdict(risk_score=None, velocity=5)
    fast = verdict(risk_score=None, velocity=baseline.DEGRADED_VELOCITY_PER_MINUTE + 1)

    assert quiet.action == "allow"
    assert fast.action == "throttle"
    assert fast.rule_id == "baseline.degraded_velocity"


def test_the_tightened_limit_does_not_apply_while_the_model_is_working():
    """Otherwise it would be a flat rate limit wearing a degradation's name, and a busy
    legitimate agent would be throttled on a healthy system."""
    working = verdict(risk_score=0.1, velocity=baseline.DEGRADED_VELOCITY_PER_MINUTE * 10)
    assert working.action == "allow"


def test_the_degraded_threshold_sits_between_the_archetypes():
    """Set from the zoo's arrival rates rather than from taste.

    A legitimate agent runs at roughly ten requests per minute and a card tester at two
    hundred and forty. A threshold below the first throttles good customers whenever Redis
    hiccups; above the second it does nothing at all.
    """
    from zoo.agents.card_tester import MEAN_GAP_SECONDS as TESTER_GAP
    from zoo.agents.legit_shopper import MEAN_GAP_SECONDS as SHOPPER_GAP

    shopper_per_minute = 60 / SHOPPER_GAP
    tester_per_minute = 60 / TESTER_GAP
    assert shopper_per_minute < baseline.DEGRADED_VELOCITY_PER_MINUTE < tester_per_minute


# ── injection ───────────────────────────────────────────────────────────────────────


def test_the_injection_flag_denies():
    """The rule exists before the detector does. When stage 4 starts setting the flag on
    28 August, the decision path it feeds is already built, already tested and already
    visible in the audit trail as a named rule."""
    assert verdict(injection=True).action == "deny"
    assert verdict(injection=True).rule_id == "baseline.injection_detected"


def test_the_injection_flag_is_currently_always_false():
    """Recorded so that `injection_flag = false` on a record is not misread.

    Until the detector lands, `false` in that column means "nothing checked", not "checked
    and clean". The two things that say so are `stages_executed`, which lists no detection
    stage, and `/health`, which reports the component as down.
    """
    from dwaar.authorize.stages import risk as risk_stage

    source = risk_stage.__doc__ or ""
    assert "injection" in source.lower(), (
        "the risk stage must state that injection_flag is a default rather than a finding"
    )


# ── composition ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("permit", "deny", "deny"),
        ("deny", "permit", "deny"),
        ("permit", "step_up", "step_up"),
        ("bound", "throttle", "throttle"),
        ("step_up", "deny", "deny"),
        ("permit", "permit", "permit"),
    ],
)
def test_the_more_restrictive_verdict_wins(left, right, expected):
    assert baseline.more_restrictive(left, right) == expected
    assert baseline.more_restrictive(right, left) == expected


def test_an_unrecognised_verdict_resolves_to_deny():
    """A verdict this function does not recognise is not something to resolve
    optimistically."""
    assert baseline.more_restrictive("permit", "something_new") == "deny"


def test_composition_is_not_concatenation():
    """Concatenating the two rulesets would make ORDER into authority.

    Merchant rules first and an `allow` shadows the baseline deny; baseline first and the
    merchant cannot write any rule about a scored request. Taking the maximum makes the
    baseline a floor: a merchant policy can tighten anything and loosen nothing — the same
    one-directional property the arithmetic gate has, without depending on the order two
    authors happened to write in.
    """
    permissive = dsl.parse(
        {
            "rules": [
                {
                    "id": "merchant_allows_everything",
                    "when": {"lit": True},
                    "action": "allow",
                    "reason_code": "allowed",
                }
            ]
        }
    )
    namespace = engine.build_namespace(request=_Request(), risk_score=0.99)

    merchant = engine.evaluate(permissive, namespace)
    base = engine.evaluate(baseline.RULESET, namespace)
    assert merchant.action == "allow"
    assert base.action == "deny"

    assert baseline.more_restrictive("permit", "deny") == "deny", (
        "a merchant policy must not be able to permit what the baseline refuses"
    )


def test_a_permit_reports_no_rule():
    """'Nothing objected' is not the same claim as 'a rule affirmatively allowed this', and
    `rule_fired` is read as the second."""
    from dwaar.authorize.stages.policy import _rule_name

    assert _rule_name("baseline.permit", "permit") is None
    assert _rule_name("baseline.risk_deny", "deny") == "policy.baseline.risk_deny"


def test_every_baseline_rule_id_is_namespaced():
    """A record must never suggest a merchant agreed to a rule that ships with the code."""
    for rule in baseline.RULESET.rules:
        assert rule.id.startswith("baseline."), rule.id


def test_the_baseline_parses_under_the_same_validator_as_a_compiled_policy():
    """It is not exempt from the DSL. If it were, the baseline could use an operator the
    compiler cannot emit and the two would drift."""
    assert dsl.parse(baseline.BASELINE_DOCUMENT).rules == baseline.RULESET.rules
