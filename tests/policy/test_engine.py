"""The policy engine: determinism, the closed operator set, and conflict resolution.

Pure, so it is tested exhaustively without a database. That is the point of keeping it pure:
this function decides what a merchant's rules mean, and anything needing infrastructure to
test is something that gets tested less.
"""

from __future__ import annotations

import pytest

from dwaar.policy import dsl, engine
from dwaar.policy.dsl import NAMESPACE, OPERATORS, PolicyError


class Req:
    def __init__(self, amount_paise=100_000, category="groceries", action="purchase", sku=None):
        self.amount_paise = amount_paise
        self.category = category
        self.action = action
        self.sku = sku


def ns(**overrides):
    namespace = engine.build_namespace(
        request=Req(),
        mandate={
            "max_total_paise": 5_000_000,
            "max_per_txn_paise": 500_000,
            "allow_categories": ["groceries", "apparel"],
            "deny_categories": ["gift_cards"],
            "substitution_tolerance": "same_price",
        },
    )
    namespace.update(overrides)
    return namespace


def rules(*specs):
    return dsl.parse({"rules": list(specs)})


# ── parsing is where malformed rules die ────────────────────────────────────────────

def test_an_unknown_operator_is_a_compile_error():
    with pytest.raises(PolicyError, match="unknown operator"):
        rules({"id": "r", "when": {"exec": ["rm -rf /"]}, "action": "deny", "reason_code": "x"})


def test_an_unknown_variable_is_a_compile_error():
    """Closed namespace: a typo becomes a compile error rather than a rule that silently
    never fires — which is the failure mode nobody notices."""
    with pytest.raises(PolicyError, match="unknown variable"):
        rules({
            "id": "r",
            "when": {"==": [{"var": "request.ammount_paise"}, {"lit": 1}]},
            "action": "deny", "reason_code": "x",
        })


def test_duplicate_rule_ids_are_rejected():
    """Ids land in decision_records.rule_fired, so a duplicate makes the audit trail
    ambiguous about which rule denied a request."""
    spec = {"id": "same", "when": {"lit": True}, "action": "deny", "reason_code": "x"}
    with pytest.raises(PolicyError, match="duplicate id"):
        rules(spec, dict(spec))


def test_bound_requires_an_integer_paise_amount():
    with pytest.raises(PolicyError, match="positive integer"):
        rules({
            "id": "r", "when": {"lit": True}, "action": "bound",
            "reason_code": "x", "bound_to_paise": 2000.5,
        })


def test_bound_to_paise_is_rejected_on_other_actions():
    with pytest.raises(PolicyError, match="only meaningful"):
        rules({
            "id": "r", "when": {"lit": True}, "action": "deny",
            "reason_code": "x", "bound_to_paise": 2000,
        })


def test_an_unknown_action_is_rejected():
    with pytest.raises(PolicyError, match="not one of"):
        rules({"id": "r", "when": {"lit": True}, "action": "refund_everything",
               "reason_code": "x"})


def test_the_operator_set_is_closed():
    """Adding one is a deliberate act with a test, not a config change. Asserted so that
    widening it silently is impossible."""
    assert frozenset({
        "var", "lit", "and", "or", "not",
        "==", "!=", "<", "<=", ">", ">=",
        "in", "not_in", "intersects", "is_null", "not_null",
    }) == OPERATORS


def test_there_is_no_eval_anywhere_in_the_engine():
    """A rule can compare values and nothing else. The LLM writes these."""
    from pathlib import Path

    for module in ("dwaar/policy/engine.py", "dwaar/policy/dsl.py"):
        source = Path(module).read_text()
        assert "eval(" not in source
        assert "exec(" not in source
        assert "__import__" not in source


# ── evaluation ──────────────────────────────────────────────────────────────────────

def test_first_match_wins():
    """Ordering is part of the policy, and `rule_fired` must name exactly one rule."""
    ruleset = rules(
        {"id": "first", "when": {"lit": True}, "action": "deny", "reason_code": "a"},
        {"id": "second", "when": {"lit": True}, "action": "allow", "reason_code": "b"},
    )
    assert engine.evaluate(ruleset, ns()).rule_id == "first"


def test_no_match_permits_explicitly():
    """A ruleset that denies nothing permits everything, and that must be explicit rather
    than an accident of falling off the end."""
    ruleset = rules({"id": "never", "when": {"lit": False}, "action": "deny",
                     "reason_code": "x"})
    verdict = engine.evaluate(ruleset, ns())
    assert verdict is engine.NO_MATCH
    assert verdict.action == "allow"
    assert verdict.rule_id is None
    assert verdict.matched is False


def test_category_deny_via_mandate_list():
    ruleset = rules({
        "id": "denied_category",
        "when": {"in": [{"var": "request.category"}, {"var": "mandate.deny_categories"}]},
        "action": "deny", "reason_code": "denied",
    })
    assert engine.evaluate(ruleset, ns(**{"request.category": "gift_cards"})).rule_id
    assert engine.evaluate(ruleset, ns(**{"request.category": "apparel"})).rule_id is None


def test_intersects_for_list_overlap():
    ruleset = rules({
        "id": "overlap",
        "when": {"intersects": [{"var": "mandate.allow_categories"},
                                {"lit": ["apparel", "electronics"]}]},
        "action": "deny", "reason_code": "x",
    })
    assert engine.evaluate(ruleset, ns()).rule_id == "overlap"


def test_conjunction_and_disjunction():
    ruleset = rules({
        "id": "unverified_large",
        "when": {"and": [
            {"==": [{"var": "agent.verified"}, {"lit": False}]},
            {">": [{"var": "request.amount_paise"}, {"lit": 200_000}]},
        ]},
        "action": "bound", "reason_code": "allowed", "bound_to_paise": 200_000,
    })
    hit = ns(**{"agent.verified": False, "request.amount_paise": 300_000})
    miss = ns(**{"agent.verified": True, "request.amount_paise": 300_000})
    assert engine.evaluate(ruleset, hit).bound_to_paise == 200_000
    assert engine.evaluate(ruleset, miss).rule_id is None


# ── missing values fail closed in the direction that matters ────────────────────────

def test_a_comparison_against_a_missing_value_is_false():
    """A rule that cannot be evaluated does not fire, so an absent feature can never CAUSE
    an allow — it can only fail to cause a deny. The model degrading cannot manufacture
    authority."""
    ruleset = rules({
        "id": "velocity",
        "when": {">": [{"var": "features.velocity_1m"}, {"lit": 5}]},
        "action": "deny", "reason_code": "x",
    })
    assert engine.evaluate(ruleset, ns()).rule_id is None            # feature absent
    assert engine.evaluate(ruleset, ns(**{"features.velocity_1m": 9})).rule_id == "velocity"


def test_booleans_do_not_order():
    """`True < 2` is legal Python and meaningless in a policy."""
    ruleset = rules({
        "id": "r", "when": {">": [{"var": "agent.verified"}, {"lit": 0}]},
        "action": "deny", "reason_code": "x",
    })
    assert engine.evaluate(ruleset, ns(**{"agent.verified": True})).rule_id is None


def test_a_non_empty_string_does_not_make_a_rule_fire():
    """Truthiness is explicit, so a stray string value never silently decides a rule."""
    ruleset = rules({"id": "r", "when": {"var": "request.category"}, "action": "deny",
                     "reason_code": "x"})
    assert engine.evaluate(ruleset, ns(**{"request.category": "groceries"})).rule_id is None


def test_in_against_a_non_list_is_false_not_an_error():
    ruleset = rules({
        "id": "r", "when": {"in": [{"lit": "x"}, {"var": "request.amount_paise"}]},
        "action": "deny", "reason_code": "x",
    })
    assert engine.evaluate(ruleset, ns()).rule_id is None


# ── determinism ─────────────────────────────────────────────────────────────────────

def test_evaluation_is_deterministic():
    """A decision record stores `features` so an auditor can re-run this years later and
    get the same answer. Hidden state would make that claim false."""
    ruleset = rules({
        "id": "cap", "when": {">": [{"var": "request.amount_paise"}, {"lit": 50_000}]},
        "action": "deny", "reason_code": "denied",
    })
    namespace = ns()
    first = engine.evaluate(ruleset, namespace)
    for _ in range(50):
        assert engine.evaluate(ruleset, namespace) == first


def test_the_namespace_is_flat_and_complete():
    """The evaluator never reaches back into an object, so a rule cannot trigger a lazy
    load or any other side effect from inside a comparison."""
    namespace = ns()
    assert set(namespace) == set(NAMESPACE)
    assert all(not callable(value) for value in namespace.values())
