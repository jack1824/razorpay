"""Deterministic policy evaluation. Pure, no I/O, target under 1ms.

A tree walk over the closed operator set in ``dsl.py``, against a flat namespace built once
per request. There is no ``eval``, no attribute traversal, no callable in the expression
tree — a rule can compare values and nothing else.

── Determinism is the product here ─────────────────────────────────────────────────────

Two identical inputs produce the same verdict forever. That is what makes a decision record
replayable: `features` are stored on the record precisely so an auditor can re-run this
function years later and get the same answer. An evaluator with any hidden state — a clock,
a cache, a random tiebreak — would make that claim false.

── First match wins ────────────────────────────────────────────────────────────────────

Rules are ordered and evaluation stops at the first match, so ordering is part of the
policy and the compiler must preserve it. The alternative — evaluate all, combine by
severity — sounds safer and is worse: it makes `rule_fired` ambiguous, and "which rule
denied me" is the question every dispute starts with.

── Missing values ──────────────────────────────────────────────────────────────────────

A variable the caller did not supply is ``None``, and comparisons against ``None`` are
FALSE rather than an error. A rule that cannot be evaluated does not fire, so an absent
feature can never *cause* an allow — it can only fail to cause a deny. That is fail-closed
in the direction that matters: the model degrading cannot manufacture authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dwaar.policy.dsl import Rule, Ruleset

_MISSING = object()


@dataclass(frozen=True)
class Verdict:
    action: str
    rule_id: str | None
    reason_code: str
    bound_to_paise: int | None = None

    @property
    def matched(self) -> bool:
        return self.rule_id is not None


#: Returned when no rule matches. A ruleset that denies nothing permits everything, and
#: that must be explicit rather than an accident of falling off the end.
NO_MATCH = Verdict(action="allow", rule_id=None, reason_code="allowed")


def build_namespace(
    *,
    request: Any,
    mandate: dict[str, Any] | None = None,
    budget_remaining_paise: int | None = None,
    risk_score: float | None = None,
    injection_flag: bool = False,
    agent_verified: bool | None = None,
    features: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Flatten everything a rule may reference into one dict of dotted keys.

    Built once per request and passed by value. The evaluator never reaches back into an
    object, so a rule cannot trigger a lazy load, a database call, or any other side effect
    from inside what is supposed to be a pure comparison.
    """
    features = features or {}
    mandate = mandate or {}
    return {
        "request.amount_paise": getattr(request, "amount_paise", None),
        "request.category": getattr(request, "category", None),
        "request.action": getattr(request, "action", None),
        "request.sku": getattr(request, "sku", None),
        "mandate.max_total_paise": mandate.get("max_total_paise"),
        "mandate.max_per_txn_paise": mandate.get("max_per_txn_paise"),
        "mandate.allow_categories": list(mandate.get("allow_categories") or ()),
        "mandate.deny_categories": list(mandate.get("deny_categories") or ()),
        "mandate.substitution_tolerance": mandate.get("substitution_tolerance"),
        "budget.remaining_paise": budget_remaining_paise,
        "risk.score": risk_score,
        "risk.injection_flag": injection_flag,
        "agent.verified": agent_verified,
        "features.velocity_1m": features.get("velocity_1m"),
        "features.velocity_1h": features.get("velocity_1h"),
        "features.distinct_skus_1h": features.get("distinct_skus_1h"),
        "features.burst_index": features.get("burst_index"),
    }


def _resolve(node: dict[str, Any], namespace: dict[str, Any]) -> Any:
    """Evaluate one expression node to a value."""
    (op, operand), = node.items()

    if op == "lit":
        return operand
    if op == "var":
        return namespace.get(operand)

    if op == "not":
        return not _truthy(_resolve(operand, namespace))
    if op == "and":
        return all(_truthy(_resolve(child, namespace)) for child in operand)
    if op == "or":
        return any(_truthy(_resolve(child, namespace)) for child in operand)

    if op == "is_null":
        return _resolve(operand, namespace) is None
    if op == "not_null":
        return _resolve(operand, namespace) is not None

    left = _resolve(operand[0], namespace)
    right = _resolve(operand[1], namespace)

    if op == "==":
        return left == right
    if op == "!=":
        return left != right

    if op in ("<", "<=", ">", ">="):
        # A comparison involving a missing value is FALSE, not an error and not a
        # coincidental ordering. Python would happily compare None to a string and raise,
        # or compare bools to ints and surprise you; neither belongs in a money decision.
        if left is None or right is None:
            return False
        if not _comparable(left) or not _comparable(right):
            return False
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        return left >= right

    if op == "in":
        return left in right if isinstance(right, (list, tuple, set, str)) else False
    if op == "not_in":
        return left not in right if isinstance(right, (list, tuple, set, str)) else False
    if op == "intersects":
        if not isinstance(left, (list, tuple, set)) or not isinstance(right, (list, tuple, set)):
            return False
        return bool(set(left) & set(right))

    raise AssertionError(f"operator {op!r} passed validation but has no implementation")


def _comparable(value: Any) -> bool:
    """Only numbers order. `bool` is excluded: `True < 2` is legal Python and meaningless
    in a policy."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _truthy(value: Any) -> bool:
    """Explicit, so a non-empty string or a zero never silently decides a rule."""
    return value is True or (isinstance(value, (list, tuple, set, dict)) and bool(value)) or (
        _comparable(value) and value != 0
    )


def evaluate(ruleset: Ruleset, namespace: dict[str, Any]) -> Verdict:
    """First matching rule wins. Returns ``NO_MATCH`` if none match."""
    for rule in ruleset.rules:
        if _truthy(_resolve(rule.when, namespace)):
            return Verdict(
                action=rule.action,
                rule_id=rule.id,
                reason_code=rule.reason_code,
                bound_to_paise=rule.bound_to_paise,
            )
    return NO_MATCH


def matching_rule(ruleset: Ruleset, namespace: dict[str, Any]) -> Rule | None:
    """The rule that would fire. Used by the compiler's generated tests and by the console."""
    for rule in ruleset.rules:
        if _truthy(_resolve(rule.when, namespace)):
            return rule
    return None
