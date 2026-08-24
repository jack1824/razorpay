"""The compiled rule DSL.

── Why a purpose-built DSL and not CEL-py ──────────────────────────────────────────────

CEL-py was the package's suggestion and it was seriously considered. Three things decided
against it:

1. **Import surface in the hot path.** Rule 1 is enforced by a static import-closure test.
   Pulling a general expression language into `dwaar.policy.engine` means everything *it*
   imports becomes reachable from the request path, and the purity test would have to
   allow-list a subtree we do not control.
2. **We do not need an expression language.** Policies compare a handful of typed fields
   against constants and sets. That is a dozen operators, not a language with macros,
   comprehensions and a type checker.
3. **The LLM writes these.** A compiler generating CEL can generate *any* CEL, and the
   review burden is then "read arbitrary code". A closed operator set means a generated
   rule is either in the DSL or rejected at parse time — the review is about intent, not
   about what the expression might do.

The cost, stated plainly: expressiveness. Anything the operator set does not cover requires
extending this file and shipping it, rather than writing a cleverer rule. For a mandate-
scoped authorisation policy that is the right trade; for a general rules product it would
not be.

── The shape ───────────────────────────────────────────────────────────────────────────

    {
      "rules": [
        {"id": "no_gift_cards",
         "when": {"in": [{"var": "request.category"}, {"lit": ["gift_cards"]}]},
         "action": "deny",
         "reason_code": "denied"}
      ]
    }

Rules are evaluated **in order** and the first match wins, so ordering is part of the
policy. `evaluate` returns the rule that fired, which is what `decision_records.rule_fired`
records.

No `eval`, no `exec`, no attribute access, no callables. A tree walk over a closed set of
operators against a flat, pre-built variable namespace.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Action = Literal["allow", "bound", "throttle", "step_up", "deny"]

VALID_ACTIONS: frozenset[str] = frozenset({"allow", "bound", "throttle", "step_up", "deny"})

# The closed operator set. Adding one is a deliberate act with a test, not a config change.
OPERATORS: frozenset[str] = frozenset(
    {
        "var", "lit",
        "and", "or", "not",
        "==", "!=", "<", "<=", ">", ">=",
        "in", "not_in",
        "intersects",       # any element of A appears in B — for category lists
        "is_null", "not_null",
    }
)

# Variables a rule may reference. Closed on purpose: a typo becomes a compile error rather
# than a silently-null comparison that makes a rule never fire.
NAMESPACE: frozenset[str] = frozenset(
    {
        "request.amount_paise",
        "request.category",
        "request.action",
        "request.sku",
        "mandate.max_total_paise",
        "mandate.max_per_txn_paise",
        "mandate.allow_categories",
        "mandate.deny_categories",
        "mandate.substitution_tolerance",
        "budget.remaining_paise",
        "risk.score",
        "risk.injection_flag",
        "agent.verified",
        "features.velocity_1m",
        "features.velocity_1h",
        "features.distinct_skus_1h",
        "features.burst_index",
    }
)


class PolicyError(Exception):
    """The ruleset is malformed. Raised at COMPILE time, never during a request."""


@dataclass(frozen=True)
class Rule:
    id: str
    when: dict[str, Any]
    action: Action
    reason_code: str
    bound_to_paise: int | None = None
    """Only meaningful for ``action="bound"``: the amount the request is reduced to."""
    description: str = ""


@dataclass(frozen=True)
class Ruleset:
    rules: tuple[Rule, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "rules": [
                {
                    "id": rule.id,
                    "when": rule.when,
                    "action": rule.action,
                    "reason_code": rule.reason_code,
                    **({"bound_to_paise": rule.bound_to_paise} if rule.bound_to_paise else {}),
                    **({"description": rule.description} if rule.description else {}),
                }
                for rule in self.rules
            ]
        }


def _validate_expression(node: Any, path: str = "when") -> None:
    """Reject anything outside the closed operator and variable sets.

    Validation happens at compile time so a malformed rule cannot reach a request. A policy
    that fails to parse is a policy that never goes live, which is the correct failure: the
    alternative is discovering it while deciding about money.
    """
    if not isinstance(node, dict) or len(node) != 1:
        raise PolicyError(f"{path}: expected a single-key operator object, got {node!r}")

    (op, operand), = node.items()
    if op not in OPERATORS:
        raise PolicyError(f"{path}: unknown operator {op!r}; allowed: {sorted(OPERATORS)}")

    if op == "lit":
        return  # any JSON scalar or list

    if op == "var":
        if operand not in NAMESPACE:
            raise PolicyError(
                f"{path}: unknown variable {operand!r}. The namespace is closed so a typo "
                f"is a compile error rather than a rule that silently never fires. "
                f"Allowed: {sorted(NAMESPACE)}"
            )
        return

    if op == "not":
        _validate_expression(operand, f"{path}.not")
        return

    if op in ("and", "or"):
        if not isinstance(operand, list) or len(operand) < 2:
            raise PolicyError(f"{path}.{op}: expected a list of at least two expressions")
        for index, child in enumerate(operand):
            _validate_expression(child, f"{path}.{op}[{index}]")
        return

    if op in ("is_null", "not_null"):
        _validate_expression(operand, f"{path}.{op}")
        return

    # Binary operators.
    if not isinstance(operand, list) or len(operand) != 2:
        raise PolicyError(f"{path}.{op}: expected exactly two operands")
    for index, child in enumerate(operand):
        _validate_expression(child, f"{path}.{op}[{index}]")


def parse(document: dict[str, Any]) -> Ruleset:
    """Validate and build a ruleset. Raises ``PolicyError`` on anything malformed."""
    if not isinstance(document, dict) or "rules" not in document:
        raise PolicyError("ruleset must be an object with a 'rules' array")

    raw_rules = document["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise PolicyError("ruleset must contain at least one rule")

    seen: set[str] = set()
    rules: list[Rule] = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise PolicyError(f"rules[{index}]: expected an object")

        for required in ("id", "when", "action", "reason_code"):
            if required not in raw:
                raise PolicyError(f"rules[{index}]: missing {required!r}")

        rule_id = raw["id"]
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError(f"rules[{index}]: id must be a non-empty string")
        if rule_id in seen:
            raise PolicyError(
                f"rules[{index}]: duplicate id {rule_id!r}. Ids land in "
                "decision_records.rule_fired, so a duplicate makes the audit trail ambiguous."
            )
        seen.add(rule_id)

        action = raw["action"]
        if action not in VALID_ACTIONS:
            raise PolicyError(
                f"rules[{index}]: action {action!r} is not one of {sorted(VALID_ACTIONS)}"
            )

        bound = raw.get("bound_to_paise")
        if action == "bound":
            if not isinstance(bound, int) or isinstance(bound, bool) or bound <= 0:
                raise PolicyError(
                    f"rules[{index}]: action 'bound' requires a positive integer "
                    "bound_to_paise — money is integer paise, never float"
                )
        elif bound is not None:
            raise PolicyError(
                f"rules[{index}]: bound_to_paise is only meaningful for action 'bound'"
            )

        _validate_expression(raw["when"], f"rules[{index}].when")

        rules.append(
            Rule(
                id=rule_id,
                when=raw["when"],
                action=action,
                reason_code=raw["reason_code"],
                bound_to_paise=bound,
                description=raw.get("description", ""),
            )
        )

    return Ruleset(rules=tuple(rules))
