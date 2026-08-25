"""The MCP proxy: authority evaluated before a tool call reaches the vendor.

── The shape ───────────────────────────────────────────────────────────────────────────

An agent asks to call a tool. The proxy resolves the mandate its principal signed, maps the
tool to a required scope, checks the scope, checks the amount against the same arithmetic
gate `/v1/authorize` uses, reserves against the same ledger, writes the same kind of chained
decision record — and only then forwards.

Nothing here is a second authorization system. Every decision goes through
`dwaar.authorize.pipeline`, which is why an MCP denial and an HTTP denial are the same row in
the same chain with the same verifier over them. A proxy with its own rules would be a second
place to get authority wrong.

── Why the enforcement is HERE and not in the agent ────────────────────────────────────

An agent that enforces its own spending limits is the thing under constraint applying the
constraint. That is not a security boundary; it is a convention, and it survives exactly
until the agent is confused, compromised, or simply updated.

The cost is stated plainly in `DEFENSE.md` entry 9 and repeated here because it is the first
thing a reader should notice: **an agent holding the raw merchant token bypasses this proxy
entirely.** There is no cryptography here that prevents that. The proxy is only an
enforcement point for an agent that was given a mandate instead of a token — which is why
this belongs in the platform, where the token can be scoped at issue, rather than as a
third-party product that asks to be routed through.

── Scope and amount are different questions ────────────────────────────────────────────

    scope    MAY this agent take this KIND of action at all?
    amount   is THIS instance within what the principal allowed?

A mandate for 50,000 rupees of collections does not authorise a 40,000 rupee refund. The
amount is fine; the direction is not. Checking only the amount is the mistake that makes a
spending limit look like a delegation model, and it is the one this file exists to avoid.

Scope is checked FIRST, and a scope failure short-circuits before any behavioural work — the
same arrangement as the arithmetic gate, for the same reason. A refund the principal never
delegated is refused on the mandate's own terms, and the record carries `risk_score = NULL`
proving no model was consulted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dwaar.mcp import scopes as scopemod
from dwaar.money import Paise

#: Returned to the agent. Coarse, like every other outbound reason code (threat 10): naming
#: the exact missing scope would let an agent enumerate its own mandate by probing tools.
REASON_SCOPE = "scope_not_delegated"
REASON_UNKNOWN_TOOL = "tool_not_permitted"

#: The argument names Razorpay's tools use for an amount, in paise. Checked in order.
AMOUNT_KEYS = ("amount", "amount_paise", "total_amount")


@dataclass(frozen=True)
class ScopeVerdict:
    """The pure part: everything decidable from the mandate and the tool alone.

    Separated from the pipeline call so it can be tested exhaustively without a database,
    for the same reason `render_decision` is pure.
    """

    permitted: bool
    reason_code: str | None
    rule_fired: str | None
    internal_reason: str | None = None
    amount_paise: Paise | None = None
    rule: scopemod.ToolRule | None = None


def check_scope(
    tool: str, arguments: dict[str, Any], mandate: dict[str, Any] | None
) -> ScopeVerdict:
    """Scope and shape, before any I/O. Pure.

    Order matters and is the same order the arithmetic gate uses: the cheapest, most
    certain refusals first, so that a request the mandate forbids never reaches anything
    that costs money or produces a score.
    """
    if mandate is None:
        return ScopeVerdict(
            False, REASON_SCOPE, "mcp.mandate_unresolvable",
            internal_reason="no mandate resolved for this agent",
        )

    rule = scopemod.rule_for(tool)
    if rule is None:
        # UNLISTED IS DENIED. Not "unknown, allow with a warning" — a proxy whose default is
        # permissive stops enforcing the day the vendor ships a tool nobody mapped.
        return ScopeVerdict(
            False, REASON_UNKNOWN_TOOL, "mcp.tool_unmapped",
            internal_reason=(
                f"{tool!r} is not in the scope map. Unlisted tools deny by default; this is "
                "not a statement that the tool is unsafe, it is a statement that nobody has "
                "decided."
            ),
        )

    granted = mandate.get("scopes")
    if granted is None:
        # A mandate signed before scopes existed (migration 0015) delegates none of them.
        # NULL and [] behave identically here and differ only in the record.
        return ScopeVerdict(
            False, REASON_SCOPE, f"mcp.scope.{rule.scope}",
            internal_reason=(
                f"mandate carries no scopes; {tool!r} requires {rule.scope!r}"
            ),
            rule=rule,
        )

    if rule.scope not in set(granted):
        return ScopeVerdict(
            False, REASON_SCOPE, f"mcp.scope.{rule.scope}",
            internal_reason=(
                f"{tool!r} requires {rule.scope!r}; mandate delegates {sorted(granted)}"
            ),
            rule=rule,
        )

    amount = _amount_from(arguments)
    if rule.requires_amount_check and amount is None:
        # A tool the map says needs an amount, called without one, is a malformed call —
        # and permitting it would be permitting an unbounded one.
        return ScopeVerdict(
            False, REASON_UNKNOWN_TOOL, "mcp.amount_missing",
            internal_reason=f"{tool!r} requires an amount and the call carries none",
            rule=rule,
        )

    return ScopeVerdict(True, None, None, amount_paise=amount, rule=rule)


def _amount_from(arguments: dict[str, Any]) -> Paise | None:
    """Pull the amount out of a tool call, in paise.

    Deliberately strict. A float is refused rather than coerced: money is integer paise
    everywhere in this codebase, and the one place that quietly accepts a float is the place
    that eventually rounds one.
    """
    for key in AMOUNT_KEYS:
        if key not in arguments:
            continue
        value = arguments[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"{key}={value!r} is not an integer number of paise. Money is integer paise "
                "everywhere in this system; a float here is a rounding error waiting for a "
                "reconciliation."
            )
        return value
    return None


#: Directions that are known NOT to move money outward. Whitelisted rather than
#: blacklisted: the first version tested `if moves_money_outward: payout` and fell through
#: to `purchase` for anything else, so a direction nobody anticipated got the LEAST
#: restrictive reading while the comment above it claimed the most. A test caught it.
#:
#: The general shape is worth stating: a default reached by falling off the end of a chain
#: of positive checks is a default nobody chose. Enumerate the safe cases and let everything
#: else land on the strict one.
INBOUND_DIRECTIONS: frozenset[str] = frozenset({"inbound", "none"})


def action_for(rule: scopemod.ToolRule) -> str:
    """Map a tool onto the pipeline's action vocabulary.

    The pipeline's `action` is a closed set, so this is a translation and not a passthrough.
    Anything whose direction is not explicitly inbound becomes `payout` — the most
    restrictive reading — because guessing optimistically about the direction money moves is
    the wrong way to be wrong.
    """
    if rule.tool == "create_refund":
        return "refund"
    if rule.tool == "create_payment_link":
        return "payment_link"
    if rule.money_direction in INBOUND_DIRECTIONS:
        return "purchase"
    return "payout"
