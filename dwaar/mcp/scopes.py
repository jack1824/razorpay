"""Tool → scope mapping, and the default that governs everything not in it.

── What this is and is not ─────────────────────────────────────────────────────────────

Razorpay's Remote MCP Server exposes 35+ tools behind a merchant token —
`base64(key:secret)` — and the documented scoping controls are a `--read-only` flag and a
`--toolsets` filter. Both are real and both work as documented.

**Nothing here is a vulnerability claim.** A token doing what a token does is not a flaw. The
observation is narrower and, if it is worth anything, more useful: a token carries
*possession*, and delegating authority to something that makes its own decisions requires
expressing *intent* — who, for how much, for which actions, until when. Toolset-level and
read-only granularity exist; per-principal delegation with monetary bounds does not. That is
a missing abstraction rather than a defect, and this file is an attempt at the abstraction.

Getting that distinction right matters beyond politeness. "Your product has a security hole"
is a claim we would have to defend and would lose. "Your product is missing a primitive, here
is one" is a claim the code supports.

── Default deny, and why the list is short on purpose ──────────────────────────────────

An unlisted tool is DENIED. Not permitted-with-a-warning, not logged-and-allowed.

A proxy in front of 35+ tools whose default is allow is a proxy that stops enforcing the day
the upstream adds a tool — and the upstream adds tools without telling us, because that is
what a vendor does. The failure mode of default-deny is a support ticket. The failure mode of
default-allow is an agent moving money through a tool nobody mapped.

The mapping deliberately covers the money-moving tools first. A tool being absent is not a
statement that it is safe; it is a statement that nobody has decided.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

SCOPE_MAP_PATH = Path(__file__).with_name("scope_map.json")

#: Every scope a mandate may delegate. Closed, for the same reason the policy DSL's operator
#: set is closed: a typo in a mandate must be a load error rather than a scope that silently
#: matches nothing and denies everything the principal meant to permit.
KNOWN_SCOPES: frozenset[str] = frozenset(
    {"read", "collect.create", "collect.capture", "collect.manage", "money.outbound"}
)

#: Scopes that move money OUT of the merchant's account. Held separately because they are
#: the ones worth naming in a review, and because the amount check is not optional for them.
OUTBOUND_SCOPES: frozenset[str] = frozenset({"money.outbound"})


@dataclass(frozen=True)
class ToolRule:
    tool: str
    scope: str
    money_direction: str
    requires_amount_check: bool
    risk: str

    @property
    def moves_money_outward(self) -> bool:
        return self.money_direction == "outbound"


class ScopeMapError(Exception):
    """The map is malformed. Raised at LOAD time, never during a tool call."""


@lru_cache(maxsize=1)
def load(path: Path | str = SCOPE_MAP_PATH) -> dict[str, ToolRule]:
    """Parse and validate the map. Cached: it is a file that changes with a deploy.

    Validation is strict on purpose. A rule naming a scope outside `KNOWN_SCOPES` would be
    unsatisfiable — no mandate could ever carry it — so the tool would deny unconditionally
    while looking configured. That is worse than an unlisted tool, which at least denies
    honestly.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))

    if raw.get("default_action") != "deny":
        raise ScopeMapError(
            f"default_action is {raw.get('default_action')!r}. It must be 'deny': a proxy "
            "in front of a vendor's tool list stops enforcing the day the vendor adds a "
            "tool, and vendors add tools without telling anyone."
        )

    rules: dict[str, ToolRule] = {}
    for tool, entry in raw["tools"].items():
        scope = entry["scope"]
        if scope not in KNOWN_SCOPES:
            raise ScopeMapError(
                f"tool {tool!r} requires scope {scope!r}, which is not in KNOWN_SCOPES. "
                "No mandate could carry it, so the tool would deny unconditionally while "
                "appearing configured."
            )
        rules[tool] = ToolRule(
            tool=tool,
            scope=scope,
            money_direction=entry["money_direction"],
            requires_amount_check=bool(entry["requires_amount_check"]),
            risk=entry["risk"],
        )

    for tool, entry in rules.items():
        if entry.moves_money_outward and not entry.requires_amount_check:
            raise ScopeMapError(
                f"{tool!r} moves money outward with requires_amount_check=false. An "
                "outbound tool exempt from the amount check is an unbounded withdrawal."
            )
    return rules


def rule_for(tool: str) -> ToolRule | None:
    """`None` means unlisted, which means denied. The caller must not treat it as permitted."""
    return load().get(tool)
