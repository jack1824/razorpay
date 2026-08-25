"""The scope map, and the default that governs everything not in it.

The map is a configuration file that decides whether money moves. It is validated at load
rather than at call time, because a malformed map should be a boot failure and not a surprise
on the first refund.
"""

from __future__ import annotations

import json

import pytest

from dwaar.mcp import proxy, scopes


@pytest.fixture(autouse=True)
def _clear_cache():
    scopes.load.cache_clear()
    yield
    scopes.load.cache_clear()


def write_map(path, **overrides):
    document = {
        "default_action": "deny",
        "tools": {
            "create_order": {
                "scope": "collect.create", "money_direction": "inbound",
                "requires_amount_check": True, "risk": "low",
            }
        },
    }
    document.update(overrides)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


# ── the shipped map ─────────────────────────────────────────────────────────────────


def test_the_shipped_map_loads_and_defaults_to_deny():
    rules = scopes.load()
    assert rules
    raw = json.loads(scopes.SCOPE_MAP_PATH.read_text(encoding="utf-8"))
    assert raw["default_action"] == "deny"


def test_the_map_is_a_TRACKED_artifact():
    """It lives in `dwaar/mcp/`, not in the gitignored strategy package.

    The proxy decides whether money moves. Its behaviour has to be reviewable from the
    repository alone — a control whose configuration is not in the tree is a control a
    reader has to take on trust.
    """
    from tests._support.importgraph import REPO_ROOT

    assert scopes.SCOPE_MAP_PATH.is_relative_to(REPO_ROOT / "dwaar")
    assert "strategy" not in str(scopes.SCOPE_MAP_PATH)


def test_every_outbound_tool_requires_an_amount_check():
    """An outbound tool exempt from the amount check is an unbounded withdrawal."""
    for rule in scopes.load().values():
        if rule.moves_money_outward:
            assert rule.requires_amount_check, rule.tool


def test_the_money_moving_tools_are_mapped():
    """`create_refund`, `create_payment_link` and the settlement tool are the three that
    move money outward or collect it. An unmapped one denies, which is safe — but silently
    denying the tools the demo depends on is not what we want to discover on stage."""
    rules = scopes.load()
    for tool in ("create_refund", "create_payment_link", "create_order"):
        assert tool in rules, f"{tool} is not mapped"
    assert rules["create_refund"].scope == "money.outbound"
    assert rules["create_refund"].moves_money_outward


# ── validation ──────────────────────────────────────────────────────────────────────


def test_a_permissive_default_is_REFUSED(tmp_path):
    """The single most important assertion in this file.

    A proxy in front of a vendor's tool list whose default is allow stops enforcing the day
    the vendor ships a tool nobody mapped — and vendors ship tools without telling their
    integrators. The failure mode of default-deny is a support ticket.
    """
    path = write_map(tmp_path / "m.json", default_action="allow")
    with pytest.raises(scopes.ScopeMapError, match="must be 'deny'"):
        scopes.load(path)


def test_an_unsatisfiable_scope_is_refused(tmp_path):
    """A rule naming a scope no mandate can carry denies unconditionally while looking
    configured — which is worse than an unlisted tool, because an unlisted tool denies
    honestly."""
    path = write_map(tmp_path / "m.json", tools={
        "create_order": {
            "scope": "collect.invented", "money_direction": "inbound",
            "requires_amount_check": True, "risk": "low",
        }
    })
    with pytest.raises(scopes.ScopeMapError, match="not in KNOWN_SCOPES"):
        scopes.load(path)


def test_an_outbound_tool_without_an_amount_check_is_refused(tmp_path):
    path = write_map(tmp_path / "m.json", tools={
        "create_refund": {
            "scope": "money.outbound", "money_direction": "outbound",
            "requires_amount_check": False, "risk": "HIGH",
        }
    })
    with pytest.raises(scopes.ScopeMapError, match="unbounded withdrawal"):
        scopes.load(path)


# ── the scope check ─────────────────────────────────────────────────────────────────

COLLECT_ONLY = {"scopes": ["read", "collect.create"]}


def test_the_demo_beat_a_refund_is_denied():
    """₹40,000 refund against a mandate delegating [read, collect.create].

    The amount is fine — it is well inside a ₹50,000 mandate. The DIRECTION is not. Checking
    only the amount is what makes a spending limit look like a delegation model.
    """
    verdict = proxy.check_scope("create_refund", {"amount": 4_000_000}, COLLECT_ONLY)
    assert verdict.permitted is False
    assert verdict.reason_code == proxy.REASON_SCOPE
    assert verdict.rule_fired == "mcp.scope.money.outbound"


def test_a_delegated_tool_is_permitted():
    verdict = proxy.check_scope("create_order", {"amount": 150_000}, COLLECT_ONLY)
    assert verdict.permitted is True
    assert verdict.amount_paise == 150_000


def test_an_unlisted_tool_is_denied():
    verdict = proxy.check_scope("create_payout_v2", {"amount": 1}, COLLECT_ONLY)
    assert verdict.permitted is False
    assert verdict.rule_fired == "mcp.tool_unmapped"
    assert "nobody has decided" in (verdict.internal_reason or "")


def test_a_mandate_with_no_scopes_delegates_none():
    """NULL scopes — a mandate signed before migration 0015. It grants nothing, and it fails
    closed rather than being treated as unrestricted."""
    verdict = proxy.check_scope("create_order", {"amount": 1}, {"scopes": None})
    assert verdict.permitted is False
    assert verdict.reason_code == proxy.REASON_SCOPE


def test_an_empty_scope_list_also_delegates_none():
    verdict = proxy.check_scope("create_order", {"amount": 1}, {"scopes": []})
    assert verdict.permitted is False


def test_an_unresolvable_mandate_denies():
    assert proxy.check_scope("fetch_payment", {}, None).permitted is False


def test_a_tool_needing_an_amount_and_given_none_is_denied():
    """Permitting it would be permitting an unbounded one."""
    verdict = proxy.check_scope("create_order", {}, COLLECT_ONLY)
    assert verdict.permitted is False
    assert verdict.rule_fired == "mcp.amount_missing"


def test_a_read_only_tool_needs_no_amount():
    assert proxy.check_scope("fetch_payment", {}, COLLECT_ONLY).permitted is True


def test_a_float_amount_is_REFUSED_not_coerced():
    """Money is integer paise everywhere. The one place that quietly accepts a float is the
    place that eventually rounds one."""
    with pytest.raises(ValueError, match="integer number of paise"):
        proxy.check_scope("create_order", {"amount": 1500.5}, COLLECT_ONLY)


def test_a_boolean_amount_is_refused():
    """`True` is an int in Python. It is not an amount."""
    with pytest.raises(ValueError):
        proxy.check_scope("create_order", {"amount": True}, COLLECT_ONLY)


# ── the outbound reason code stays coarse ───────────────────────────────────────────


def test_the_denial_does_not_name_the_missing_scope_outbound():
    """Threat 10. Naming the exact missing scope lets an agent enumerate its own mandate by
    probing tools one at a time — the fine detail belongs in the record, not the response."""
    verdict = proxy.check_scope("create_refund", {"amount": 1}, COLLECT_ONLY)
    assert verdict.reason_code == "scope_not_delegated"
    assert "money.outbound" not in verdict.reason_code
    # ...and the detail IS kept internally, where an operator can see it.
    assert "money.outbound" in (verdict.internal_reason or "")


# ── the action mapping ──────────────────────────────────────────────────────────────


def test_an_unmapped_direction_becomes_the_most_restrictive_action():
    """Guessing optimistically about the direction money moves is the wrong way to be
    wrong."""
    rule = scopes.ToolRule("weird_tool", "money.outbound", "sideways", True, "HIGH")
    assert proxy.action_for(rule) == "payout"


def test_refunds_and_links_map_to_their_own_actions():
    rules = scopes.load()
    assert proxy.action_for(rules["create_refund"]) == "refund"
    assert proxy.action_for(rules["create_payment_link"]) == "payment_link"
