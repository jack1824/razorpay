"""The policy compiler: the three gates between an LLM's output and a money decision.

No network. The provider is stubbed, because what is being tested is the *pipeline around*
the model — parse, execute the generated tests, refuse to auto-promote — not the model's
prose. Those three gates are the entire argument for using an LLM here, so they are what
must be verified.
"""

from __future__ import annotations

import json

import pytest

from dwaar.policy import compiler
from dwaar.policy.dsl import PolicyError


def payload(rules, tests=None, ambiguities=None):
    return {
        "rules": [{**rule, "when": json.dumps(rule["when"])} for rule in rules],
        "tests": [
            {**case, "namespace": json.dumps(case["namespace"])} for case in (tests or [])
        ],
        "ambiguities": ambiguities or [],
    }


GOOD_RULE = {
    "id": "no_gift_cards",
    "description": "Gift cards are never allowed.",
    "when": {"in": [{"var": "request.category"}, {"lit": ["gift_cards"]}]},
    "action": "deny",
    "reason_code": "denied",
}


# ── gate 1: it must parse ───────────────────────────────────────────────────────────

def test_a_ruleset_that_parses_becomes_a_ruleset():
    ruleset = compiler.build_ruleset(payload([GOOD_RULE]))
    assert [rule.id for rule in ruleset.rules] == ["no_gift_cards"]


def test_a_rule_referencing_an_invented_variable_is_rejected():
    """The model cannot widen the namespace by writing a plausible-looking name."""
    hostile = {**GOOD_RULE, "when": {"==": [{"var": "request.is_fraud"}, {"lit": True}]}}
    with pytest.raises(PolicyError, match="unknown variable"):
        compiler.build_ruleset(payload([hostile]))


def test_a_rule_using_an_invented_operator_is_rejected():
    hostile = {**GOOD_RULE, "when": {"regex_match": [{"var": "request.sku"}, {"lit": ".*"}]}}
    with pytest.raises(PolicyError, match="unknown operator"):
        compiler.build_ruleset(payload([hostile]))


def test_malformed_embedded_json_is_a_compile_error():
    broken = dict(payload([GOOD_RULE]))
    broken["rules"][0]["when"] = "{not json"
    with pytest.raises(PolicyError, match="not valid JSON"):
        compiler.build_ruleset(broken)


# ── gate 2: its own tests must pass ─────────────────────────────────────────────────

def test_generated_tests_run_against_the_real_evaluator():
    ruleset = compiler.build_ruleset(payload([GOOD_RULE]))
    cases = [
        {"name": "gift card denied", "namespace": {"request.category": "gift_cards"},
         "expect_action": "deny", "expect_rule_id": "no_gift_cards"},
        {"name": "groceries allowed", "namespace": {"request.category": "groceries"},
         "expect_action": "allow"},
    ]
    parsed = [{**c, "namespace": json.dumps(c["namespace"])} for c in cases]
    assert compiler.run_generated_tests(ruleset, parsed) == []


def test_a_ruleset_that_fails_its_own_prediction_is_reported():
    """The case that matters: a ruleset which reads correctly and does not behave as its
    author expected is exactly the one a human reviewer approves by mistake."""
    ruleset = compiler.build_ruleset(payload([GOOD_RULE]))
    wrong = [{
        "name": "groceries wrongly expected to deny",
        "namespace": json.dumps({"request.category": "groceries"}),
        "expect_action": "deny",
    }]
    failures = compiler.run_generated_tests(ruleset, wrong)
    assert len(failures) == 1
    assert "expected action 'deny'" in failures[0]


def test_a_test_referencing_an_unknown_variable_is_a_failure_not_a_pass():
    """Otherwise a typo in a test would make it vacuously pass, and the gate would be
    checking nothing."""
    ruleset = compiler.build_ruleset(payload([GOOD_RULE]))
    bad = [{
        "name": "typo", "namespace": json.dumps({"request.catgeory": "gift_cards"}),
        "expect_action": "deny",
    }]
    failures = compiler.run_generated_tests(ruleset, bad)
    assert failures and "unknown variables" in failures[0]


def test_the_right_action_from_the_wrong_rule_is_a_failure():
    """Two rules can both deny. Which one fired is what a dispute turns on."""
    ruleset = compiler.build_ruleset(payload([
        {**GOOD_RULE, "id": "catch_all", "when": {"lit": True}},
        GOOD_RULE,
    ]))
    cases = [{
        "name": "expects the specific rule",
        "namespace": json.dumps({"request.category": "gift_cards"}),
        "expect_action": "deny", "expect_rule_id": "no_gift_cards",
    }]
    failures = compiler.run_generated_tests(ruleset, cases)
    assert failures and "expected rule" in failures[0]


# ── gate 3: the human ───────────────────────────────────────────────────────────────

async def test_compile_retries_on_semantic_failure_then_gives_up(monkeypatch):
    """The loop exists for rulesets that PARSE and then fail their own tests — schema
    conformance already comes from the API."""
    attempts = []

    async def always_wrong(prompt, *, schema, **kwargs):
        attempts.append(prompt)
        return payload(
            [GOOD_RULE],
            tests=[{"name": "impossible", "namespace": {"request.category": "groceries"},
                    "expect_action": "deny"}],
        ), "gemini-stub"

    monkeypatch.setattr("dwaar.llm.client.complete_json", always_wrong)
    result = await compiler.compile_policy("deny gift cards", max_attempts=3)

    assert result.attempts == 3
    assert not result.tests_passed
    assert len(attempts) == 3
    assert "FAILED ITS OWN TESTS" in attempts[-1], (
        "the retry must tell the model what went wrong, or it is just resampling"
    )


async def test_compile_succeeds_when_the_tests_pass(monkeypatch):
    async def good(prompt, *, schema, **kwargs):
        return payload(
            [GOOD_RULE],
            tests=[{"name": "denied", "namespace": {"request.category": "gift_cards"},
                    "expect_action": "deny"}],
        ), "gemini-stub"

    monkeypatch.setattr("dwaar.llm.client.complete_json", good)
    result = await compiler.compile_policy("deny gift cards")

    assert result.tests_passed
    assert result.attempts == 1
    assert result.model == "gemini-stub"


async def test_ambiguities_are_carried_through_never_resolved_silently(monkeypatch):
    """A compiler that quietly picked the permissive reading would be inventing authority
    nobody granted, and the merchant would find out from the payment that got through."""
    question = {
        "question": "Does 'large' mean over Rs 5,000 or over Rs 50,000?",
        "restrictive_reading": "over Rs 5,000",
        "permissive_reading": "over Rs 50,000",
    }

    async def ambiguous(prompt, *, schema, **kwargs):
        return payload(
            [GOOD_RULE],
            tests=[{"name": "denied", "namespace": {"request.category": "gift_cards"},
                    "expect_action": "deny"}],
            ambiguities=[question],
        ), "gemini-stub"

    monkeypatch.setattr("dwaar.llm.client.complete_json", ambiguous)
    result = await compiler.compile_policy("block large gift card purchases")

    assert result.ambiguities == [question]
    rendered = compiler._render_diff(result, None)
    assert "QUESTIONS FOR THE MERCHANT" in rendered
    assert "restrictive reading was applied" in rendered


def test_the_prompt_states_the_closed_namespace_and_operators():
    """The model cannot comply with a constraint it was not given."""
    from dwaar.policy.dsl import NAMESPACE, OPERATORS

    prompt = compiler.PROMPT.format(
        operators=", ".join(sorted(OPERATORS)),
        namespace="\n".join(sorted(NAMESPACE)),
        actions="allow, deny",
        policy="x",
    )
    assert "request.amount_paise" in prompt
    assert "intersects" in prompt
    assert "PAISE" in prompt, "the prompt must be explicit that money is integer paise"
    assert "Do not guess" in prompt


def test_the_compiler_is_not_reachable_from_the_request_path():
    """It imports an LLM client. If a request could reach it, rule 1 would be broken by
    the very component that exists to keep the model off the hot path."""
    from tests._support.importgraph import build_graph, find_path_to

    graph = build_graph("dwaar")
    for entry in ("dwaar.api.routes.authorize", "dwaar.authorize.pipeline"):
        assert find_path_to(graph, entry, "dwaar.policy.compiler") is None


def test_the_engine_is_reachable_from_the_request_path():
    """The counterpart. If this were absent the purity test would pass trivially."""
    from tests._support.importgraph import build_graph, find_path_to

    graph = build_graph("dwaar")
    assert find_path_to(graph, "dwaar.authorize.pipeline", "dwaar.policy.engine") is not None
