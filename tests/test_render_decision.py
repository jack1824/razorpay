"""Stage 7, exhaustively. No database, no clock, no async.

`render_decision` is pure, which is the point: it is the system's actual answer to the
question the product exists to ask, and it can be driven over the whole cross-product of
stage outcomes in milliseconds. Anything that needs a database to test is something we
would test less.
"""

from __future__ import annotations

import itertools

import pytest

from dwaar.authorize.stages.decision import (
    REASON_ALLOWED,
    REASON_DENIED,
    REASON_NOT_AUTHORIZED,
    REASON_STEP_UP,
    REASON_THROTTLED,
    REASON_UNAVAILABLE,
    render_decision,
)
from dwaar.authorize.types import (
    AuthorityResult,
    AuthorizeRequest,
    LedgerResult,
    MandateResult,
    PolicyResult,
    RiskResult,
    SignatureResult,
)

REQ = AuthorizeRequest(
    agent_id="agt_000000000001",
    mandate_id="mnd_000000000001",
    action="purchase",
    amount_paise=124_000,
    idempotency_key="k" * 16,
    category="groceries",
)

SIG_OK = SignatureResult(ok=True, agent_id=REQ.agent_id)
MANDATE_OK = MandateResult(ok=True, merchant_id="mch_1", principal_id="prn_1")
GATE_OK = AuthorityResult(ok=True, permitted=True)
RISK_QUIET = RiskResult(ok=True, risk_score=None, injection_flag=False)
POLICY_PERMIT = PolicyResult(ok=True, verdict="permit", policy_version=0)
LEDGER_OK = LedgerResult(ok=True, reserved=True, budget_before=5_000_000, budget_after=4_876_000)


def render(**overrides):
    kwargs = {
        "signature": SIG_OK,
        "mandate": MANDATE_OK,
        "authority": GATE_OK,
        "risk": RISK_QUIET,
        "policy": POLICY_PERMIT,
        "ledger": LEDGER_OK,
    }
    kwargs.update(overrides)
    return render_decision(REQ, **kwargs)


# ── the happy path ──────────────────────────────────────────────────────────────────

def test_everything_permits_allows():
    d = render()
    assert d.decision == "allow"
    assert d.reason_code == REASON_ALLOWED
    assert d.rule_fired is None


# ── authority beats everything ──────────────────────────────────────────────────────

def test_invalid_mandate_denies_regardless_of_every_other_signal():
    """No downstream stage can grant what the principal did not."""
    d = render(
        mandate=MandateResult(ok=False, merchant_id="mch_1", internal_reason="mandate_revoked"),
        risk=RiskResult(ok=True, risk_score=0.0),
        policy=PolicyResult(ok=True, verdict="permit", policy_version=3),
        ledger=LEDGER_OK,
    )
    assert d.decision == "deny"
    assert d.reason_code == REASON_NOT_AUTHORIZED
    assert d.internal_reason == "mandate_revoked"


def test_authority_gate_denial_beats_a_permitting_policy_and_a_zero_risk_score():
    d = render(
        authority=AuthorityResult(
            ok=True, permitted=False, rule_fired="mandate.max_per_txn",
            internal_reason="amount 1200000 exceeds max_per_txn 500000",
        ),
        risk=RiskResult(ok=True, risk_score=0.0),
        policy=PolicyResult(ok=True, verdict="permit", policy_version=3),
    )
    assert d.decision == "deny"
    assert d.rule_fired == "mandate.max_per_txn"
    assert d.reason_code == REASON_DENIED


@pytest.mark.parametrize(
    "rule",
    ["mandate.expired", "mandate.category_denied", "mandate.category_not_allowed",
     "mandate.max_per_txn"],
)
def test_every_gate_rule_produces_a_mandate_prefixed_deny(rule):
    """The `mandate.` prefix is what distinguishes the principal's own grant refusing
    from a merchant policy layered on top. A judge can read that off the record."""
    d = render(authority=AuthorityResult(ok=True, permitted=False, rule_fired=rule))
    assert d.decision == "deny"
    assert d.rule_fired.startswith("mandate.")


# ── deterministic beats probabilistic ───────────────────────────────────────────────

def test_policy_deny_beats_a_confidently_benign_risk_score():
    """FAIL_MATRIX: conflicting signals → policy wins, always."""
    d = render(
        risk=RiskResult(ok=True, risk_score=0.01, model_version="lgbm-1"),
        policy=PolicyResult(ok=True, verdict="deny", rule_fired="policy.gift_cards",
                            policy_version=3),
    )
    assert d.decision == "deny"
    assert d.rule_fired == "policy.gift_cards"


def test_a_high_risk_score_alone_cannot_deny():
    """The model can only tighten through policy, never decide on its own.

    A score with no policy verdict and no injection flag leaves the decision to authority
    and the ledger — which is the structural reason a hallucinating model is a degraded
    experience rather than a security incident.
    """
    d = render(risk=RiskResult(ok=True, risk_score=0.99, model_version="lgbm-1"))
    assert d.decision == "allow"


def test_injection_flag_denies():
    d = render(risk=RiskResult(ok=True, risk_score=0.4, model_version="lgbm-1",
                               injection_flag=True))
    assert d.decision == "deny"
    assert d.rule_fired == "injection.detected"


@pytest.mark.parametrize(
    ("verdict", "expected", "reason"),
    [
        ("step_up", "step_up", REASON_STEP_UP),
        ("throttle", "throttle", REASON_THROTTLED),
    ],
)
def test_policy_escalations(verdict, expected, reason):
    d = render(policy=PolicyResult(ok=True, verdict=verdict, policy_version=3))
    assert d.decision == expected
    assert d.reason_code == reason


def test_bound_carries_the_bounded_amount():
    d = render(
        policy=PolicyResult(ok=True, verdict="bound", policy_version=3,
                            bounded_amount_paise=200_000)
    )
    assert d.decision == "bound"
    assert d.bounded_amount_paise == 200_000


# ── the ledger, and the distinction that matters ────────────────────────────────────

def test_budget_exhausted_denies_with_the_cumulative_rule():
    """Distinct from the per-transaction gate: this one needed the ledger to know."""
    d = render(
        ledger=LedgerResult(ok=True, reserved=False, rule_fired="mandate.max_total",
                            internal_reason="insufficient", budget_before=100,
                            budget_after=100)
    )
    assert d.decision == "deny"
    assert d.reason_code == REASON_DENIED
    assert d.rule_fired == "mandate.max_total"


def test_ledger_unavailable_is_distinct_from_budget_exceeded():
    """"You cannot afford this" and "we cannot tell whether you can" are different answers.

    Both deny — fail-closed on authority — but an operator reading the audit trail must be
    able to tell an exhausted mandate from an outage.
    """
    exhausted = render(ledger=LedgerResult(ok=True, reserved=False,
                                           rule_fired="mandate.max_total"))
    outage = render(ledger=LedgerResult(ok=False, internal_reason="connection refused"))

    assert exhausted.decision == outage.decision == "deny"
    assert exhausted.reason_code == REASON_DENIED
    assert outage.reason_code == REASON_UNAVAILABLE
    assert outage.rule_fired == "ledger.unavailable"


def test_a_short_circuited_ledger_is_never_treated_as_an_allow():
    """`ledger=None` means stage 6 never ran. It must not read as success."""
    d = render(authority=GATE_OK, ledger=None)
    assert d.decision == "deny"
    assert d.reason_code == REASON_UNAVAILABLE


# ── the outbound vocabulary is small on purpose ─────────────────────────────────────

def test_outbound_reason_codes_are_coarse():
    """Threat 10: a fine-grained code lets an agent binary-search the mandate.

    Every path through the function must emit one of a handful of codes, while the
    internal reason stays precise.
    """
    coarse = {REASON_ALLOWED, REASON_DENIED, REASON_NOT_AUTHORIZED, REASON_UNAVAILABLE,
              REASON_STEP_UP, REASON_THROTTLED}

    mandates = [MANDATE_OK, MandateResult(ok=False, merchant_id="m", internal_reason="revoked")]
    gates = [GATE_OK, AuthorityResult(ok=True, permitted=False, rule_fired="mandate.expired")]
    risks = [RISK_QUIET, RiskResult(ok=True, risk_score=0.9, model_version="m",
                                    injection_flag=True), None]
    policies = [POLICY_PERMIT, PolicyResult(ok=True, verdict="deny", policy_version=1),
                PolicyResult(ok=True, verdict="step_up", policy_version=1), None]
    ledgers = [LEDGER_OK, LedgerResult(ok=True, reserved=False,
                                       rule_fired="mandate.max_total"),
               LedgerResult(ok=False, internal_reason="down"), None]

    seen = set()
    for mandate, gate, risk, pol, ledger in itertools.product(
        mandates, gates, risks, policies, ledgers
    ):
        d = render_decision(REQ, SIG_OK, mandate, gate, risk, pol, ledger)
        assert d.reason_code in coarse, f"leaked a fine-grained code: {d.reason_code}"
        seen.add(d.decision)

    # Every combination resolves to a valid decision; none raise, none return None.
    assert seen <= {"allow", "deny", "step_up", "throttle", "bound"}


def test_internal_reason_is_never_the_outbound_code():
    """The fine detail must stay inside. If these ever became one field, threat 10's
    mitigation would silently stop existing."""
    d = render(
        authority=AuthorityResult(
            ok=True, permitted=False, rule_fired="mandate.max_per_txn",
            internal_reason="amount 1200000 exceeds max_per_txn 500000",
        )
    )
    assert "1200000" in d.internal_reason
    assert "1200000" not in d.reason_code
    assert d.reason_code == REASON_DENIED


def test_render_decision_is_pure():
    """Same inputs, same answer — asserted, because the whole test file assumes it."""
    first = render()
    second = render()
    assert first == second
