"""Stubs must not lie.

Every stubbed stage returns a documented constant **and** declares itself in
`degraded_mode`. Without the declaration, a stub is demoable as a working component by
accident — the same failure class as a hardcoded metric, and harder to spot, because
everything looks green.

These tests enumerate the pipeline's own stage registry rather than a hand-written list,
so a stage added without a token cannot slip past by not being mentioned here.
"""

from __future__ import annotations

import inspect

import pytest

from dwaar.authorize import pipeline
from dwaar.authorize.stages import (
    authority,
    decision,
    features,
    ledger,
    mandate,
    policy,
    record,
    risk,
    signature,
)
from dwaar.authorize.types import AuthorizeRequest
from dwaar.config import Settings

STUB_MODULES = [signature, features, risk, policy]
REAL_MODULES = [mandate, authority, ledger, decision, record]

REQ = AuthorizeRequest(
    agent_id="agt_000000000001",
    mandate_id="mnd_000000000001",
    action="purchase",
    amount_paise=124_000,
    idempotency_key="k" * 16,
    category="groceries",
)


def test_every_stage_has_a_name():
    for module in STUB_MODULES + REAL_MODULES:
        assert hasattr(module, "STAGE_NAME"), f"{module.__name__} has no STAGE_NAME"


def test_stage_order_covers_every_stage_module():
    """The registry and the modules cannot drift apart."""
    named = {m.STAGE_NAME for m in STUB_MODULES + REAL_MODULES}
    assert set(pipeline.STAGE_ORDER) == named


@pytest.mark.parametrize("module", STUB_MODULES, ids=lambda m: m.__name__.split(".")[-1])
def test_every_stub_declares_a_degradation_token(module):
    assert hasattr(module, "DEGRADED_TOKEN"), (
        f"{module.__name__} is a stub with no DEGRADED_TOKEN. A stub that does not "
        "declare itself can be demoed as a working component by accident."
    )
    assert module.DEGRADED_TOKEN.endswith(("_stubbed", "_unverified"))
    assert pipeline.STUB_STAGES[module.STAGE_NAME] == module.DEGRADED_TOKEN


@pytest.mark.parametrize("module", REAL_MODULES, ids=lambda m: m.__name__.split(".")[-1])
def test_real_stages_declare_no_degradation_token(module):
    """A real stage carrying a stub token would be worse than a stub carrying none:
    every record would claim a degradation that never happened."""
    assert not hasattr(module, "DEGRADED_TOKEN")
    assert module.STAGE_NAME not in pipeline.STUB_STAGES


@pytest.mark.parametrize("module", STUB_MODULES, ids=lambda m: m.__name__.split(".")[-1])
def test_every_stub_documents_its_contract(module):
    """The docstring must state what constant comes back. A stub whose return value is
    only discoverable by reading the code is a stub someone will misread."""
    doc = inspect.getdoc(module) or ""
    assert "STUB CONTRACT" in doc, f"{module.__name__} does not document its stub contract"
    assert module.DEGRADED_TOKEN in doc


async def test_signature_stub_returns_its_documented_constant():
    result = await signature.verify_signature(REQ, {}, settings=Settings(DWAAR_ENV="local"))
    assert result.ok is True
    assert result.agent_id == REQ.agent_id
    assert result.degraded == signature.DEGRADED_TOKEN


async def test_signature_stub_refuses_to_run_outside_local():
    """The most important line in the stub layer.

    A stubbed authentication check that silently passes is not a degraded control, it is
    no control — and nothing about a green test suite would reveal it. This makes the
    failure a loud startup error instead of a silently unauthenticated gateway.
    """
    for env in ("staging", "production", "demo"):
        with pytest.raises(RuntimeError, match="refuses to run"):
            await signature.verify_signature(REQ, {}, settings=Settings(DWAAR_ENV=env))


async def test_features_stub_returns_empty_and_says_so():
    result = await features.compute_features(REQ, {})
    assert result.features == {}
    assert result.degraded == features.DEGRADED_TOKEN


async def test_risk_stub_returns_none_not_zero():
    """`0.0` is a real score meaning "confidently benign". `None` means "not consulted".

    Conflating them would destroy the claim that a NULL risk_score proves the model was
    never reached — which is what demo beat 2 rests on entirely.
    """
    result = await risk.score_risk(REQ, {})
    assert result.risk_score is None
    assert result.risk_score is not False and result.risk_score != 0.0
    assert result.model_version is None
    assert result.injection_flag is False
    assert result.degraded == risk.DEGRADED_TOKEN


async def test_policy_stub_permits_and_reports_no_compiled_policy():
    result = await policy.evaluate_policy(REQ, {}, None)
    assert result.verdict == "permit"
    assert result.policy_version == policy.NO_COMPILED_POLICY == 0
    assert result.rule_fired is None
    assert result.degraded == policy.DEGRADED_TOKEN


def test_policy_version_zero_and_null_mean_different_things():
    """NULL: never consulted. 0: consulted, no approved policy exists.

    Two different facts about how a decision was reached, and the audit trail keeps them
    apart rather than collapsing both to "no policy".
    """
    assert policy.NO_COMPILED_POLICY == 0
    assert policy.NO_COMPILED_POLICY is not None
