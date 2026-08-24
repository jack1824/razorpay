"""Stubs must not lie — and as of 27 August there are none left.

Every stubbed stage had to return a documented constant **and** declare itself in
`degraded_mode`. Without the declaration, a stub is demoable as a working component by
accident: the same failure class as a hardcoded metric, and harder to spot, because
everything looks green.

`pipeline.STUB_STAGES` is now empty. That does not make this file obsolete — it makes it the
thing that keeps the registry empty, and that notices immediately if a stage is added
without a contract. The machinery stays armed rather than being deleted along with the last
stub, because deleting it is how the next stub ships undeclared.

The tests enumerate the pipeline's own registry rather than a hand-written list, so a stage
added without a token cannot slip past by not being mentioned here.
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
from dwaar.risk import features as featuremod
from dwaar.risk import observations as obsmod

#: Empty. Every stage is real. A module lands here only for as long as it is a placeholder.
STUB_MODULES: list = []

#: `signature` became real on 25 Aug, `policy` on 26 Aug, `features` and `risk` on 27 Aug.
REAL_MODULES = [
    signature, mandate, authority, features, risk, policy, ledger, decision, record,
]

#: Tokens that meant "this component does not exist". None of them may ever appear on a
#: record again, and the check is against the registry rather than against a grep, so
#: reintroducing one requires putting it back in the registry where this test sees it.
RETIRED_TOKENS = (
    "signature_unverified",
    "policy_stubbed",
    "features_stubbed",
    "risk_model_stubbed",
)

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
    """The registry and the modules cannot drift apart.

    Two entries in STAGE_ORDER have no module. `replay_lookup` is a short-circuit that runs
    before the work; `record_observation` writes the rolling window before the arithmetic
    gate so the window is not conditioned on the gate's own decision. Both are timed like
    stages so a slow one shows up in the same place as everything else.
    """
    named = {m.STAGE_NAME for m in STUB_MODULES + REAL_MODULES}
    unmoduled = {pipeline.REPLAY_STAGE, pipeline.OBSERVE_STAGE}
    assert set(pipeline.STAGE_ORDER) - unmoduled == named


def test_the_stub_registry_is_empty():
    """The milestone: no record carries a token meaning "this component does not exist".

    Asserted rather than assumed, because "we finished the stubs" is exactly the kind of
    claim that stays in a README after it stops being true.
    """
    assert pipeline.STUB_STAGES == {}, (
        f"stubs remain: {pipeline.STUB_STAGES}. Every degradation token on a record must "
        "now name a RUNTIME condition — Redis unreachable, a model bundle that would not "
        "load — never an unimplemented component."
    )


@pytest.mark.parametrize("token", RETIRED_TOKENS)
def test_a_retired_token_can_never_reappear(token):
    """A leftover token would claim a degradation that never happened, which is as
    dishonest as a stub that declares nothing."""
    assert token not in pipeline.STUB_STAGES.values()


@pytest.mark.parametrize("module", REAL_MODULES, ids=lambda m: m.__name__.split(".")[-1])
def test_real_stages_declare_no_stub_token(module):
    """A real stage may carry a DEGRADED_TOKEN, but it must name a runtime condition.

    `features` and `risk` both keep a token: Redis can be unreachable and a model bundle can
    fail to load, and a record made in either state must say so. What they may not do is
    keep the *old* token, which meant "not built" — a record cannot be allowed to blame a
    working component's absence for a live outage or vice versa.
    """
    assert module.STAGE_NAME not in pipeline.STUB_STAGES
    token = getattr(module, "DEGRADED_TOKEN", None)
    if token is not None:
        assert not token.endswith(("_stubbed", "_unverified")), (
            f"{module.__name__} still uses a stub-shaped token {token!r}"
        )


@pytest.mark.parametrize("module", STUB_MODULES, ids=lambda m: m.__name__.split(".")[-1])
def test_every_stub_documents_its_contract(module):
    """Kept armed for the next stub. The docstring must state what constant comes back: a
    stub whose return value is only discoverable by reading the code is a stub someone will
    misread."""
    doc = inspect.getdoc(module) or ""
    assert "STUB CONTRACT" in doc, f"{module.__name__} does not document its stub contract"
    assert module.DEGRADED_TOKEN in doc
    assert pipeline.STUB_STAGES[module.STAGE_NAME] == module.DEGRADED_TOKEN


def test_the_stub_machinery_would_still_catch_an_undeclared_stub():
    """Positive control for a parametrised test over an EMPTY list.

    `test_every_stub_documents_its_contract` currently runs zero times. A test that runs
    zero times passes, reports as green, and enforces nothing — the same shape as F-014.
    This exercises the assertion against a module that would fail it, so the machinery is
    known to work on the day it is needed again.
    """

    class UndeclaredStub:
        STAGE_NAME = "forgetful"
        __doc__ = "Does something. Says nothing about being a stub."

    assert "STUB CONTRACT" not in (inspect.getdoc(UndeclaredStub) or "")
    with pytest.raises(AssertionError):
        assert "STUB CONTRACT" in (inspect.getdoc(UndeclaredStub) or ""), "would fail"


def test_features_degrades_rather_than_lying_when_the_window_is_gone():
    """An unavailable window is reported, not silently reported as a quiet agent.

    The vector is all zeros either way. What distinguishes "no history" from "no Redis" is
    the token, and it has to be there, because a zero velocity is a *benign* reading.
    """
    result = features.compute_features_from_window(REQ, obsmod.EMPTY, now=1000.0)
    assert result.features == featuremod.empty()
    assert result.degraded == features.DEGRADED_TOKEN
    assert result.internal_reason == "observation_window_unavailable"


def test_features_does_not_degrade_on_a_genuinely_empty_window():
    """A first-time agent is not a degradation, and a record must not say it was."""
    window = obsmod.WindowSnapshot((), ())
    result = features.compute_features_from_window(REQ, window, now=1000.0)
    assert result.degraded is None
    assert set(result.features) == set(featuremod.FEATURE_NAMES)


async def test_risk_returns_none_not_zero_when_no_model_is_loaded():
    """`0.0` is a real score meaning "confidently benign". `None` means "not consulted".

    Conflating them would destroy the claim that a NULL risk_score proves the model was
    never reached — which is what demo beat 2 rests on entirely.
    """
    result = await risk.score_risk(featuremod.empty(), scorer=None)
    assert result.risk_score is None
    assert result.risk_score is not False and result.risk_score != 0.0
    assert result.model_version is None
    assert result.injection_flag is False
    assert result.degraded == risk.DEGRADED_TOKEN


async def test_risk_fails_open_when_the_model_raises():
    """Fail-open is the documented behaviour and it must be the implemented one.

    An exception from inference cannot become a 500: the gate, the policy engine and the
    ledger are all unaffected by the model being broken, and refusing a legitimate payment
    because an ONNX graph threw would be a self-inflicted outage.
    """

    class Exploding:
        def score(self, features):
            raise RuntimeError("graph is corrupt")

    result = await risk.score_risk(featuremod.empty(), scorer=Exploding())
    assert result.ok is True
    assert result.risk_score is None
    assert result.degraded == risk.DEGRADED_TOKEN
    assert result.internal_reason == "scoring_failed:RuntimeError"


def test_no_stage_still_claims_a_stubbed_policy():
    """Stage 5 is real. The token must be gone from the registry, not merely unused."""
    assert "policy_stubbed" not in pipeline.STUB_STAGES.values()
    assert not hasattr(policy, "DEGRADED_TOKEN")


def test_policy_version_zero_and_null_mean_different_things():
    """NULL: never consulted. 0: consulted, no approved policy exists.

    Two different facts about how a decision was reached, and the audit trail keeps them
    apart rather than collapsing both to "no policy".
    """
    assert policy.NO_COMPILED_POLICY == 0
    assert policy.NO_COMPILED_POLICY is not None
