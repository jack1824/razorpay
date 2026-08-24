"""No feature may encode anything the arithmetic gate already decides.

── Why this is the most important file in `tests/risk/` ────────────────────────────────

If a feature restates the per-transaction cap, the category lists or the expiry, the model
learns to predict the gate rather than to describe behaviour. Its accuracy looks excellent,
because predicting a deterministic function is easy. Its feature importances become
meaningless, because the top feature is a copy of a rule. And the whole claim that this
system separates deterministic enforcement from probabilistic judgment stops being true —
in a way a reader can spot in about ten seconds.

Three layers of assertion, weakest to strongest:

    signature    `compute()` has no mandate parameter and no connection.  Structural.
    closure      nothing `dwaar.risk.features` imports can reach one.     Structural.
    behavioural  vary the mandate across the gate boundary, hold the request stream fixed,
                 and assert the vector does not move.                      Empirical.

The first two are the property. The third is the proof that the wiring still honours it,
because a signature can be changed and a closure can be widened, and the day either happens
the behavioural test is what notices.

The FOURTH layer — no single feature separates the archetypes on its own — cannot run
without generated traffic, so it is computed by `tools/train_risk.py`, recorded in the model
bundle, and asserted here against the shipped bundle. See `test_model_bundle.py`.
"""

from __future__ import annotations

import inspect

import pytest

from dwaar.authorize.stages import features as features_stage
from dwaar.risk import features as featuremod
from dwaar.risk.observations import Observation, WindowSnapshot

NOW = 1_800_000_000.0


# ── layer 1: signatures ─────────────────────────────────────────────────────────────

FORBIDDEN_PARAMETERS = ("mandate", "conn", "connection", "pool", "authority", "gate")


def test_compute_cannot_receive_a_mandate():
    """*Chooses not to read* is a promise. *Cannot receive* is a property.

    The same distinction the append-only table rests on: `dwaar_app` does not decline to
    UPDATE `decision_records`, it holds no UPDATE grant.
    """
    parameters = set(inspect.signature(featuremod.compute).parameters)
    assert not (parameters & set(FORBIDDEN_PARAMETERS)), (
        f"compute() can see {parameters & set(FORBIDDEN_PARAMETERS)}. A feature that can "
        "see an authority limit is a feature that will eventually encode one."
    )


def test_the_feature_stage_cannot_receive_a_mandate_either():
    """The stage is where a mandate would most naturally be threaded through, because every
    other stage has one."""
    parameters = set(
        inspect.signature(features_stage.compute_features_from_window).parameters
    )
    assert not (parameters & set(FORBIDDEN_PARAMETERS)), (
        f"the feature stage can see {parameters & set(FORBIDDEN_PARAMETERS)}"
    )


def test_the_scorer_cannot_receive_a_request():
    """Stage 4 sees the feature vector and nothing else.

    Three consequences, all wanted: it cannot encode an authority decision, it cannot read
    agent-supplied free text so it is not an injection target, and a stored row can be
    replayed against the named model version to reproduce the score exactly.
    """
    from dwaar.authorize.stages import risk as risk_stage

    parameters = set(inspect.signature(risk_stage.score_risk).parameters)
    assert parameters == {"features", "scorer"}, (
        f"score_risk takes {parameters}; it must take the vector and the scorer only"
    )


# ── layer 2: import closure ─────────────────────────────────────────────────────────


def test_the_feature_module_cannot_reach_the_database_or_the_gate():
    """A parameter can be removed and a module-level import used instead.

    This is the same walk that enforces the no-LLM rule, pointed at a different target: if
    `dwaar.risk.features` can reach `dwaar.db` or the authority stage, it can fetch a mandate
    without anyone passing it one.
    """
    from tests._support.importgraph import build_graph, find_path_to

    graph = build_graph("dwaar")
    for forbidden in (
        "dwaar.db",
        "dwaar.authorize.stages.authority",
        "dwaar.authorize.stages.ledger",
        "dwaar.policy",
    ):
        path = find_path_to(graph, "dwaar.risk.features", forbidden)
        assert path is None, (
            f"dwaar.risk.features can reach {forbidden}: "
            + " | ".join(str(edge) for edge in path)
        )


def test_no_training_framework_is_reachable_from_the_feature_module():
    """`dwaar.risk.features` is pure arithmetic. If it grows a numpy dependency the policy
    engine grows one too, because the engine imports it for the rule namespace."""
    from tests._support.importgraph import build_graph, find_path_to

    graph = build_graph("dwaar")
    for forbidden in ("numpy", "lightgbm", "sklearn", "onnxruntime"):
        assert find_path_to(graph, "dwaar.risk.features", forbidden) is None, (
            f"dwaar.risk.features reaches {forbidden}"
        )


# ── layer 3: behaviour, across the gate boundary ────────────────────────────────────


@pytest.mark.db
async def test_the_vector_does_not_move_when_the_mandate_does(
    owner_dsn, app_dsn, make_mandate, signer, settings, nonce_store, sign_headers
):
    """The whole property, end to end, through the real pipeline.

    Two agents send the SAME sequence of amounts and categories. One holds a mandate whose
    per-transaction cap permits every one of them; the other holds a mandate whose cap denies
    half. The gate therefore behaves completely differently for the two — different decisions,
    different `rule_fired`, different stages executed.

    The feature vectors must be identical anyway.

    This is also the test of the pipeline's ordering. The rolling window is written at step
    2.2, BEFORE the gate, precisely so that a gate-denied request still appears in the
    history. Move that write after the gate and the tightly-capped agent's window loses half
    its events, its velocities drop, and this fails — which is the point.
    """
    import uuid

    import psycopg

    from dwaar.authorize import pipeline
    from dwaar.authorize.types import AuthorizeRequest
    from dwaar.crypto.signer import ensure_registered
    from dwaar.db.repositories import decision_records
    from dwaar.risk.observations import InMemoryObservationStore

    # Same amounts for both. Some are over the tight cap and under the loose one.
    script = [
        (300_000, "groceries", "SKU1000"),
        (1_800_000, "apparel", "SKU1003"),      # over the tight cap
        (250_000, "groceries", "SKU1000"),
        (1_900_000, "apparel", "SKU1003"),      # over the tight cap
        (150_000, "groceries", "SKU1004"),
        (400_000, "apparel", "SKU1003"),
    ]

    async def run_one(merchant: str, cap: int) -> list[dict]:
        setup = await psycopg.AsyncConnection.connect(owner_dsn)
        mandate = await make_mandate(
            setup,
            merchant_id=merchant,
            max_total_paise=50_000_000,
            max_per_txn_paise=cap,
        )
        await ensure_registered(setup, signer)
        await setup.commit()
        await setup.close()

        store = InMemoryObservationStore()
        vectors: list[dict] = []
        async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
            for index, (amount, category, sku) in enumerate(script):
                request = AuthorizeRequest(
                    agent_id=mandate["agent_id"],
                    mandate_id=mandate["mandate_id"],
                    action="purchase",
                    amount_paise=amount,
                    idempotency_key=f"leak-{uuid.uuid4().hex[:20]}",
                    category=category,
                    sku=sku,
                    instrument_bin="411111",
                    cart_id="cart-fixed",
                )
                payload = {
                    "agent_id": request.agent_id,
                    "mandate_id": request.mandate_id,
                    "action": request.action,
                    "amount_paise": request.amount_paise,
                    "idempotency_key": request.idempotency_key,
                    "category": request.category,
                    "sku": request.sku,
                    "instrument_bin": request.instrument_bin,
                    "cart_id": request.cart_id,
                }
                headers, body = sign_headers(request.agent_id, payload)
                # A FIXED clock. Two runs at different wall-clock times would produce
                # different inter-arrival gaps and the comparison would be meaningless.
                stamped = _FIXED_TIMES[index]
                outcome = await pipeline.authorize(
                    request,
                    conn=conn,
                    signer=signer,
                    settings=settings,
                    headers=headers,
                    body=body,
                    nonce_store=nonce_store,
                    observation_store=store,
                    now=stamped,
                )
                await conn.commit()
                record = await decision_records.get(conn, outcome.record_id)
                vectors.append(
                    {"decision": outcome.decision.decision, "features": record["features"]}
                )
        return vectors

    from tests.conftest import rand_id

    loose = await run_one(rand_id("mch"), cap=2_000_000)
    tight = await run_one(rand_id("mch"), cap=500_000)

    # The gate must actually have behaved differently, or this proves nothing.
    assert [row["decision"] for row in loose] != [row["decision"] for row in tight], (
        "the two mandates produced identical decisions, so the comparison below is vacuous"
    )

    compared = 0
    for index, (a, b) in enumerate(zip(loose, tight, strict=True)):
        if not a["features"] or not b["features"]:
            # A gate-denied request has no vector at all, which is itself the claim: the
            # model was never consulted. Nothing to compare on that row.
            continue
        compared += 1
        assert a["features"] == b["features"], (
            f"request {index} produced different features under different mandates.\n"
            f"  loose cap: {a['features']}\n"
            f"  tight cap: {b['features']}\n"
            "A feature is reading an authority limit, or the observation window is being "
            "written after the arithmetic gate instead of before it."
        )

    # Without this the loop could skip every row and the test would pass having compared
    # nothing — the vacuous pass this suite exists to make impossible.
    assert compared >= 3, (
        f"only {compared} rows had features on both sides; the comparison is too thin to "
        "mean anything"
    )


#: Fixed timestamps for the run above, so both agents see identical inter-arrival gaps.
def _fixed_times():
    from datetime import UTC, datetime, timedelta

    base = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)
    return [base + timedelta(seconds=offset) for offset in (0, 3, 9, 20, 47, 95)]


_FIXED_TIMES = _fixed_times()


def test_no_feature_name_mentions_an_authority_concept():
    """A blunt check, and it earns its place: a feature called `over_cap` would sail through
    every structural test above, because nothing about the plumbing would be wrong."""
    forbidden = (
        "cap", "limit", "max_", "allowed", "denied", "permitted", "expiry", "expires",
        "mandate", "budget", "remaining",
    )
    offenders = [
        name
        for name in featuremod.FEATURE_NAMES
        if any(token in name for token in forbidden)
    ]
    assert not offenders, (
        f"feature names suggesting an authority decision: {offenders}. A feature must "
        "describe what the agent did, not what it was allowed to do."
    )


def test_the_window_holds_no_authority_state():
    """What is stored is what a feature can be computed from."""
    fields = set(Observation.__dataclass_fields__)
    assert fields == {"ts", "amount_paise", "category", "sku_hash", "bin_hash", "cart_hash"}
    snapshot_fields = set(WindowSnapshot.__dataclass_fields__)
    assert snapshot_fields == {"observations", "outcomes", "available"}
