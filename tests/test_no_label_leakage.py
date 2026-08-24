"""No archetype label may cross the boundary into anything the gateway can see.

── This file did not exist ─────────────────────────────────────────────────────────────

`docs/strategy/10_SIMULATION/SIMULATION.md` states, as defence #3 of three:

    "`tests/test_no_label_leakage.py` asserts that no feature name or field in the request
     payload correlates with archetype by construction."

There was no such file. That is the same shape as F-012 — a control described in the
package's prose and never shipped — and it is recorded here rather than quietly created,
because the package's claims are being treated as design intent to be implemented, not as
statements of fact about the repository.

── Two layers, and the second is the one that catches a subtle generator ───────────────

**Request layer.** Nothing an agent sends may identify its archetype. Not the agent id, not
the display name, not a header, not a field that takes disjoint values per class. This
catches the blatant version.

**Feature layer.** No single feature may separate the archetypes on its own. A generator can
be perfectly clean at the request layer and still write the answer into the input one
aggregation later — if `bin_diversity` were 1.0 for exactly one archetype and 0.1 for every
other, the model would be a lookup table with excellent metrics.

The feature layer needs generated traffic, so it is computed by `tools/train_risk.py`, which
REFUSES to write a bundle that fails, and recorded in `models/risk/bundle.json`. This file
asserts against the shipped bundle, so the check runs on a laptop with no database.
"""

from __future__ import annotations

import json

import pytest

from tests._support.importgraph import REPO_ROOT
from zoo.agents import ARCHETYPES

BUNDLE_PATH = REPO_ROOT / "models" / "risk" / "bundle.json"


# ── request layer ───────────────────────────────────────────────────────────────────


def _sample_requests(agents_per_archetype: int = 8) -> dict[str, list[dict]]:
    """Several agents per archetype, as a real run has.

    One agent per archetype would be the wrong sample: a single card tester picks two SKUs
    and a single breacher picks one, so their value sets are almost always disjoint by
    chance rather than by construction. The question is whether the ARCHETYPE's pool is
    separable, and that needs more than one draw from it.
    """
    from zoo import catalogue as cataloguemod
    from zoo.base import AgentIdentity

    identity = AgentIdentity("agt_000000000001", "prn_000000000001", "mnd_000000000001", 1)
    catalogue = cataloguemod.load()
    sampled: dict[str, list[dict]] = {}
    for archetype, cls in ARCHETYPES.items():
        kwargs = {"max_per_txn_paise": 2_000_000} if archetype == "budget_breacher" else {}
        requests: list[dict] = []
        for index in range(agents_per_archetype):
            agent = cls(
                identity, base_url="http://127.0.0.1:8080", seed=4242 + index,
                catalogue=catalogue, requests=40, **kwargs,
            )
            requests.extend(agent.build_body() for _ in range(40))
        sampled[archetype] = requests
    return sampled


def test_no_archetype_name_appears_in_any_request():
    """The blatant leak, and the one that actually happens.

    An `agent_id` of `agt_card_tester_01`, a `display_name` of "Card Tester", a debug header
    — any of these ends the evaluation before a feature is computed, and each is the kind of
    thing added at 2am to make a log readable.
    """
    for archetype, requests in _sample_requests().items():
        serialised = json.dumps(requests)
        for name in ARCHETYPES:
            assert name not in serialised, (
                f"{archetype}'s requests contain the string {name!r}. The gateway must see "
                "a request, never a label."
            )


def test_no_single_request_field_identifies_the_archetype():
    """Perfect separation, which is V = 1.0 — one field whose value set is disjoint per
    class. Amounts and categories SHOULD differ between archetypes; that is behaviour, and
    it is what the model is for. What must not happen is a field that answers the question
    outright.
    """
    sampled = _sample_requests()
    fields = ("action", "category", "sku", "instrument_bin", "cart_id")

    for field in fields:
        values: dict[str, set] = {
            archetype: {str(request.get(field)) for request in requests}
            for archetype, requests in sampled.items()
        }
        for left in values:
            for right in values:
                if left >= right:
                    continue
                if not values[left] or not values[right]:
                    continue
                # `cart_id` is exempt: it is a random per-agent identifier, so it is
                # disjoint between ANY two agents of any archetype. The gateway hashes it
                # and counts mutations; its identity is never a feature.
                if field == "cart_id":
                    continue
                assert values[left] & values[right], (
                    f"{field!r} takes completely disjoint values for {left} and {right}; "
                    "knowing the field identifies the archetype"
                )


def test_the_idempotency_key_prefix_is_not_a_label():
    """It carries the archetype's first four characters for debuggability. That is fine ONLY
    because the gateway namespaces and stores it as `rsv:<key>` and no feature reads it —
    but it is worth an explicit assertion, because it is the one place an archetype string
    legitimately travels over the wire.
    """
    from dwaar.risk.features import FEATURE_NAMES
    from dwaar.risk.observations import Observation

    assert "idempotency" not in " ".join(FEATURE_NAMES)
    assert not any(
        "idempotency" in name for name in Observation.__dataclass_fields__
    ), "the idempotency key reached the rolling window; its prefix names the archetype"


def test_the_gateway_cannot_see_the_run_manifest():
    """The manifest is where the labels are. Nothing under `dwaar/` may read it."""
    from tests._support import sourcescan

    result = sourcescan.scan(
        [REPO_ROOT / "dwaar"],
        ["data/traffic", "run_manifest", "manifest.jsonl"],
        relative_to=REPO_ROOT,
    )
    assert result.files_scanned >= 10
    assert not result.findings, sourcescan.render(result.findings)


# ── feature layer ───────────────────────────────────────────────────────────────────


def _bundle() -> dict:
    if not BUNDLE_PATH.exists():
        pytest.skip(
            f"no model bundle at {BUNDLE_PATH}. Generate traffic with `python -m zoo.run` "
            "and train with `python -m tools.train_risk`."
        )
    return json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))


def test_the_bundle_records_a_feature_layer_leakage_check():
    """A bundle without this block was built by a trainer that did not check, which is
    indistinguishable from a bundle that passed."""
    leakage = _bundle().get("leakage")
    assert leakage, (
        "models/risk/bundle.json has no `leakage` block. Either the bundle predates the "
        "check or the trainer stopped running it; both mean the feature layer is unchecked."
    )
    assert set(leakage) >= {"threshold", "per_feature", "max_cramers_v", "passes", "rows"}


def test_no_single_feature_separates_the_archetypes():
    """Cramer's V per feature against the archetype label, over the traffic the model was
    trained on.

    The threshold is high on purpose. A feature is SUPPOSED to carry signal — a velocity
    that told you nothing about a card tester would be a useless velocity — and V around
    0.3-0.5 is what a genuinely informative behavioural feature looks like. What must not
    happen is one column identifying the archetype on its own, so the model never has to
    combine evidence and the importances become a description of the generator.
    """
    leakage = _bundle()["leakage"]
    assert leakage["rows"] >= 500, (
        f"the leakage check ran over {leakage['rows']} rows; too few to mean anything"
    )
    assert leakage["passes"], (
        f"`{leakage['max_feature']}` separates archetypes at V={leakage['max_cramers_v']}, "
        f"above the threshold of {leakage['threshold']}.\n"
        "The generator is writing the answer into the input and the model is a lookup "
        "table. Fix the generator or the feature. Do not raise the threshold.\n"
        + json.dumps(leakage["per_feature"], indent=2)
    )


def test_the_leakage_threshold_has_not_been_relaxed():
    """The number that would be tuned first if a run failed.

    Pinned here as well as in the trainer, so raising it requires editing a test whose name
    says what raising it means.
    """
    from tools.train_risk import MAX_CRAMERS_V

    assert MAX_CRAMERS_V == 0.75
    assert _bundle()["leakage"]["threshold"] == MAX_CRAMERS_V, (
        "the shipped bundle was built under a different threshold than the code enforces"
    )
