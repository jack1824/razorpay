"""The scorer: what it refuses to load, how fast it is, and what a score means.

Most of this file is about REFUSING things. A model that loads a mismatched artifact does
not raise — it produces confident nonsense, because an ONNX graph takes a positional tensor
and does not know that slot 7 used to be `failure_ratio` and is now `bin_diversity`.
"""

from __future__ import annotations

import json
import shutil
import time

import pytest

from dwaar.risk import model as riskmodel
from dwaar.risk.bands import DENY_BAND, STEP_UP_BAND, band_for
from dwaar.risk.features import FEATURE_NAMES, FEATURE_SCALE, empty


def bundle_or_skip() -> riskmodel.Scorer:
    scorer = riskmodel.load()
    if scorer is None:
        pytest.skip(
            "no model bundle in models/risk. Generate traffic with `python -m zoo.run` "
            "and train with `python -m tools.train_risk`."
        )
    return scorer


# ── bands ───────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, "permit"),
        (0.5499, "permit"),
        (STEP_UP_BAND, "step_up"),
        (0.7, "step_up"),
        (DENY_BAND, "step_up"),
        (0.8001, "deny"),
        (1.0, "deny"),
    ],
)
def test_band_boundaries(score, expected):
    """Exactly 0.80 is a step-up, not a deny.

    Stated as a test because "> 0.80 -> deny" leaves the boundary undefined, and an
    undefined boundary in a money decision is a bug waiting for a round number.
    """
    assert band_for(score) == expected


def test_none_is_not_a_low_score():
    """`None` means the model was never consulted. Reading it as a permit the model agreed
    with is exactly the conflation the whole NULL story exists to prevent."""
    assert band_for(None) == "not_scored"


def test_the_bands_are_defined_in_one_place():
    """The console banner, the model's own `band` field and the rule that actually decides
    must read the same constants, or a demo asserts 'deny above 0.80' while the rule says
    something else."""
    from dwaar.policy import baseline

    document = json.dumps(baseline.BASELINE_DOCUMENT)
    assert str(DENY_BAND) in document
    assert str(STEP_UP_BAND) in document


# ── loading ─────────────────────────────────────────────────────────────────────────


def test_a_missing_bundle_degrades_rather_than_raising():
    """A missing model is a degraded state, not a broken one. The gate, the policy engine
    and the ledger all still hold, and the service must start."""
    assert riskmodel.load("models/does-not-exist") is None


def test_a_bundle_trained_on_a_different_feature_vector_is_REFUSED(tmp_path):
    """The failure that produces confident nonsense instead of an error.

    An ONNX graph takes a positional tensor. Reorder `FEATURE_NAMES` and every value is fed
    into the slot the model learned as something else — the model still returns a number,
    still returns it in two milliseconds, and the number is meaningless. There is no runtime
    symptom, which is why this is checked at load and refused rather than warned about.
    """
    source = bundle_or_skip().directory
    target = tmp_path / "risk"
    shutil.copytree(source, target)

    bundle = json.loads((target / "bundle.json").read_text(encoding="utf-8"))
    bundle["feature_names"] = list(reversed(bundle["feature_names"]))
    (target / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(riskmodel.ModelUnavailable, match="different feature vector"):
        riskmodel.Scorer(target)

    # And through `load()`, which is what the application calls: degraded, not crashed.
    assert riskmodel.load(target) is None


def test_a_bundle_missing_a_feature_is_refused(tmp_path):
    source = bundle_or_skip().directory
    target = tmp_path / "risk"
    shutil.copytree(source, target)
    bundle = json.loads((target / "bundle.json").read_text(encoding="utf-8"))
    bundle["feature_names"] = bundle["feature_names"][:-1]
    (target / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(riskmodel.ModelUnavailable):
        riskmodel.Scorer(target)


def test_the_shipped_bundle_matches_the_shipped_feature_list():
    scorer = bundle_or_skip()
    assert tuple(scorer.bundle["feature_names"]) == FEATURE_NAMES
    assert scorer.bundle["feature_scale"] == FEATURE_SCALE


# ── scoring ─────────────────────────────────────────────────────────────────────────


def test_a_score_is_in_range_and_names_its_components():
    scorer = bundle_or_skip()
    scored = scorer.score(empty())
    assert 0.0 <= scored.risk_score <= 1.0
    assert 0.0 <= scored.supervised_score <= 1.0
    assert 0.0 <= scored.anomaly_score <= 1.0
    assert scored.model_version == scorer.model_version
    assert scored.band == band_for(scored.risk_score)


def test_the_combined_score_is_the_max_of_the_two_components():
    """Deliberately the blunt combiner.

    A weighted blend dilutes the anomaly signal exactly when it matters most: an unseen
    archetype produces a high anomaly score and a low supervised one, and averaging them
    lands in no band at all. `max` also means every score is attributable to a named
    component, with no weight that was tuned on data we generated.
    """
    scorer = bundle_or_skip()
    for vector in (empty(), _busy_vector()):
        scored = scorer.score(vector)
        assert scored.risk_score == pytest.approx(
            round(max(scored.supervised_score, scored.anomaly_score), 4)
        )


def test_scoring_is_deterministic_and_therefore_replayable():
    """The reason `decision_records.features` is worth storing: anyone with the bundle can
    replay a stored row and get the same number, rather than having to believe it."""
    scorer = bundle_or_skip()
    vector = _busy_vector()
    assert scorer.score(vector) == scorer.score(vector)


def test_top_features_are_labelled_as_an_approximation():
    """It is `global gain x |z-score|`, not SHAP. Real attribution needs LightGBM at
    inference — a training framework on the request path, which this module refuses on
    principle — so the approximation is named in the output rather than passed off."""
    scorer = bundle_or_skip()
    scored = scorer.score(_busy_vector())
    for entry in scored.top_features:
        assert entry["method"] == "importance_x_zscore"
        assert entry["name"] in FEATURE_NAMES


# ── latency ─────────────────────────────────────────────────────────────────────────


def test_the_session_is_prewarmed_by_the_constructor():
    """ONNX Runtime specialises kernels on first use. Paying that on the first authorize
    would be a p99 breach caused entirely by the first request being first — and it would be
    the first request of the demo."""
    scorer = bundle_or_skip()
    vector = _busy_vector()

    first = time.perf_counter()
    scorer.score(vector)
    first_call = (time.perf_counter() - first) * 1000

    timings = []
    for _ in range(200):
        started = time.perf_counter()
        scorer.score(vector)
        timings.append((time.perf_counter() - started) * 1000)
    median = sorted(timings)[len(timings) // 2]

    assert first_call < median * 20 + 5.0, (
        f"first call {first_call:.3f}ms against a median of {median:.3f}ms; the session "
        "does not look pre-warmed"
    )


def test_inference_p99_is_under_two_milliseconds():
    """The stage budget. Measured, never asserted from a constant."""
    scorer = bundle_or_skip()
    vector = _busy_vector()
    timings = []
    for _ in range(2_000):
        started = time.perf_counter()
        scorer.score(vector)
        timings.append((time.perf_counter() - started) * 1000)
    timings.sort()
    p50 = timings[len(timings) // 2]
    p99 = timings[int(len(timings) * 0.99)]
    assert p99 < 2.0, f"risk inference p99 is {p99:.3f}ms (p50 {p50:.3f}ms), budget 2ms"


def _busy_vector() -> dict[str, int]:
    vector = empty()
    vector.update(
        {
            "velocity_1m": 40 * FEATURE_SCALE,
            "velocity_1h": 900 * FEATURE_SCALE,
            "burst_index": 12 * FEATURE_SCALE,
            "bin_diversity": FEATURE_SCALE,
            "failure_ratio": int(0.7 * FEATURE_SCALE),
            "distinct_skus_1h": 2 * FEATURE_SCALE,
            "cadence_entropy": int(0.1 * FEATURE_SCALE),
        }
    )
    return vector


# ── the anomaly mapping ─────────────────────────────────────────────────────────────


def test_the_anomaly_mapping_is_silent_on_typical_traffic():
    """The defect this replaced: an inverted percentile rank is UNIFORM on the population it
    was fitted to, so `1 - rank` puts exactly 20% of legitimate traffic above the 0.80 deny
    band whatever the forest does. Measured at 25%.

    Structural, not statistical: a point at the median of the legitimate training
    distribution must score zero from this component, and only the narrow tail may score at
    all. Asserted against the mapping rather than against a dataset, so it holds for any
    retrain.
    """
    scorer = bundle_or_skip()
    quantiles = scorer._anomaly_quantiles
    tail = scorer._anomaly_tail

    assert 0 < tail <= 0.2, f"anomaly tail is {tail}; a wide tail reintroduces the defect"

    median = float(quantiles[len(quantiles) // 2])
    assert scorer._anomaly_to_unit(median) == 0.0, (
        "the median legitimate training point scores non-zero for anomaly; the mapping is "
        "putting a fixed fraction of normal traffic into a band"
    )

    # The most anomalous point ever seen in training is the top of the scale.
    assert scorer._anomaly_to_unit(float(quantiles[0]) - 1.0) == 1.0

    # And the expected false-positive rate at the deny band is `tail x the band's tail`,
    # not the band's tail. Checked by walking the training distribution itself.
    flagged = sum(1 for value in quantiles if scorer._anomaly_to_unit(float(value)) > DENY_BAND)
    assert flagged / len(quantiles) <= tail, (
        f"{flagged / len(quantiles):.1%} of legitimate training traffic scores above the "
        f"deny band on anomaly alone, against a tail of {tail:.0%}"
    )


def test_the_bundle_records_the_tail_so_training_and_serving_agree():
    """A mismatch would silently shift every anomaly score, with no error anywhere."""
    from tools.train_risk import ANOMALY_TAIL

    assert bundle_or_skip().bundle["anomaly_tail"] == ANOMALY_TAIL
