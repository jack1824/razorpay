"""Risk scoring. ONNX inference, and nothing that could train anything.

── Two components, because one of them cannot possibly work ────────────────────────────

A supervised classifier trained on four archetypes has no reason whatsoever to recognise a
fifth. Handed `compromised` or `sleeper` — the two held out until evaluation day — it will
force them into whichever of its four known classes they sit nearest, and the held-out
numbers will be poor for a **structural** reason rather than a real one. Reporting that as a
finding about the system would be reporting a finding about our choice of estimator.

So there are two:

    supervised   LightGBM, BINARY: legitimate vs not. Not six-class.
    anomaly      Isolation forest, fit on LEGITIMATE TRAFFIC ONLY.

Binary rather than six-class on purpose. A six-class model learns *"which of my generators
produced this"*, which is precisely the circularity the whole evaluation design is trying to
avoid — it would score beautifully on our own data and mean nothing.

The anomaly half never sees an adversary during training. It scores distance from normal
rather than similarity to known-bad, which is the only mechanism either component has for
an archetype nobody has seen. If the held-out archetypes are caught, this is probably what
caught them; if they are not, that is a genuine result and it goes in the eval as one.

The two are reported separately, always, so the eval can say which one did the work —
including the outcome where the supervised half contributes nothing.

── Combination ─────────────────────────────────────────────────────────────────────────

`risk_score = max(supervised, anomaly)`. Deliberately the blunt one.

A weighted blend would dilute the anomaly signal exactly when it matters most: an unseen
archetype produces a high anomaly score and a low supervised score, and averaging them
produces a middling number that lands in no band. `max` means "flagged if either component
flags", every score is attributable to a named component, and there is no weight that was
tuned on data we generated.

The cost is false positives: two independent chances to be wrong instead of one. That cost
is the reason the ~3% legitimate-overlap requirement in the traffic generator is not
optional — without it the false-positive rate would be measured against traffic that never
looks suspicious, and the rupee figure would be fiction.

── What this module may not import ─────────────────────────────────────────────────────

`onnxruntime` and `numpy`. Not LightGBM, not scikit-learn, not a converter. Training lives
in `tools/train_risk.py` and everything it needs stays there.

That is enforced, not merely intended: `tests/test_hot_path_purity.py` walks the request
path's transitive imports and fails if a training library is reachable, the same walk that
enforces the no-LLM rule. The reason is first-inference cost and import surface — a request
path that can import a training framework is a request path where someone will eventually
fit something during a request.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from dwaar.logging import get_logger
from dwaar.risk.bands import band_for
from dwaar.risk.features import FEATURE_NAMES, FEATURE_SCALE, to_vector

log = get_logger("dwaar.risk.model")

DEFAULT_MODEL_DIR = Path("models/risk")

BUNDLE_FILE = "bundle.json"
SUPERVISED_FILE = "supervised.onnx"
ANOMALY_FILE = "anomaly.onnx"

#: How many features a score names. Three is what fits on a console row and in an
#: explanation sentence; more is a list nobody reads.
TOP_FEATURES = 3


class ModelUnavailable(Exception):
    """No usable bundle. The caller fails OPEN — see `dwaar/authorize/stages/risk.py`."""


@dataclass(frozen=True)
class RiskScore:
    risk_score: float
    supervised_score: float
    anomaly_score: float
    band: str
    model_version: str
    top_features: list[dict[str, Any]] = field(default_factory=list)


class Scorer:
    """Two pre-warmed ONNX sessions and a calibration table.

    Constructed once at startup and shared. Construction reads from disk and builds two
    inference graphs; doing that lazily on the first request would put ~50ms of session
    setup on some unlucky caller's 25ms budget, and it would be the *first* request of the
    demo.
    """

    def __init__(self, directory: Path | str = DEFAULT_MODEL_DIR) -> None:
        self.directory = Path(directory)
        bundle_path = self.directory / BUNDLE_FILE
        if not bundle_path.exists():
            raise ModelUnavailable(
                f"no model bundle at {bundle_path}. Train one with "
                "`python -m tools.train_risk` — the service runs without it, fail-open, "
                "with the degradation recorded."
            )

        self.bundle: dict[str, Any] = json.loads(bundle_path.read_text(encoding="utf-8"))
        self.model_version: str = self.bundle["model_version"]

        # The feature order is part of the artifact. An ONNX graph takes a positional
        # tensor, so a bundle trained against a different ordering would silently feed
        # `burst_index` into the slot the model learned as `failure_ratio` and produce
        # confident nonsense. Refused rather than warned about.
        recorded = tuple(self.bundle["feature_names"])
        if recorded != FEATURE_NAMES:
            raise ModelUnavailable(
                "model bundle was trained on a different feature vector.\n"
                f"  bundle: {recorded}\n"
                f"  code:   {FEATURE_NAMES}\n"
                "Retrain, or check out the commit the bundle was built from. Scoring with "
                "a mismatched ordering produces confident nonsense, not an error."
            )

        import onnxruntime as ort  # noqa: PLC0415 — deferred so an import cannot cost 40ms

        options = ort.SessionOptions()
        # One thread. Every other request is a thread too, and letting a 13-feature model
        # fan out across cores makes p99 worse under load, not better.
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        options.log_severity_level = 3

        self._supervised = ort.InferenceSession(
            str(self.directory / SUPERVISED_FILE),
            sess_options=options,
            providers=["CPUExecutionProvider"],
        )
        self._anomaly = ort.InferenceSession(
            str(self.directory / ANOMALY_FILE),
            sess_options=options,
            providers=["CPUExecutionProvider"],
        )
        self._supervised_input = self._supervised.get_inputs()[0].name
        self._anomaly_input = self._anomaly.get_inputs()[0].name

        # Isotonic calibration, exported at training time as breakpoints so that applying it
        # needs `numpy.interp` rather than scikit-learn. A calibrated probability is what
        # makes the 0.55 and 0.80 bands mean something; an uncalibrated GBM margin does not.
        calibration = self.bundle.get("calibration") or {}
        self._cal_x = np.asarray(calibration.get("x", [0.0, 1.0]), dtype=np.float64)
        self._cal_y = np.asarray(calibration.get("y", [0.0, 1.0]), dtype=np.float64)

        # Empirical quantiles of the anomaly score over LEGITIMATE training traffic. A raw
        # isolation-forest score is an arbitrary scale; its percentile among known-normal
        # traffic is a number a person can reason about.
        self._anomaly_quantiles = np.asarray(
            self.bundle.get("anomaly_quantiles", [0.0]), dtype=np.float64
        )
        # Carried in the bundle so inference and training cannot disagree about where the
        # tail starts — a mismatch would silently shift every anomaly score.
        self._anomaly_tail = float(self.bundle.get("anomaly_tail", 0.05))
        self._importance = self.bundle.get("feature_importance", {})
        self._train_mean = np.asarray(
            self.bundle.get("feature_mean", [0.0] * len(FEATURE_NAMES)), dtype=np.float64
        )
        self._train_std = np.asarray(
            self.bundle.get("feature_std", [1.0] * len(FEATURE_NAMES)), dtype=np.float64
        )
        self._train_std[self._train_std == 0] = 1.0

        self.warm()

    def warm(self) -> None:
        """Run both graphs once so no request pays first-inference cost.

        ONNX Runtime allocates arenas and specialises kernels on the first call. Measured at
        two to three milliseconds here against a two-millisecond stage budget — a p99 breach
        caused entirely by the first request being first.
        """
        started = time.perf_counter()
        zeros = np.zeros((1, len(FEATURE_NAMES)), dtype=np.float32)
        self._supervised.run(None, {self._supervised_input: zeros})
        self._anomaly.run(None, {self._anomaly_input: zeros})
        log.info(
            "risk_model_warm",
            model_version=self.model_version,
            warm_ms=round((time.perf_counter() - started) * 1000, 3),
        )

    def score(self, features: dict[str, int]) -> RiskScore:
        vector = np.asarray([to_vector(features)], dtype=np.float32)

        supervised_raw = self._supervised.run(None, {self._supervised_input: vector})
        probability = float(_positive_class(supervised_raw))
        supervised = float(np.interp(probability, self._cal_x, self._cal_y))

        anomaly_raw = self._anomaly.run(None, {self._anomaly_input: vector})
        anomaly = self._anomaly_to_unit(float(_anomaly_value(anomaly_raw)))

        combined = max(supervised, anomaly)
        return RiskScore(
            # Four places, matching `decision_records.risk_score NUMERIC(5,4)`. Rounding
            # here rather than at the database means the number that was compared against a
            # band is the number that was stored.
            risk_score=round(combined, 4),
            supervised_score=round(supervised, 4),
            anomaly_score=round(anomaly, 4),
            band=band_for(round(combined, 4)),
            model_version=self.model_version,
            top_features=self._top_features(features),
        )

    def _anomaly_to_unit(self, raw: float) -> float:
        """How far into the LOWER TAIL of known-normal this point falls.

        The isolation forest's `decision_function` is higher for more-normal points on a
        scale with no external meaning, so it has to be mapped into [0, 1] before a band can
        be drawn on it.

        The obvious mapping — inverted percentile rank among legitimate training scores —
        is structurally wrong for a band, and it was the first thing tried. A percentile
        rank is UNIFORM on the population it was fitted to, so `1 - rank` puts exactly 20%
        of legitimate traffic above 0.80 and 45% above 0.55 no matter how good the forest
        is. The measured false-positive rate came back at 25% and 54%: not a bad model, an
        arithmetically inevitable one.

        So the rank is compressed into the tail instead. Only the bottom `anomaly_tail`
        fraction of the legitimate distribution scores anything at all, and it ramps to 1.0
        at the most anomalous point ever seen in training. The expected false-positive rate
        at the deny band becomes `tail x 0.2` rather than `0.2`.

        This is a real trade and it is worth naming: an adversary that sits just inside the
        legitimate distribution now scores zero from this component. That is the correct
        posture for the half of the model whose job is unseen archetypes — it should be
        silent unless something is genuinely out of family, and the supervised half covers
        what it has already been shown.
        """
        if self._anomaly_quantiles.size <= 1 or self._anomaly_tail <= 0:
            return 0.0
        rank = float(np.searchsorted(self._anomaly_quantiles, raw)) / self._anomaly_quantiles.size
        return round(max(0.0, min(1.0, (self._anomaly_tail - rank) / self._anomaly_tail)), 6)

    def _top_features(self, features: dict[str, int]) -> list[dict[str, Any]]:
        """The features that most plausibly drove this score.

        **This is an approximation and is labelled as one.** Real attribution is SHAP, and
        SHAP needs LightGBM at inference time — a training framework on the request path,
        which this module refuses on principle. What is computed instead is
        `global gain importance x |z-score against the training mean|`: how much the model
        relies on a feature in general, times how unusual this request's value of it is.

        That is enough to answer "why did this fire" on a console row and in an explanation.
        It is not enough to answer "what would change the outcome", and no part of the
        system claims otherwise.
        """
        values = np.asarray(to_vector(features), dtype=np.float64)
        deviation = np.abs((values - self._train_mean) / self._train_std)
        scored = [
            (name, float(self._importance.get(name, 0.0)) * float(deviation[index]))
            for index, name in enumerate(FEATURE_NAMES)
        ]
        scored.sort(key=lambda pair: (-pair[1], pair[0]))
        return [
            {
                "name": name,
                "contribution": round(contribution, 6),
                "value": round(features.get(name, 0) / FEATURE_SCALE, 6),
                "method": "importance_x_zscore",
            }
            for name, contribution in scored[:TOP_FEATURES]
            if contribution > 0
        ]


def _positive_class(outputs: list[Any]) -> float:
    """Pull P(not legitimate) out of whatever shape the converter emitted.

    ONNX classifier outputs differ by converter and by `zipmap`: a label tensor plus either
    a probability tensor or a list of dicts. Handled here, once, rather than being an
    assumption three layers deep about a file produced by a tool we do not control.
    """
    for output in outputs:
        if isinstance(output, list) and output and isinstance(output[0], dict):
            return float(output[0].get(1, output[0].get("1", 0.0)))
        array = np.asarray(output)
        if array.ndim == 2 and array.shape[1] >= 2:
            return float(array[0, 1])
    raise ModelUnavailable(
        f"supervised model produced no probability output; got shapes "
        f"{[np.asarray(o).shape for o in outputs if not isinstance(o, list)]}"
    )


def _anomaly_value(outputs: list[Any]) -> float:
    """The isolation forest's score, which is the LAST output, not the label."""
    for output in reversed(outputs):
        array = np.asarray(output)
        if array.dtype.kind == "f":
            return float(array.reshape(-1)[0])
    raise ModelUnavailable("anomaly model produced no float score output")


def load(directory: Path | str = DEFAULT_MODEL_DIR) -> Scorer | None:
    """Load a scorer, or return None having said why.

    Returns rather than raises because a missing model is a **degraded** state, not a broken
    one. The gate, the policy engine and the ledger all still hold; the fail matrix calls
    this fail-open and the service must start.
    """
    try:
        return Scorer(directory)
    except ModelUnavailable as exc:
        # The message goes to stderr, not into the structured line. `ModelUnavailable`
        # carries a path and a remedy, which is exactly the kind of free-form string the
        # log allowlist exists to keep out — the allowlist is a control, and widening it
        # for convenience is how the field nobody thought of ends up in a log.
        log.warning("risk_model_unavailable", error_type=type(exc).__name__)
        print(f"risk model not loaded: {exc}", file=sys.stderr)
        return None
    except Exception as exc:  # noqa: BLE001
        log.warning("risk_model_load_failed", error_type=type(exc).__name__)
        print(f"risk model failed to load: {exc}", file=sys.stderr)
        return None
