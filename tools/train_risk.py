#!/usr/bin/env python3
"""Train the risk model from the audit trail.

    python -m tools.train_risk --manifest data/traffic/train-20260827.jsonl

── Why the training set is the audit trail ─────────────────────────────────────────────

The features come from `decision_records` — the rows the gateway wrote, from windows the
gateway maintained, at the moment each decision was made. The labels come from the zoo's run
manifest, joined on `agent_id`.

Neither side ever holds both. The gateway computes features and has no idea which archetype
it is serving; the zoo knows the archetype and never sees a feature. There is no code path
that could put the answer into the input, because no process has both halves at once.

It also means the training distribution is exactly the serving distribution: the same
`compute()`, the same rolling windows, the same wall clock. A model trained on features
recomputed offline from a trace would be trained on features the gateway never produces.

── Why this lives OUTSIDE `dwaar/` ─────────────────────────────────────────────────────

It reads evaluation labels. `tests/test_ground_truth_isolation.py` scans `dwaar/` for any
reference to an archetype or a label file and fails the build if it finds one. Putting the
trainer in `tools/` makes "the service cannot see labels" a fact about the package boundary
rather than a claim about discipline.

It also keeps LightGBM, scikit-learn and the ONNX converters off the request path, which
`tests/test_hot_path_purity.py` asserts with the same import walk that enforces the no-LLM
rule.

── Why the split is by AGENT, not by row ───────────────────────────────────────────────

Rows from one agent are anything but independent — a rolling-window feature at request 30
shares most of its window with the feature at request 29. Splitting by row would put nearly
identical vectors on both sides of the boundary and report a test score that is really a
memorisation score. Splitting by agent means the test set contains agents the model has
never seen, which is the question actually being asked.

── Two models ──────────────────────────────────────────────────────────────────────────

Supervised LightGBM, binary. Isolation forest fit on legitimate rows only. They are
evaluated separately and reported separately, because on evaluation day the interesting
question is which of them caught the held-out archetypes — and "neither" is a real answer
that a combined number would hide.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import psycopg

from dwaar.risk.bands import DENY_BAND, STEP_UP_BAND
from dwaar.risk.features import FEATURE_NAMES, FEATURE_SCALE

BUNDLE_VERSION = "0.1.0"
DEFAULT_OUT = Path("models/risk")
TRAFFIC_DIR = Path("data/traffic")

#: 200 trees at depth 6, from the architecture document. Small on purpose: the p99 budget
#: for this stage is 2ms, and a forest that cannot be evaluated inside it is not a better
#: model, it is a broken one.
N_ESTIMATORS = 200
MAX_DEPTH = 6
LEARNING_RATE = 0.06

ISO_ESTIMATORS = 150

#: What fraction of the legitimate distribution's lower tail carries any anomaly signal.
#:
#: An inverted percentile rank — the obvious mapping — is UNIFORM on legitimate traffic, so
#: it puts exactly 20% of it above the 0.80 deny band whatever the forest does. Measured at
#: 25%. Compressing the rank into a narrow tail makes the expected false-positive rate
#: `tail x 0.2` instead. See `Scorer._anomaly_to_unit`.
ANOMALY_TAIL = 0.05

#: ONNX opset. Pinned rather than left to the converter's default, because the graph is a
#: committed artifact: a converter upgrade that silently changes the opset would produce a
#: bundle that loads on the machine that built it and fails on the demo laptop.
TARGET_OPSET = {"": 15, "ai.onnx.ml": 3}


@dataclass
class Row:
    agent_id: str
    archetype: str
    is_legitimate: bool
    bursty: bool
    features: dict[str, int]
    decision: str
    model_version: str | None
    """Non-null means a model scored this request — so a model influenced whether the card
    was ever charged, and therefore what `failure_ratio` looks like. See `_model_free`."""


def load_manifests(paths: list[Path]) -> dict[str, dict[str, Any]]:
    """agent_id -> {archetype, is_legitimate, bursty}, from every run manifest given."""
    labels: dict[str, dict[str, Any]] = {}
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                entry = json.loads(line)
                if entry.get("kind") != "run":
                    continue
                for agent in entry["agents"]:
                    labels[agent["agent_id"]] = agent
    return labels


def load_rows(dsn: str, labels: dict[str, dict[str, Any]]) -> list[Row]:
    """Feature vectors from `decision_records`, joined to labels on agent_id.

    Only rows that actually reached the feature stage are returned. A request denied by the
    arithmetic gate has `features = {}` and was never scored, so including it would train
    the model on a population it never sees at inference — and, worse, on precisely the
    population the gate handles, which is how a model learns to predict the gate.
    """
    rows: list[Row] = []
    with psycopg.connect(dsn) as conn:
        for agent_id, meta in labels.items():
            for features, decision, model_version in conn.execute(
                "SELECT features, decision, model_version FROM decision_records "
                "WHERE agent_id = %s AND features <> '{}'::jsonb",
                (agent_id,),
            ).fetchall():
                if not all(name in features for name in FEATURE_NAMES):
                    continue
                rows.append(
                    Row(
                        agent_id=agent_id,
                        archetype=meta["archetype"],
                        is_legitimate=bool(meta["is_legitimate"]),
                        bursty=bool(meta.get("bursty")),
                        features=features,
                        decision=decision,
                        model_version=model_version,
                    )
                )
    return rows


def _model_free(rows: list[Row]) -> tuple[bool, int, set[str]]:
    """Whether this traffic was generated against a gateway with NO risk model loaded.

    Training the first model on traffic a model shaped is circular, and the loop is not
    hypothetical — it was measured. A model trained on one run then denied 99% of the next
    run's card-testing traffic, so almost no card was ever presented, so almost no payment
    outcome was recorded, so `failure_ratio` — the feature that describes card testing —
    came back near zero for card testers. The second model would have been trained on the
    first model's blind spot and would have inherited it.

    Feature VALUES are not affected: they are computed at stage 3, before any verdict. What
    the model affects is which requests reached a card at all, and therefore what the PSP
    ever had an opinion about.

    The check is `model_version IS NULL` on the training rows, which is a fact recorded by
    the gateway rather than a promise made by whoever ran the generator.
    """
    shaped = {row.model_version for row in rows if row.model_version}
    return (not shaped, sum(1 for row in rows if row.model_version), shaped)


def split_by_agent(
    rows: list[Row], *, seed: int
) -> tuple[list[Row], list[Row], list[Row], dict[str, str]]:
    """60 / 20 / 20 train / calibrate / test, stratified by archetype, split on AGENT."""
    by_archetype: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()
    for row in rows:
        if row.agent_id not in seen:
            seen.add(row.agent_id)
            by_archetype[row.archetype].append(row.agent_id)

    rng = np.random.default_rng(seed)
    assignment: dict[str, str] = {}
    for _archetype, agents in sorted(by_archetype.items()):
        shuffled = list(agents)
        rng.shuffle(shuffled)
        n = len(shuffled)
        # At least one agent in each bucket wherever there are enough to go round; an
        # archetype with a single agent lands entirely in train, and the report says so
        # rather than silently reporting a test score over zero rows.
        n_train = max(1, int(round(n * 0.6)))
        n_cal = max(1, int(round(n * 0.2))) if n - n_train >= 2 else 0
        for index, agent_id in enumerate(shuffled):
            if index < n_train:
                assignment[agent_id] = "train"
            elif index < n_train + n_cal:
                assignment[agent_id] = "calibrate"
            else:
                assignment[agent_id] = "test"

    buckets: dict[str, list[Row]] = {"train": [], "calibrate": [], "test": []}
    for row in rows:
        buckets[assignment[row.agent_id]].append(row)
    return buckets["train"], buckets["calibrate"], buckets["test"], assignment


def to_matrix(rows: list[Row]) -> tuple[np.ndarray, np.ndarray]:
    x = np.asarray(
        [[row.features[name] / FEATURE_SCALE for name in FEATURE_NAMES] for row in rows],
        dtype=np.float32,
    )
    y = np.asarray([0 if row.is_legitimate else 1 for row in rows], dtype=np.int32)
    return x, y


def isotonic_breakpoints(scores: np.ndarray, labels: np.ndarray) -> dict[str, list[float]]:
    """Fit isotonic regression and export it as (x, y) breakpoints for `numpy.interp`.

    Exported rather than pickled because inference must not import scikit-learn. A monotone
    step function is fully described by its knots, and `np.interp` over them is exact at the
    knots and linear between — which is what `IsotonicRegression(out_of_bounds="clip")` does
    anyway.
    """
    from sklearn.isotonic import IsotonicRegression

    if len(set(labels.tolist())) < 2 or len(scores) < 10:
        return {"x": [0.0, 1.0], "y": [0.0, 1.0]}

    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(scores, labels)
    grid = np.linspace(0.0, 1.0, 101)
    return {"x": [round(float(v), 6) for v in grid],
            "y": [round(float(v), 6) for v in iso.predict(grid)]}


def reliability_table(probabilities: np.ndarray, labels: np.ndarray, bins: int = 10):
    """Predicted vs observed, per decile. Computed, never asserted.

    This is the reliability diagram the architecture document asks for, as numbers rather
    than a picture: a committed PNG cannot be diffed and cannot be recomputed by a reader.
    """
    table = []
    edges = np.linspace(0.0, 1.0, bins + 1)
    for low, high in zip(edges, edges[1:], strict=False):
        upper = probabilities < high if high < 1.0 else probabilities <= 1.0
        mask = (probabilities >= low) & upper
        count = int(mask.sum())
        table.append(
            {
                "bin": f"{low:.1f}-{high:.1f}",
                "count": count,
                "mean_predicted": round(float(probabilities[mask].mean()), 4) if count else None,
                "observed_rate": round(float(labels[mask].mean()), 4) if count else None,
            }
        )
    return table


#: A single feature whose Cramer's V against the archetype exceeds this is not a feature —
#: it is the label wearing a feature's name, and the model built on it is a lookup table.
#:
#: The threshold is deliberately HIGH. A feature is *supposed* to carry signal: a velocity
#: that told you nothing about a card tester would be a useless velocity, and V around 0.3-0.5
#: is what a genuinely informative behavioural feature looks like. What must not happen is one
#: column identifying the archetype on its own, so that the model never has to combine
#: evidence and the importances become a description of the generator.
#:
#: Chosen once, before seeing any number, and recorded here rather than tuned until the run
#: passes. If a feature exceeds it, the fix is the generator or the feature — never this line.
MAX_CRAMERS_V = 0.75

#: Quantile bins for the contingency table. Ten is enough resolution to see a separation and
#: few enough that a 2,000-row run has ~200 per bin.
CRAMER_BINS = 10


def cramers_v(values: np.ndarray, groups: list[str]) -> float:
    """Association between one continuous feature and the archetype label.

    The feature is binned into quantiles, a contingency table is built against the archetype,
    and V = sqrt(chi2 / (n * min(r-1, c-1))). Quantile bins rather than equal-width, because
    most of these features are heavily skewed and equal-width bins would put 95% of the mass
    in one cell and report near-zero association for a feature that separates perfectly.
    """
    labels = sorted(set(groups))
    if len(labels) < 2 or values.size < 50:
        return 0.0

    edges = np.unique(np.quantile(values, np.linspace(0, 1, CRAMER_BINS + 1)))
    if edges.size < 3:
        # A constant (or near-constant) feature cannot separate anything.
        return 0.0
    binned = np.clip(np.searchsorted(edges, values, side="right") - 1, 0, edges.size - 2)

    table = np.zeros((edges.size - 1, len(labels)), dtype=np.float64)
    index = {label: i for i, label in enumerate(labels)}
    for bin_id, group in zip(binned, groups, strict=True):
        table[bin_id, index[group]] += 1

    n = table.sum()
    if n == 0:
        return 0.0
    expected = np.outer(table.sum(axis=1), table.sum(axis=0)) / n
    mask = expected > 0
    chi2 = float(((table[mask] - expected[mask]) ** 2 / expected[mask]).sum())
    denominator = n * (min(table.shape) - 1)
    return round(float(np.sqrt(chi2 / denominator)) if denominator else 0.0, 4)


def leakage_report(rows: list[Row]) -> dict:
    """Cramer's V for every feature, against the archetype label.

    This is `test_no_label_leakage` at the FEATURE layer. The request layer is checked
    separately, in `tests/test_no_label_leakage.py`; a generator can be clean at the request
    layer and still write the answer into the input one aggregation later.
    """
    groups = [row.archetype for row in rows]
    per_feature = {
        name: cramers_v(
            np.asarray([row.features[name] / FEATURE_SCALE for row in rows]), groups
        )
        for name in FEATURE_NAMES
    }
    worst = max(per_feature.items(), key=lambda kv: kv[1])
    return {
        "threshold": MAX_CRAMERS_V,
        "bins": CRAMER_BINS,
        "rows": len(rows),
        "per_feature": dict(sorted(per_feature.items(), key=lambda kv: -kv[1])),
        "max_feature": worst[0],
        "max_cramers_v": worst[1],
        "passes": worst[1] <= MAX_CRAMERS_V,
    }


def binary_metrics(scores: np.ndarray, labels: np.ndarray, threshold: float) -> dict:
    predicted = scores >= threshold
    tp = int(((predicted == 1) & (labels == 1)).sum())
    fp = int(((predicted == 1) & (labels == 0)).sum())
    fn = int(((predicted == 0) & (labels == 1)).sum())
    tn = int(((predicted == 0) & (labels == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "threshold": threshold,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
    }


def roc_auc(scores: np.ndarray, labels: np.ndarray) -> float | None:
    """Rank-based AUC. `None` when one class is absent, rather than a misleading 0.5."""
    positives, negatives = scores[labels == 1], scores[labels == 0]
    if positives.size == 0 or negatives.size == 0:
        return None
    order = np.argsort(np.concatenate([positives, negatives]), kind="mergesort")
    ranks = np.empty(order.size, dtype=np.float64)
    ranks[order] = np.arange(1, order.size + 1)
    # Average ranks over ties, or a model that outputs one constant scores 1.0.
    combined = np.concatenate([positives, negatives])
    for value in np.unique(combined):
        tied = combined == value
        ranks[tied] = ranks[tied].mean()
    rank_sum = ranks[: positives.size].sum()
    return round(
        float((rank_sum - positives.size * (positives.size + 1) / 2)
              / (positives.size * negatives.size)),
        4,
    )


def train(args: argparse.Namespace) -> int:
    # BOOTSTRAP manifests only. Traffic generated against a gateway with a model loaded is
    # shaped by that model — see F-031 — and the refusal below catches it, but defaulting to
    # the right glob means nobody has to hit the refusal to find out.
    manifests = (
        [Path(args.manifest)] if args.manifest
        else sorted(TRAFFIC_DIR.glob("bootstrap-*.jsonl"))
    )
    if not manifests:
        print(
            f"no bootstrap manifests under {TRAFFIC_DIR}.\n"
            "Training traffic must be generated against a gateway with NO model loaded:\n"
            "  DWAAR_MODEL_DIR=/nonexistent uvicorn dwaar.api.app:app --port 8080\n"
            "  make traffic"
        )
        return 2

    labels = load_manifests(manifests)
    rows = load_rows(args.dsn, labels)
    if len(rows) < 100:
        print(
            f"only {len(rows)} scored rows found for {len(labels)} agents. "
            "Training on this would produce a number, not a model."
        )
        return 2

    clean, shaped_count, versions = _model_free(rows)
    if not clean and not args.allow_model_shaped:
        print()
        print(
            f"REFUSING TO TRAIN: {shaped_count} of {len(rows)} training rows were scored by "
            f"a model ({sorted(versions)}).\n"
            "Training on traffic a model shaped is circular: the model decided which requests\n"
            "reached a card, so it decided what payment outcomes the PSP ever reported, so it\n"
            "decided what `failure_ratio` looks like. The next model inherits the last one's\n"
            "blind spot.\n\n"
            "Regenerate with the model unloaded:\n"
            "  DWAAR_MODEL_DIR=/nonexistent uvicorn dwaar.api.app:app --port 8080\n"
            "  make traffic\n\n"
            "Or pass --allow-model-shaped if you are deliberately retraining on production\n"
            "traffic and have accounted for the selection bias."
        )
        return 4

    train_rows, cal_rows, test_rows, assignment = split_by_agent(rows, seed=args.seed)
    x_train, y_train = to_matrix(train_rows)
    x_cal, y_cal = to_matrix(cal_rows)
    x_test, y_test = to_matrix(test_rows)

    print(f"manifests        {[str(m) for m in manifests]}")
    print(f"agents           {len(labels)}")
    print(f"scored rows      {len(rows)}")
    print(f"  train          {len(train_rows):6d}   positives {int(y_train.sum()):5d}")
    print(f"  calibrate      {len(cal_rows):6d}   positives {int(y_cal.sum()):5d}")
    print(f"  test           {len(test_rows):6d}   positives {int(y_test.sum()):5d}")
    print("rows per archetype")
    for archetype, count in sorted(Counter(r.archetype for r in rows).items()):
        print(f"  {archetype:<20}{count:6d}")

    if len(set(y_train.tolist())) < 2:
        print("training rows contain a single class; nothing to learn")
        return 2

    # ── feature-layer leakage, BEFORE anything is trained ───────────────────────────
    #
    # Checked first so a leaked feature stops the run rather than producing a model with an
    # excellent score that nobody looks at twice. A bundle is never written when this fails.
    leakage = leakage_report(rows)
    print()
    print(f"feature-layer leakage (Cramer's V vs archetype, threshold {MAX_CRAMERS_V})")
    for name, value in list(leakage["per_feature"].items())[:6]:
        print(f"  {name:<26}{value:6.3f}")
    if not leakage["passes"]:
        print()
        print(
            f"REFUSING TO TRAIN: `{leakage['max_feature']}` separates archetypes at "
            f"V={leakage['max_cramers_v']} > {MAX_CRAMERS_V}.\n"
            "A single feature that identifies the archetype means the generator is writing "
            "the answer into the input, and the model would be a lookup table with good "
            "metrics. Fix the generator or the feature. Do not raise the threshold."
        )
        return 3

    # ── supervised ──────────────────────────────────────────────────────────────────
    import lightgbm as lgb

    classifier = lgb.LGBMClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        learning_rate=LEARNING_RATE,
        # The classes are imbalanced by construction — legitimate traffic dominates, as it
        # should. Balancing tells the model the prior is 50/50, which is a lie about the
        # world and produces a model that fires far too often.
        is_unbalance=False,
        random_state=args.seed,
        verbose=-1,
        deterministic=True,
        force_row_wise=True,
        num_threads=1,
    )
    classifier.fit(x_train, y_train)

    raw_cal = classifier.predict_proba(x_cal)[:, 1] if len(cal_rows) else np.array([])
    calibration = (
        isotonic_breakpoints(raw_cal, y_cal)
        if len(cal_rows) >= 10
        else {"x": [0.0, 1.0], "y": [0.0, 1.0]}
    )

    raw_test = classifier.predict_proba(x_test)[:, 1] if len(test_rows) else np.array([])
    calibrated_test = (
        np.interp(raw_test, calibration["x"], calibration["y"])
        if raw_test.size
        else raw_test
    )

    # ── anomaly ─────────────────────────────────────────────────────────────────────
    #
    # LEGITIMATE training rows only. It never sees an adversary, which is what gives it any
    # chance at all against an archetype nobody has seen — it scores distance from normal
    # rather than similarity to known-bad.
    from sklearn.ensemble import IsolationForest

    legit_train = x_train[y_train == 0]
    if len(legit_train) < 50:
        print(f"only {len(legit_train)} legitimate training rows; anomaly half needs more")
        return 2

    forest = IsolationForest(
        n_estimators=ISO_ESTIMATORS,
        contamination="auto",
        random_state=args.seed,
        n_jobs=1,
    )
    forest.fit(legit_train)

    # Empirical distribution of the forest's raw score over known-legitimate traffic. A raw
    # isolation-forest score is an arbitrary scale; its percentile among normal traffic is a
    # number a person can reason about and a band can be drawn on.
    legit_scores = np.sort(forest.decision_function(legit_train).astype(np.float64))
    quantiles = [round(float(v), 6) for v in legit_scores]

    def anomaly_unit(matrix: np.ndarray) -> np.ndarray:
        """Must match `Scorer._anomaly_to_unit` exactly, or the reported metrics describe a
        transform the service does not apply."""
        if matrix.size == 0:
            return matrix
        raw = forest.decision_function(matrix).astype(np.float64)
        rank = np.searchsorted(legit_scores, raw).astype(np.float64) / max(
            1, legit_scores.size
        )
        return np.clip((ANOMALY_TAIL - rank) / ANOMALY_TAIL, 0.0, 1.0)

    anomaly_test = anomaly_unit(x_test)
    combined_test = (
        np.maximum(calibrated_test, anomaly_test) if raw_test.size else raw_test
    )

    # Score EVERY row, not only the test split. Needed for one specific question: do the
    # legitimate agents that were built to look suspicious actually get flagged?
    #
    # With ~3% of thirty legitimate agents marked bursty there is exactly one of them, and a
    # 60/20/20 split by agent puts it wherever it puts it — usually not in test. Reporting
    # "no false positives" because the only agent capable of producing one was in the
    # training set would be the most misleading number in the whole bundle.
    x_all, _ = to_matrix(rows)
    raw_all = classifier.predict_proba(x_all)[:, 1]
    combined_all = np.maximum(
        np.interp(raw_all, calibration["x"], calibration["y"]), anomaly_unit(x_all)
    )

    # ── export ──────────────────────────────────────────────────────────────────────
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType
    from skl2onnx import to_onnx

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    supervised_onnx = convert_lightgbm(
        classifier.booster_,
        initial_types=[("input", FloatTensorType([None, len(FEATURE_NAMES)]))],
        zipmap=False,
        target_opset=TARGET_OPSET[""],
    )
    (out / "supervised.onnx").write_bytes(supervised_onnx.SerializeToString())

    anomaly_onnx = to_onnx(forest, x_train[:1], target_opset=TARGET_OPSET)
    (out / "anomaly.onnx").write_bytes(anomaly_onnx.SerializeToString())

    importance = dict(
        zip(
            FEATURE_NAMES,
            [float(v) for v in classifier.booster_.feature_importance("gain")],
            strict=True,
        )
    )
    total_gain = sum(importance.values()) or 1.0
    importance = {name: round(gain / total_gain, 6) for name, gain in importance.items()}

    model_version = _version(x_train, y_train, args.seed)

    bundle = {
        "model_version": model_version,
        "bundle_version": BUNDLE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "feature_scale": FEATURE_SCALE,
        "calibration": calibration,
        "anomaly_quantiles": quantiles,
        "anomaly_tail": ANOMALY_TAIL,
        "feature_importance": importance,
        "feature_mean": [round(float(v), 6) for v in x_train.mean(axis=0)],
        "feature_std": [round(float(v), 6) for v in x_train.std(axis=0)],
        "training": {
            "manifests": [str(m) for m in manifests],
            "model_free_traffic": clean,
            "model_shaped_rows": shaped_count,
            "seed": args.seed,
            "rows_total": len(rows),
            "rows_train": len(train_rows),
            "rows_calibrate": len(cal_rows),
            "rows_test": len(test_rows),
            "positives_train": int(y_train.sum()),
            "agents": len(labels),
            "supervised": {
                "n_estimators": N_ESTIMATORS,
                "max_depth": MAX_DEPTH,
                "learning_rate": LEARNING_RATE,
            },
            "anomaly": {"n_estimators": ISO_ESTIMATORS, "fit_rows": int(len(legit_train))},
        },
        "leakage": leakage,
        "evaluation": {
            "note": (
                "Held-out AGENTS, not held-out rows. These numbers describe traffic this "
                "project generated; see DEFENSE.md entry 8. The archetypes held out from "
                "development entirely are reported separately by `make eval`."
            ),
            "supervised": {
                "auc": roc_auc(calibrated_test, y_test) if raw_test.size else None,
                "at_step_up_band": binary_metrics(calibrated_test, y_test, STEP_UP_BAND)
                if raw_test.size else None,
                "at_deny_band": binary_metrics(calibrated_test, y_test, DENY_BAND)
                if raw_test.size else None,
            },
            "anomaly": {
                "auc": roc_auc(anomaly_test, y_test) if anomaly_test.size else None,
                "at_step_up_band": binary_metrics(anomaly_test, y_test, STEP_UP_BAND)
                if anomaly_test.size else None,
                "at_deny_band": binary_metrics(anomaly_test, y_test, DENY_BAND)
                if anomaly_test.size else None,
            },
            "combined": {
                "auc": roc_auc(combined_test, y_test) if combined_test.size else None,
                "at_step_up_band": binary_metrics(combined_test, y_test, STEP_UP_BAND)
                if combined_test.size else None,
                "at_deny_band": binary_metrics(combined_test, y_test, DENY_BAND)
                if combined_test.size else None,
            },
            "reliability": reliability_table(calibrated_test, y_test)
            if raw_test.size else [],
            "per_archetype_at_deny_band": _per_archetype(
                test_rows, combined_test, DENY_BAND
            ),
            "bursty_legitimate": _bursty_report(
                rows, combined_all, DENY_BAND, assignment
            ),
        },
    }
    (out / "bundle.json").write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    (out / "reliability.svg").write_text(
        _reliability_svg(bundle["evaluation"]["reliability"]) + "\n", encoding="utf-8"
    )

    _report(bundle, out)
    return 0


def _version(x: np.ndarray, y: np.ndarray, seed: int) -> str:
    """Deterministic in the training data and the hyperparameters.

    Two runs on the same data produce the same version string, and any change to either
    produces a different one. A timestamp would change on every rerun and tell a reader
    nothing about whether two records were scored by the same model.
    """
    digest = hashlib.sha256()
    digest.update(x.tobytes())
    digest.update(y.tobytes())
    digest.update(
        json.dumps(
            [list(FEATURE_NAMES), N_ESTIMATORS, MAX_DEPTH, LEARNING_RATE,
             ISO_ESTIMATORS, seed]
        ).encode()
    )
    return f"risk-{BUNDLE_VERSION}-{digest.hexdigest()[:12]}"


def _bursty_report(
    rows: list[Row], scores: np.ndarray, threshold: float, assignment: dict[str, str]
) -> dict:
    """The legitimate agents built to look like something worth stopping.

    **These must generate false positives.** A generator whose classes never overlap gives
    the model near-perfect scores and makes the false-positive cost in rupees pure fiction.
    A zero here is a finding about the generator, not a result about the model.

    Reported across every split, with the split named, because the honest caveat — that a
    bursty agent in the training set is an in-sample number — is smaller than the dishonesty
    of omitting it.
    """
    indices = [i for i, row in enumerate(rows) if row.bursty]
    if not indices:
        return {"agents": 0, "rows": 0, "note": "NO OVERLAP GENERATED — see zoo/README.md"}

    flagged = sum(1 for i in indices if scores[i] >= threshold)
    agents = sorted({rows[i].agent_id for i in indices})
    return {
        "agents": len(agents),
        "rows": len(indices),
        "flagged": flagged,
        "flag_rate": round(flagged / len(indices), 4),
        "splits": sorted({assignment.get(rows[i].agent_id, "?") for i in indices}),
        "note": (
            "Legitimate agents deliberately given adversary-like bursts. Rows in the train "
            "or calibrate split are in-sample and are labelled as such by `splits`."
        ),
    }


def _per_archetype(rows: list[Row], scores: np.ndarray, threshold: float) -> dict:
    """Flag rate per archetype on the test split.

    Reported per archetype rather than only in aggregate because the aggregate hides the one
    result that matters most here: the flag rate on the LEGITIMATE agents that were built to
    look suspicious. If that number is zero, the generator has no class overlap and the
    false-positive cost in rupees is fiction.
    """
    if scores.size == 0:
        return {}
    result: dict[str, dict] = {}
    for archetype in sorted({row.archetype for row in rows}):
        mask = np.asarray([row.archetype == archetype for row in rows])
        bursty = np.asarray([row.archetype == archetype and row.bursty for row in rows])
        result[archetype] = {
            "rows": int(mask.sum()),
            "flagged": int((scores[mask] >= threshold).sum()),
            "flag_rate": round(float((scores[mask] >= threshold).mean()), 4),
        }
        if bursty.any():
            result[archetype]["bursty_rows"] = int(bursty.sum())
            result[archetype]["bursty_flagged"] = int((scores[bursty] >= threshold).sum())
    return result


def _reliability_svg(table: list[dict]) -> str:
    """The reliability diagram, as an SVG built by hand.

    No matplotlib: it is a large dependency for one chart, and a committed PNG cannot be
    diffed or recomputed by a reader. An SVG is text, so a reviewer can see the numbers that
    produced the picture rather than trusting the picture.

    What the chart shows: predicted probability against observed frequency, per decile. A
    perfectly calibrated model sits on the diagonal. Bars below it are over-confident, above
    it under-confident, and the 0.55 / 0.80 bands only mean anything if the model is close
    to that line — an uncalibrated gradient-boosting margin is not a probability.
    """
    width, height, pad = 420, 420, 50
    plot = width - 2 * pad

    def x(value: float) -> float:
        return pad + value * plot

    def y(value: float) -> float:
        return height - pad - value * plot

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="monospace" font-size="10">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<line x1="{x(0)}" y1="{y(0)}" x2="{x(1)}" y2="{y(1)}" stroke="#bbbbbb" '
        f'stroke-dasharray="4 3"/>',
        f'<line x1="{x(0)}" y1="{y(0)}" x2="{x(1)}" y2="{y(0)}" stroke="#333333"/>',
        f'<line x1="{x(0)}" y1="{y(0)}" x2="{x(0)}" y2="{y(1)}" stroke="#333333"/>',
    ]
    for band, colour in ((STEP_UP_BAND, "#d08a1e"), (DENY_BAND, "#b03030")):
        parts.append(
            f'<line x1="{x(band)}" y1="{y(0)}" x2="{x(band)}" y2="{y(1)}" '
            f'stroke="{colour}" stroke-dasharray="2 3"/>'
        )
        parts.append(f'<text x="{x(band) + 3}" y="{y(1) + 10}" fill="{colour}">{band}</text>')

    points = [
        (row["mean_predicted"], row["observed_rate"], row["count"])
        for row in table
        if row["count"] and row["mean_predicted"] is not None
    ]
    for predicted, observed, count in points:
        radius = 2.5 + min(6.0, (count ** 0.5) / 3)
        parts.append(
            f'<circle cx="{x(predicted):.1f}" cy="{y(observed):.1f}" r="{radius:.1f}" '
            f'fill="#1a4d2e" fill-opacity="0.75"/>'
        )
    if len(points) > 1:
        path = " ".join(
            f"{'M' if i == 0 else 'L'}{x(p):.1f},{y(o):.1f}"
            for i, (p, o, _) in enumerate(points)
        )
        parts.append(f'<path d="{path}" fill="none" stroke="#1a4d2e" stroke-width="1.2"/>')

    parts += [
        f'<text x="{x(0.5) - 40}" y="{height - 14}">predicted P(not legitimate)</text>',
        f'<text x="12" y="{y(0.5) + 40}" transform="rotate(-90 12 {y(0.5) + 40})">'
        f'observed frequency</text>',
        f'<text x="{pad}" y="{pad - 22}" font-size="12">Reliability — held-out agents</text>',
        f'<text x="{pad}" y="{pad - 8}" fill="#666666">dashed diagonal = perfect '
        f'calibration; circle area ~ bin count</text>',
        "</svg>",
    ]
    return "\n".join(parts)


def _report(bundle: dict, out: Path) -> None:
    print()
    print(f"model_version    {bundle['model_version']}")
    print(f"written to       {out}/")
    for name in ("supervised.onnx", "anomaly.onnx", "bundle.json", "reliability.svg"):
        size = (out / name).stat().st_size
        print(f"  {name:<18}{size / 1024:8.1f} KiB")

    print()
    print("component scores on HELD-OUT AGENTS (deny band)")
    for component in ("supervised", "anomaly", "combined"):
        block = bundle["evaluation"][component]
        metrics = block["at_deny_band"]
        auc = block["auc"]
        if metrics is None:
            print(f"  {component:<12} no test rows")
            continue
        print(
            f"  {component:<12} auc={auc if auc is not None else 'n/a':<8} "
            f"precision={metrics['precision']:<8} recall={metrics['recall']:<8} "
            f"fpr={metrics['false_positive_rate']}"
        )

    print()
    print("flag rate per archetype (deny band, test split)")
    for archetype, stats in bundle["evaluation"]["per_archetype_at_deny_band"].items():
        line = (
            f"  {archetype:<20}{stats['flagged']:5d}/{stats['rows']:<6d} "
            f"{stats['flag_rate']:6.1%}"
        )
        if "bursty_rows" in stats:
            line += f"   (bursty {stats['bursty_flagged']}/{stats['bursty_rows']})"
        print(line)

    print()
    print(
        f"feature-layer leakage: max V = {bundle['leakage']['max_cramers_v']} "
        f"({bundle['leakage']['max_feature']}), threshold {bundle['leakage']['threshold']}"
    )

    print()
    print("top features by gain")
    ranked = sorted(bundle["feature_importance"].items(), key=lambda kv: -kv[1])
    for name, gain in ranked[:6]:
        print(f"  {name:<26}{gain:7.3f}")

    bursty = bundle["evaluation"]["bursty_legitimate"]
    print()
    if not bursty.get("rows"):
        print(
            "WARNING: no legitimate agent was given adversary-like bursts. The generator "
            "has no class overlap, so the false-positive cost in rupees would be fiction. "
            "See zoo/README.md and DEFENSE.md 8."
        )
    else:
        print(
            f"legitimate agents built to look suspicious: {bursty['agents']} agent(s), "
            f"{bursty['flagged']}/{bursty['rows']} rows flagged "
            f"({bursty['flag_rate']:.1%}), splits {bursty['splits']}"
        )
        if bursty["flagged"] == 0:
            print(
                "  WARNING: zero of them flagged. Either the bursts are too mild to look "
                "adversarial or the model is ignoring them; either way the class overlap "
                "is decorative and the false-positive figure means nothing."
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", default=None, help="default: every file in data/traffic")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument(
        "--allow-model-shaped",
        action="store_true",
        help="train on traffic a model already influenced; see `_model_free`",
    )
    parser.add_argument("--seed", type=int, default=20260827)
    parser.add_argument(
        "--dsn",
        default=os.environ.get(
            "DATABASE_URL_APP", "postgresql://dwaar_app:app_pw@localhost:5432/dwaar"
        ),
        help="read-only use; the app role is enough",
    )
    return parser


def main() -> int:
    return train(build_parser().parse_args())


if __name__ == "__main__":
    sys.exit(main())
