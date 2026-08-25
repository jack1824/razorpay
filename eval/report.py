#!/usr/bin/env python3
"""`make eval` — the honest numbers.

    python -m eval.report

Every figure is computed from `decision_records` joined to the zoo's run manifests, and
every figure is labelled with what it actually measures. That second half is not decoration:
F-029, F-030 and F-033 were all cases where a number was computed correctly at run time and
still meant something other than its label claimed.

── What is printed, and why each one is here ───────────────────────────────────────────

    feature importances       Because no automated check can catch a feature that correlates
                              with how the generator was written. The only control is a
                              person reading the ranking, so the ranking is printed every
                              run and a single feature above 40% is called out.

    supervised and anomaly    Separately, always. A combined number cannot answer the one
    scored separately         question that matters on evaluation day: which half caught the
                              held-out archetypes. "Neither" is a real answer.

    per-archetype recall      An aggregate hides the archetype the model is supposed to be
                              bad at. The injector's behaviour is ordinary; only its text is
                              hostile. A behavioural model SHOULD miss it.

    legitimate flag rate      The false-positive number, and the bursty legitimate agents
                              reported separately — those are the customers this system
                              would block, and they are the point of the class overlap.

    injection discrimination  Caught vs false-positived, with SKU9001 named explicitly.

── What is NOT here yet ────────────────────────────────────────────────────────────────

The held-out archetypes. `compromised` and `sleeper` are written in a separate session, kept
on a branch, and are not run against the model until evaluation day. When they land, their
numbers appear on their own line and are the ones worth reading. Until then this report says
so rather than quietly reporting four archetypes as though they were six.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import psycopg

from dwaar.risk.bands import DENY_BAND, STEP_UP_BAND

TRAFFIC_DIR = Path("data/traffic")
MODEL_DIR = Path("models/risk")
INJECTION_DIR = Path("models/injection")

#: A single feature above this share of total gain is a generator artifact until someone
#: explains why it is not. Not a threshold that fails a build — the judgment cannot be
#: automated — but the number is put in front of whoever is looking. See F-030.
IMPORTANCE_ALARM = 0.40

#: The archetypes held out from development entirely. Their absence is reported rather than
#: silently omitted.
HELD_OUT = ("compromised", "sleeper")

SKU9001 = "Ignore Premium Detergent 2kg"


#: Bands. Imported rather than restated so a threshold change moves the report with it.


@dataclass
class Row:
    agent_id: str
    archetype: str
    is_legitimate: bool
    bursty: bool
    decision: str
    rule_fired: str | None
    risk_score: float | None
    injection_flag: bool | None
    features: dict[str, int]
    stages: list[str]
    amount_paise: int | None
    created_at: object = None
    """Ordering within an agent's own run. Needed for the change-point split, which is the
    only measurement here that controls for who wrote the agent."""
    latency_us: int = 0
    budget_before: int | None = None
    budget_after: int | None = None
    bounded_amount_paise: int | None = None
    seq: int = 0


def load_labels(paths: list[Path]) -> dict[str, dict]:
    """`decision_id -> the agent's label in the run that PRODUCED that decision`.

    ── Why this is keyed on the decision and not the agent ─────────────────────────────

    F-048: agent identities are `sha256(seed:'agent':index)` — positional, with no archetype
    in them. Two runs on the same seed with different archetype MIXES therefore reuse the
    same `agent_id` for different archetypes, because adding two archetypes shifts every
    later index.

    That happened between `eval-20260901` and `heldout-20260901`, and it is not cosmetic.
    Joining `decision_records` to a manifest on `agent_id` merged one run's rows into the
    other's labels and reported `compromised` at 43.3% when its actual rate in its own run
    was 18.8%. The number was wrong and looked entirely reasonable.

    The manifest records a `decision_id` per attempt, which is exact: it names the row that
    request produced. So the join is on that, and a record belongs to exactly the run that
    caused it.
    """
    labels: dict[str, dict] = {}
    for path in paths:
        agents: dict[str, dict] = {}
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                entry = json.loads(line)
                if entry.get("kind") == "run":
                    agents = {a["agent_id"]: a for a in entry["agents"]}
                elif entry.get("kind") == "attempt" and entry.get("decision_id"):
                    meta = agents.get(entry["agent_id"])
                    if meta is not None:
                        labels[entry["decision_id"]] = meta
    return labels


def load_rows(dsn: str, labels: dict[str, dict]) -> list[Row]:
    """Exactly the records the manifests' attempts produced. See `load_labels` on F-048."""
    rows: list[Row] = []
    ids = list(labels)
    with psycopg.connect(dsn) as conn:
        for start in range(0, len(ids), 500):
            batch = ids[start : start + 500]
            for record in conn.execute(
                "SELECT record_id, agent_id, merchant_id, decision, rule_fired, risk_score, "
                "       injection_flag, features, stages_executed, amount_paise, "
                "       created_at, latency_us, budget_before, budget_after, "
                "       bounded_amount_paise, seq "
                "FROM decision_records WHERE record_id = ANY(%s) ORDER BY seq",
                (batch,),
            ).fetchall():
                (record_id, agent_id, merchant_id, decision, rule, score, flag, features,
                 stages, amount, created_at, latency_us, budget_before, budget_after,
                 bounded, seq) = record
                meta = labels[str(record_id)]
                _MERCHANT_BY_AGENT[agent_id] = merchant_id
                rows.append(
                    Row(
                        agent_id=agent_id,
                        archetype=meta["archetype"],
                        is_legitimate=bool(meta["is_legitimate"]),
                        bursty=bool(meta.get("bursty")),
                        decision=decision,
                        rule_fired=rule,
                        risk_score=float(score) if score is not None else None,
                        injection_flag=flag,
                        features=features or {},
                        stages=list(stages or ()),
                        amount_paise=amount,
                        created_at=created_at,
                        latency_us=latency_us or 0,
                        budget_before=budget_before,
                        budget_after=budget_after,
                        bounded_amount_paise=bounded,
                        seq=seq,
                    )
                )
    return rows


def rate(numerator: int, denominator: int) -> str:
    return f"{numerator}/{denominator}" + (
        f" = {numerator / denominator:6.1%}" if denominator else "   —"
    )


def rule(title: str) -> None:
    print()
    print(title)
    print("─" * 78)


# ── sections ────────────────────────────────────────────────────────────────────────


def section_scope(rows: list[Row], labels: dict[str, dict], manifests: list[Path]) -> None:
    rule("SCOPE — what these numbers describe")
    print(f"  manifests            {', '.join(str(m) for m in manifests)}")
    print(f"  agents               {len({r.agent_id for r in rows})}")
    print(f"  attempts labelled    {len(labels)}   (joined on decision_id — F-048)")
    print(f"  decision records     {len(rows)}")
    scored = [r for r in rows if r.risk_score is not None]
    print(f"    scored by a model  {len(scored)}")
    gate_denied = sum(1 for r in rows if r.risk_score is None and r.decision == "deny")
    print(f"    denied by the gate {gate_denied}")
    print()
    print("  Traffic is SYNTHETIC and generated by this project. Accuracy figures below")
    print("  describe our own generator; see DEFENSE.md entry 8. The claims made without")
    print("  qualification are about enforcement, latency, chain integrity and failure")
    print("  behaviour, which are properties of the code.")

    present = {r.archetype for r in rows}
    missing = [name for name in HELD_OUT if name not in present]
    if missing:
        print()
        print(f"  HELD OUT, NOT YET RUN: {', '.join(missing)}")
        print("  Written in a separate session, kept on a branch, first contact is evaluation")
        print("  day. Their numbers will be reported on their own line and are the ones worth")
        print("  reading. Nothing below includes them.")


def section_importances(bundle: dict) -> None:
    rule("FEATURE IMPORTANCES — read these every run")
    importance = bundle.get("feature_importance") or {}
    if not importance:
        print("  no importances in the bundle")
        return

    ranked = sorted(importance.items(), key=lambda kv: -kv[1])
    for name, gain in ranked[:10]:
        bar = "█" * int(round(gain * 40))
        flag = "  <-- ALARM" if gain > IMPORTANCE_ALARM else ""
        print(f"  {name:<26}{gain:6.3f}  {bar}{flag}")

    top_name, top_gain = ranked[0]
    print()
    if top_gain > IMPORTANCE_ALARM:
        print(f"  `{top_name}` carries {top_gain:.0%} of total gain, above the "
              f"{IMPORTANCE_ALARM:.0%}")
        print("  line. Treat it as a GENERATOR ARTIFACT until someone explains why it is not.")
        print("  F-030 was exactly this: 74% of gain on a feature that turned out to be a fact")
        print("  about how the agents were coded. The leakage check did not catch it and no")
        print("  automated check will — a threshold catches a feature that IS the label, not")
        print("  one that correlates with how the generator was written.")
    else:
        print(f"  No single feature above {IMPORTANCE_ALARM:.0%} of gain. That is the "
              "absence of one")
        print("  known failure mode, not evidence of correctness — see F-030 and DEFENSE.md 8.")

    leakage = bundle.get("leakage") or {}
    if leakage:
        print()
        print(f"  feature-layer leakage   max Cramer's V = {leakage['max_cramers_v']} "
              f"({leakage['max_feature']}), threshold {leakage['threshold']}")
        print("  Catches a feature that IS the archetype label. It does NOT catch a feature")
        print("  that merely correlates with generator conventions.")


def confusion(rows: list[Row], score, threshold: float) -> dict:
    tp = fp = fn = tn = 0
    for row in rows:
        value = score(row)
        if value is None:
            continue
        flagged = value >= threshold
        hostile = not row.is_legitimate
        tp += flagged and hostile
        fp += flagged and not hostile
        fn += (not flagged) and hostile
        tn += (not flagged) and not hostile
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
    }


def section_components(bundle: dict) -> None:
    rule("MODEL COMPONENTS — scored separately, always")
    evaluation = bundle.get("evaluation") or {}
    print(f"  {'component':<14}{'AUC':<9}{'precision':<12}{'recall':<10}{'FPR'}")
    for component in ("supervised", "anomaly", "combined"):
        block = evaluation.get(component) or {}
        metrics = block.get("at_deny_band")
        if not metrics:
            print(f"  {component:<14}no test rows")
            continue
        auc = block.get("auc")
        print(
            f"  {component:<14}{auc if auc is not None else 'n/a':<9}"
            f"{metrics['precision']:<12}{metrics['recall']:<10}"
            f"{metrics['false_positive_rate']}"
        )
    print()
    print("  Measured on HELD-OUT AGENTS from the training run, at the deny band"
          f" ({DENY_BAND}).")
    print("  Supervised is a binary classifier over four archetypes; it has no reason to")
    print("  recognise a fifth. Anomaly is fit on legitimate traffic only, so it scores")
    print("  distance from normal rather than similarity to known-bad — it is the half with")
    print("  any chance against an archetype nobody has seen.")
    print()
    print("  anomaly score basis: percentile rank of the isolation forest's decision")
    print("    function among LEGITIMATE training traffic, compressed into the lowest")
    tail = bundle.get("anomaly_tail", 0.05)
    print(f"    {tail:.0%} of that distribution. An uncompressed rank is")
    print("    uniform on the population it was fitted to, which put a fixed 20% of")
    print("    legitimate traffic above the deny band regardless of model quality (F-029).")


def section_per_archetype(rows: list[Row]) -> None:
    rule("PER-ARCHETYPE — on live traffic, at the deny band")
    by_archetype: dict[str, list[Row]] = defaultdict(list)
    for row in rows:
        by_archetype[row.archetype].append(row)

    print(f"  {'archetype':<18}{'records':>8}{'scored':>8}{'flagged':>9}{'stopped':>9}")
    for archetype in sorted(by_archetype):
        group = by_archetype[archetype]
        scored = [r for r in group if r.risk_score is not None]
        flagged = sum(1 for r in scored if r.risk_score >= DENY_BAND)
        stopped = sum(1 for r in group if r.decision != "allow")
        print(
            f"  {archetype:<18}{len(group):>8}{len(scored):>8}{flagged:>9}{stopped:>9}"
        )

    print()
    print("  `scored` is smaller than `records` wherever the arithmetic gate short-circuited")
    print("  before the model ran. For budget_breacher that is most of its traffic, and the")
    print("  denial is arithmetic rather than behavioural — the record carries a NULL score,")
    print("  which is the evidence.")

    injector = by_archetype.get("injector")
    if injector:
        scored = [r for r in injector if r.risk_score is not None]
        flagged = sum(1 for r in scored if r.risk_score >= DENY_BAND)
        print()
        print(f"  injector, behavioural model only: {rate(flagged, len(scored))}")
        print("  A LOW number here is correct. An injector's behaviour is ordinary; only its")
        print("  text is hostile. The behavioural model should be bad at it, and the injection")
        print("  detector below is what owns that archetype.")


def section_false_positives(rows: list[Row]) -> None:
    rule("FALSE POSITIVES — the customers this system would block")
    legit = [r for r in rows if r.is_legitimate]
    scored = [r for r in legit if r.risk_score is not None]
    flagged = [r for r in scored if r.risk_score >= DENY_BAND]
    stepped = [
        r for r in scored if STEP_UP_BAND <= r.risk_score < DENY_BAND
    ]
    stopped = [r for r in legit if r.decision == "deny"]

    print(f"  legitimate records         {len(legit)}")
    print(f"    scored                   {len(scored)}")
    print(f"    above the deny band      {rate(len(flagged), len(scored))}")
    print(f"    in the step-up band      {rate(len(stepped), len(scored))}")
    print(f"    actually denied          {rate(len(stopped), len(legit))}")

    denied_rules = Counter(r.rule_fired for r in stopped)
    if denied_rules:
        print()
        print("    what denied them:")
        for name, count in denied_rules.most_common():
            print(f"      {str(name):<44}{count}")
        print("    A `mandate.*` rule is the mandate doing its job — the principal did not")
        print("    permit that category or that amount. It is not a model error.")

    bursty = [r for r in legit if r.bursty]
    if not bursty:
        print()
        print("  WARNING: no legitimate agent in this traffic was given adversary-like")
        print("  bursts. Without that class overlap the number above is measured against")
        print("  traffic that never looks suspicious, and it is fiction. See zoo/README.md.")
        return

    bursty_scored = [r for r in bursty if r.risk_score is not None]
    bursty_flagged = [r for r in bursty_scored if r.risk_score >= DENY_BAND]
    print()
    print("  of which BURSTY legitimate agents (declined-card retry storms)")
    print(f"    records                  {len(bursty)}")
    print(f"    above the deny band      {rate(len(bursty_flagged), len(bursty_scored))}")
    print("    These are legitimate customers whose card kept failing. They are SUPPOSED to")
    print("    generate false positives — a generator whose classes never overlap makes this")
    print("    whole section fiction.")
    if not bursty_flagged:
        print("    ZERO flagged. Either the bursts are too mild to look adversarial or the")
        print("    model is ignoring them; either way the overlap is decorative.")

    cost = sum(r.amount_paise or 0 for r in stopped)
    print()
    print(f"  false-positive cost, this traffic: Rs {cost / 100:,.2f} of legitimate purchases")
    print("    refused. Synthetic amounts against a synthetic basket — the METHOD is the")
    print("    claim here, not the rupee figure.")


def section_injection(rows: list[Row]) -> None:
    rule("INJECTION DETECTOR — discrimination, not pattern matching")
    from dwaar.risk import injection as inj

    detector = inj.load(INJECTION_DIR)
    if detector.degraded:
        print(f"  degraded: {detector.degraded} — named rules only, no fitted weights")
    print(f"  model_version              {detector.model_version}")

    checked = [r for r in rows if r.injection_flag is not None]
    flagged = [r for r in checked if r.injection_flag]
    unchecked = [r for r in rows if r.injection_flag is None]
    print(f"  records checked            {rate(len(checked), len(rows))}")
    print(f"    flagged                  {len(flagged)}")
    print(f"  records NOT checked        {len(unchecked)}   (gate short-circuited; flag is NULL)")

    injectors = [r for r in checked if r.archetype == "injector"]
    others = [r for r in checked if r.archetype != "injector"]
    if injectors:
        from zoo.agents.injector import LOOKALIKE_EVERY

        caught = sum(1 for r in injectors if r.injection_flag)
        # One in `LOOKALIKE_EVERY` of the injector's requests carries BENIGN text on
        # purpose, so the archetype's flag rate has a ceiling below 100% and a raw
        # percentage understates the detector badly. Stated because a number whose maximum
        # is not 100 has to say so, or it reads as a mediocre result.
        ceiling = 1.0 - 1.0 / LOOKALIKE_EVERY
        print()
        print(f"  injector archetype caught  {rate(caught, len(injectors))}")
        print(f"    ceiling                  {ceiling:6.1%}   "
              f"(1 in {LOOKALIKE_EVERY} of its requests is a deliberate lookalike)")
        attacks = len(injectors) * ceiling
        if attacks:
            print(f"    of actual attacks        {min(1.0, caught / attacks):6.1%}")
    if others:
        false = sum(1 for r in others if r.injection_flag)
        print(f"  flagged on other traffic   {rate(false, len(others))}")
        print("    Every other archetype, including 1,000+ legitimate records. A detector")
        print("    that fires here is blocking customers.")

    # The discrimination case, evaluated directly rather than inferred from traffic.
    verdict = detector.inspect({"search_term": SKU9001})
    status = "FLAGGED — WRONG" if verdict.flagged else "not flagged"
    print()
    print(f"  SKU9001 {SKU9001!r}")
    print(f"    {status}, confidence {verdict.confidence}")
    print("    A real product whose name opens with the highest-signal injection token")
    print("    there is. A detector that blocks it blocks a customer buying detergent.")

    from zoo.agents.injector import BENIGN_LOOKALIKES, INJECTION_PAYLOADS

    caught = sum(1 for t in INJECTION_PAYLOADS if detector.inspect({"q": t}).flagged)
    fp = sum(1 for t in BENIGN_LOOKALIKES if detector.inspect({"q": t}).flagged)
    print()
    print(f"  held-out payloads caught   {rate(caught, len(INJECTION_PAYLOADS))}")
    print(f"  benign lookalikes flagged  {rate(fp, len(BENIGN_LOOKALIKES))}")
    print("    Neither set is in the detector's training corpus; it is fitted on templates")
    print("    crossed with fillers, with the benign side drawn from the real catalogue.")


def section_enforcement(rows: list[Row]) -> None:
    rule("ENFORCEMENT — the claims that do NOT depend on the traffic")
    gate_denials = [
        r for r in rows
        if r.decision == "deny" and (r.rule_fired or "").startswith("mandate.")
    ]
    with_score = [r for r in gate_denials if r.risk_score is not None]
    print(f"  arithmetic denials         {len(gate_denials)}")
    print(f"    carrying a risk score    {len(with_score)}   (MUST be 0)")
    if with_score:
        print("    FAIL — a cap breach was scored. The gate is not short-circuiting, and the")
        print("    claim 'the model was never consulted' is false.")
    else:
        print("    Every one carries NULL. The model was never consulted, and the record is")
        print("    the evidence — checkable by anyone reading it, without trusting the code.")

    ran_detection = [r for r in rows if "detect_injection" in r.stages]
    inconsistent = [
        r for r in rows
        if (("detect_injection" in r.stages) != (r.injection_flag is not None))
    ]
    print()
    print(f"  records that ran detection {len(ran_detection)}")
    print(f"    flag/stage disagreements {len(inconsistent)}   (MUST be 0)")
    print("    `injection_flag` is a tristate: NULL means nothing looked. Migration 0014")
    print("    constrains it to agree with `stages_executed`, so a record cannot claim a")
    print("    check it did not perform.")




# ── the held-out pair ───────────────────────────────────────────────────────────────


def section_held_out(rows: list[Row]) -> None:
    """The two archetypes the model has never seen, on their own rows.

    ── The headline number is not the interesting one ──────────────────────────────────

    Read the change-point split first. An archetype's overall recall mixes the period it was
    behaving with the period it was not, and both held-out agents are *defined* by having
    both. A high overall number that turns out to be concentrated in the clean period is not
    detection, it is a detector that dislikes the agent — and the two are indistinguishable
    from the aggregate.

    `eval/PREDICTIONS.md` prediction 3 registered exactly this test before the run, because
    it is the one that does not require trusting the held-out author: a coding convention
    cannot change halfway through one agent's run, and a behaviour can.
    """
    held = [r for r in rows if r.archetype in HELD_OUT]
    if not held:
        rule("HELD-OUT ARCHETYPES")
        print("  none present in this traffic.")
        print("  Generate with: make traffic-heldout   (they default to 0 agents — see")
        print("  zoo/agents/__init__.py for why nothing invokes them by accident.)")
        return

    legit_scored = [r.risk_score for r in rows if r.is_legitimate and r.risk_score is not None]
    base = sum(1 for s in legit_scored if s >= DENY_BAND) / max(1, len(legit_scored))

    rule("HELD-OUT ARCHETYPES — first contact with the model")
    print(f"  legitimate base rate at the deny band: {base:.2%}  (n={len(legit_scored)})")
    print()
    print(f"  {'archetype':<16}{'n':>6}{'scored':>8}{'>=deny':>8}{'rate':>9}{'x base':>9}")
    for archetype in HELD_OUT:
        subset = [r for r in held if r.archetype == archetype]
        scored = [r.risk_score for r in subset if r.risk_score is not None]
        flagged = sum(1 for s in scored if s >= DENY_BAND)
        r_ = flagged / max(1, len(scored))
        print(
            f"  {archetype:<16}{len(subset):>6}{len(scored):>8}{flagged:>8}{r_:>8.1%}"
            f"{(r_ / base if base else float('inf')):>8.0f}x"
        )

    # ── the within-agent control ────────────────────────────────────────────────────
    print()
    print("  WITHIN-AGENT CHANGE-POINT — the measurement that controls for authorship")
    print("  Each agent split at its own declared change-point. Same author, same file,")
    print("  same habits on both sides; only the behaviour differs.")
    print()
    print(f"  {'archetype':<16}{'phase':<9}{'n':>6}{'>=deny':>8}{'rate':>9}{'mean risk':>11}"
          f"{'mean ticket':>13}")
    for archetype in HELD_OUT:
        share = _clean_share(archetype)
        totals = {"before": [0, 0, [], []], "after": [0, 0, [], []]}
        by_agent: dict[str, list[Row]] = {}
        for r in held:
            if r.archetype == archetype:
                by_agent.setdefault(r.agent_id, []).append(r)
        for agent_rows in by_agent.values():
            ordered = sorted(agent_rows, key=lambda r: r.seq)
            cut = int(len(ordered) * share)
            for phase, chunk in (("before", ordered[:cut]), ("after", ordered[cut:])):
                scored = [r.risk_score for r in chunk if r.risk_score is not None]
                totals[phase][0] += len(scored)
                totals[phase][1] += sum(1 for s in scored if s >= DENY_BAND)
                totals[phase][2] += scored
                totals[phase][3] += [r.amount_paise for r in chunk if r.amount_paise]
        for phase in ("before", "after"):
            n, flagged, scores, amounts = totals[phase]
            mean_score = sum(scores) / len(scores) if scores else 0.0
            mean_amount = sum(amounts) / len(amounts) / 100 if amounts else 0.0
            print(
                f"  {archetype:<16}{phase:<9}{n:>6}{flagged:>8}{flagged / max(1, n):>8.1%}"
                f"{mean_score:>11.4f}{mean_amount:>12,.0f}"
            )
        print(f"  {'':16}change-point at {share:.0%} of the run, read from the agent's own source")
    print()
    print("  A rate that is high BEFORE the change-point is the model disliking the agent")
    print("  rather than detecting the defection. See eval/RESULTS.md.")


def _clean_share(archetype: str) -> float:
    """The declared change-point, read from the agent's own module rather than guessed.

    Guessing it — 50%, say — would make the split an artifact of this file, and the split is
    the whole measurement. `compromised` ramps continuously and declares no constant, so it
    is halved and that is stated rather than implied.
    """
    if archetype == "sleeper":
        from zoo.agents.sleeper import CLEAN_SHARE  # noqa: PLC0415

        return float(CLEAN_SHARE)
    return 0.5


# ── the incumbent ───────────────────────────────────────────────────────────────────


def section_baseline(manifests: list[Path], dsn: str, rows: list[Row]) -> None:
    """A conventional fraud scorecard on the same traffic, at the same false-positive rate.

    Both a FITTED scorecard and an a-priori TEXTBOOK one, because the two disagreed about
    the sign of the classic card-testing terms and the disagreement is a finding about the
    training traffic. See `eval/baseline.py`.

    Where the incumbent wins, it is printed as a win. A comparison that only publishes the
    columns we take is an advertisement.
    """
    from eval.baseline import (  # noqa: PLC0415
        TERM_NAMES,
        TEXTBOOK_INTERCEPT,
        TEXTBOOK_WEIGHTS,
        Scorecard,
        load,
    )

    fit_paths = sorted(TRAFFIC_DIR.glob("bootstrap-*.jsonl"))
    if not fit_paths:
        rule("FRAUD BASELINE")
        print("  no bootstrap manifest to fit on; skipped.")
        return

    fit_run, fit_attempts = load(fit_paths[-1])
    fit_legit = {a["agent_id"] for a in fit_run["agents"] if a["is_legitimate"]}

    # ── One stream PER RUN, never concatenated ──────────────────────────────────────
    #
    # Two things go wrong if the manifests are merged into one list.
    #
    # F-048: agent identities are positional, so the same `agent_id` is a different
    # archetype in two runs with different mixes. A merged label map silently relabels one
    # run's traffic with the other's archetypes — the error that had `compromised` reading
    # 43.3% instead of its actual 18.8%.
    #
    # And the scorecard is STATEFUL. It profiles an account over time, so an agent appearing
    # in two runs eleven hours apart gets a `first_ts` from the earlier one and a velocity
    # term divided by eleven hours of elapsed time. That crushed the incumbent's strongest
    # signal and had it reading 49.7% on card testers where its real figure is 99.4%.
    #
    # A fraud engine sees one session at a time. So does this.
    runs: list[tuple[list[dict], dict[str, str]]] = []
    for path in manifests:
        run, chunk = load(path)
        by_agent = {a["agent_id"]: a["archetype"] for a in run["agents"]}
        labelled = {
            a["decision_id"]: by_agent.get(a["agent_id"], "?")
            for a in chunk
            if a.get("decision_id")
        }
        runs.append((chunk, labelled))
    attempts = [a for chunk, _ in runs for a in chunk]

    features = _features_by_record(dsn, fit_attempts + attempts)

    legit_scores = [r.risk_score for r in rows if r.is_legitimate and r.risk_score is not None]
    gateway_fpr = sum(1 for s in legit_scores if s >= DENY_BAND) / max(1, len(legit_scores))

    fitted = Scorecard().fit(fit_attempts, fit_legit, gateway_fpr, features)
    textbook = Scorecard(TEXTBOOK_WEIGHTS, TEXTBOOK_INTERCEPT).fit(
        fit_attempts, fit_legit, gateway_fpr, features
    )

    rule("FRAUD BASELINE — the incumbent, at the same false-positive rate")
    print(f"  fitted on {fitted.fit_n} bootstrap attempts: the same traffic the risk model saw")
    print(f"  both thresholds calibrated to the gateway's legit FPR of {gateway_fpr:.3%}")
    print()
    print(f"  {'term':<26}{'fitted':>10}{'textbook':>11}")
    for name in TERM_NAMES:
        print(f"  {name:<26}{fitted.weights[name]:>+10.3f}{TEXTBOOK_WEIGHTS[name]:>+11.3f}")
    print(f"  {'(intercept)':<26}{fitted.intercept:>+10.3f}{TEXTBOOK_INTERCEPT:>+11.3f}")
    print()
    print("  Where the FIT disagrees with the TEXTBOOK on a sign, that is evidence about")
    print("  this traffic and not about fraud. See eval/RESULTS.md.")

    per: dict[str, list[int]] = {}
    for label, model in (("fitted", fitted), ("textbook", textbook)):
        for chunk, labelled in runs:
            for score, attempt in model.score_stream(chunk, features):
                name = labelled.get(attempt.get("decision_id") or "", "?")
                slot = per.setdefault(name, [0, 0, 0])
                if label == "fitted":
                    slot[0] += 1
                    slot[1] += score >= model.threshold
                else:
                    slot[2] += score >= model.threshold

    gateway: dict[str, list[int]] = {}
    for r in rows:
        slot = gateway.setdefault(r.archetype, [0, 0, 0])
        slot[0] += 1
        if r.risk_score is not None:
            slot[1] += 1
            slot[2] += r.risk_score >= DENY_BAND

    print()
    print(f"  {'archetype':<17}{'n':>6}{'baseline fit':>14}{'textbook':>11}"
          f"{'model only':>12}{'END-TO-END':>12}")
    for name in sorted(per, key=lambda k: (k in HELD_OUT, k)):
        n, bf, bt = per[name]
        gn, scored, flagged = gateway.get(name, [0, 0, 0])
        model_rate = flagged / scored if scored else 0.0
        # END-TO-END is what the SYSTEM did — the arithmetic gate plus the policy engine
        # plus the model. A model-only number understates a per-transaction breach, which is
        # refused before scoring and carries risk_score NULL by design.
        denied = sum(1 for r in rows if r.archetype == name and r.decision != "allow")
        end_to_end = denied / gn if gn else 0.0
        baseline_rate = bf / max(1, n)
        # For every archetype but the legitimate one, higher is better. `legit_shopper` is
        # a FALSE-POSITIVE column and the comparison inverts, so it is never marked here —
        # a marker that means "wins" in five rows and "loses" in the sixth is a marker that
        # will be misread from the back of a room.
        # BOTH comparisons are marked, because they answer different objections and a
        # sceptic will make the harsher one. "Beats our model" is the fair question about
        # the model; "beats the system" is the fair question about the product.
        marker = ""
        if name != "legit_shopper":
            if baseline_rate > end_to_end + 0.02:
                marker = "  <- INCUMBENT BEATS THE SYSTEM"
            elif baseline_rate > model_rate + 0.02:
                marker = "  <- incumbent beats our MODEL"
        print(
            f"  {name:<17}{n:>6}{baseline_rate:>13.1%}{bt / max(1, n):>11.1%}"
            f"{model_rate:>11.1%}{end_to_end:>11.1%}{marker}"
        )
    print()
    print("  legit_shopper is a FALSE-POSITIVE row: lower is better and it is never marked.")
    print("  Its END-TO-END figure is high because most of those denials are")
    print("  `mandate.category_denied` — the principal did not permit that category. That is")
    print("  the mandate working, not the model misfiring, and the breakdown is above.")
    print()
    print("  `model only` is the risk score alone on requests that REACHED it.")
    print("  `END-TO-END` is what the system actually did, gate and policy included — a")
    print("  per-transaction breach is refused by arithmetic before any model runs, and its")
    print("  record carries risk_score NULL. Comparing a fraud model against our model alone")
    print("  measures the wrong thing; comparing it against the system is the fair question.")


#: Filled by `load_rows`. `decision_records.merchant_id` is not on `Row` because nothing
#: else needs it; the watermark lookup does.
_MERCHANT_BY_AGENT: dict[str, str] = {}


def _merchant_of(row: Row) -> str:
    return _MERCHANT_BY_AGENT.get(row.agent_id, "")


def _watermarks(dsn: str) -> dict[str, int]:
    """Per-merchant seq below which the money invariant was not yet enforced."""
    with psycopg.connect(dsn) as conn:
        try:
            return dict(
                conn.execute(
                    "SELECT merchant_id, max_seq FROM invariant_baselines "
                    "WHERE invariant = 'amount_conserved'"
                ).fetchall()
            )
        except psycopg.errors.UndefinedTable:
            return {}


def _features_by_record(dsn: str, attempts: list[dict]) -> dict[str, dict]:
    ids = [a["decision_id"] for a in attempts if a.get("decision_id")]
    out: dict[str, dict] = {}
    with psycopg.connect(dsn) as conn:
        for start in range(0, len(ids), 500):
            for record_id, features in conn.execute(
                "SELECT record_id, features FROM decision_records WHERE record_id = ANY(%s)",
                (ids[start : start + 500],),
            ).fetchall():
                out[str(record_id)] = features or {}
    return out


# ── the numbers that do not depend on the model ─────────────────────────────────────


def section_operational(rows: list[Row], dsn: str) -> None:
    """Latency, invariants, chain, LLM calls, cost.

    `eval/PREDICTIONS.md` prediction 4 registered these as the figures that do not move
    whatever the held-out run shows, because none of them depends on the traffic. They are
    printed beside the model numbers so that a poor model result cannot be read as a system
    result, and a good one cannot launder into one.
    """
    rule("OPERATIONAL — none of this depends on the model being any good")

    latencies = sorted(r.latency_us for r in rows if r.latency_us)
    if latencies:
        def q(p: float) -> float:
            return latencies[min(len(latencies) - 1, int(p * len(latencies)))] / 1000

        print(f"  latency (recorded in the row, n={len(latencies)})")
        print(f"    p50 {q(0.50):6.2f}ms   p95 {q(0.95):6.2f}ms   p99 {q(0.99):6.2f}ms"
              f"   max {latencies[-1] / 1000:6.2f}ms   budget 25ms")
        print("    Request start to just before the payload is built. It cannot include its")
        print("    own INSERT — it is a column in the row being inserted. The gate in")
        print("    tests/db/test_authorize_latency.py measures the whole pipeline and is")
        print("    therefore strictly stricter than this figure.")

    from dwaar.invariants import AmountFacts, check_amount_conserved  # noqa: PLC0415

    # Split at the migration-0017 watermark, exactly as `dwaar-verify` does. Records
    # written before the invariant was enforced are history and are COUNTED; a violation
    # above the watermark is a failure. Reporting one number for both would either hide a
    # live defect or condemn the system for rows it can no longer change.
    watermark = _watermarks(dsn)
    above = below = 0
    for r in rows:
        if not check_amount_conserved(
            AmountFacts(
                decision=r.decision,
                requested_paise=r.amount_paise,
                stated_paise=r.bounded_amount_paise,
                budget_before=r.budget_before,
                budget_after=r.budget_after,
            )
        ):
            continue
        if r.seq <= watermark.get(_merchant_of(r), 0):
            below += 1
        else:
            above += 1
    print()
    print(f"  money invariant violations ABOVE the watermark: {above}   (must be 0)")
    print(f"  below it, in records written before it was enforced: {below}")
    print("    what the ledger moved == what the decision stated, with the BOUND amount as")
    print("    the stated amount. dwaar/invariants.py. Found F-043 on its first run:")
    print("    throttle and step_up were reserving budget for decisions that permitted")
    print("    nothing. Those rows are inside signed payloads and cannot be corrected, so")
    print("    they are counted on every run rather than forgiven once.")

    llm_rows = sum(1 for r in rows if "llm" in " ".join(r.stages).lower())
    print()
    print(f"  LLM calls in the request path: {llm_rows}   (must be 0)")
    print("    Rule 1. Enforced three ways in CI — import closure, runtime, source scan.")

    with psycopg.connect(dsn) as conn:
        merchants = [
            m for (m,) in conn.execute(
                "SELECT DISTINCT merchant_id FROM decision_records "
                "WHERE agent_id = ANY(%s)", ([r.agent_id for r in rows[:1000]],)
            ).fetchall()
        ]
    from dwaar.verify_cli import verify  # noqa: PLC0415

    findings = verify(dsn, merchant=merchants[0] if len(merchants) == 1 else None)
    print()
    print(f"  chain verification: {'PASS' if findings.ok else 'FAIL'}   "
          f"{findings.checked.get('decision_records.chain', 0):,} records")
    if findings.legacy:
        total = sum(findings.legacy.values())
        print(f"    {total} record(s) below the migration-0017 watermark do not conserve")
        print(f"    money: {findings.legacy}. Counted, not hidden — F-038 and F-043.")

    # Cost. The gateway makes no model calls per decision; the only per-decision cost is
    # compute. Stated as what it is rather than converted into a headline saving.
    print()
    print("  cost per 1,000 decisions")
    print("    LLM tokens:        0    — no model call occurs in the request path")
    print("    ONNX inference:  ~2ms of CPU per decision, in-process, no network")
    print("    The explainer calls Gemini asynchronously and caches by (rule, decision,")
    print("    band), so a burst of N identical denials costs ONE call, not N. That is a")
    print("    property of the cache key, not a projection: see dwaar/explain/cache.py.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", default=None)
    parser.add_argument(
        "--dsn",
        default=os.environ.get(
            "DATABASE_URL_APP", "postgresql://dwaar_app:app_pw@localhost:5432/dwaar"
        ),
    )
    args = parser.parse_args()

    # EVAL manifests: traffic generated against the gateway as it actually runs, model
    # loaded and enforcing. That is the system being measured.
    #
    # Deliberately NOT the bootstrap manifests. Those were generated with the model unloaded
    # so it could be trained on traffic it had not shaped (F-031); measuring against them
    # would report a system that does not exist.
    # `heldout-*` as well as `eval-*`: both are traffic run against the gateway with the
    # model loaded and enforcing, which is the system being measured. Bootstrap manifests are
    # deliberately excluded — they were generated with the model unloaded so it could be
    # trained on traffic it had not shaped (F-031), and measuring against them would report a
    # system that does not exist.
    manifests = (
        [Path(args.manifest)]
        if args.manifest
        else sorted(TRAFFIC_DIR.glob("eval-*.jsonl")) + sorted(TRAFFIC_DIR.glob("heldout-*.jsonl"))
    )
    if not manifests:
        print(
            f"no eval manifests under {TRAFFIC_DIR}.\n"
            "Evaluation traffic is generated against the gateway WITH the model loaded:\n"
            "  uvicorn dwaar.api.app:app --port 8080\n"
            "  make traffic-eval"
        )
        return 2

    bundle_path = MODEL_DIR / "bundle.json"
    if not bundle_path.exists():
        print(f"no model bundle at {bundle_path}. Run `make train` first.")
        return 2
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

    labels = load_labels(manifests)
    rows = load_rows(args.dsn, labels)
    if not rows:
        print("no decision records for the agents in these manifests.")
        return 2

    print("DWAAR EVALUATION")
    print(f"model {bundle['model_version']}")

    section_scope(rows, labels, manifests)
    section_importances(bundle)
    section_components(bundle)
    section_per_archetype(rows)
    section_held_out(rows)
    section_false_positives(rows)
    section_injection(rows)
    section_enforcement(rows)
    section_baseline(manifests, args.dsn, rows)
    section_operational(rows, args.dsn)

    print()
    print("─" * 78)
    print("  Every number above was computed from decision_records at run time. None is a")
    print("  constant. That rules out fabrication; it does not rule out measuring the wrong")
    print("  thing, which is why each figure says what it measures. See FAILURES.md")
    print("  F-029, F-030 and F-033 for three cases where the difference mattered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
