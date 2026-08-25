"""The incumbent: a conventional transaction-fraud scorecard, given advantages we deny ourselves.

── Why build the thing we are arguing against ──────────────────────────────────────────

"Fraud detection asks whether a transaction is bad. We ask whether it was allowed" is the
project's central claim, and a claim about a comparison is worth nothing without the
comparison. So this is a real fraud model, tuned honestly, and it is handed inputs the
authorization gateway deliberately refuses:

    ABSOLUTE AMOUNT        `dwaar/risk/features.py` has no absolute amount and no
                           within-agent baseline. A fraud engine has both and they are its
                           strongest signals.
    DEVICE / IP            we key features on `(agent_id, principal_id)` and nothing else,
                           on purpose — see below.
    CARD DECLINE HISTORY   we have `failure_ratio`; a real engine has issuer response codes.

If the incumbent wins on a class, that is the finding and it gets reported at the top of the
section rather than in a footnote. A comparison that only publishes the columns we win is an
advertisement.

── The device/IP column is empty, and the reason is not laziness ───────────────────────

There is no device fingerprint and no IP in this system to give it. Agents are not browsers:
a fleet of agents runs from a handful of cloud egress addresses, so IP reputation on agent
traffic is close to a constant, and a device fingerprint of a headless process is the
process's own container image.

That is stated here rather than quietly scored as zero, because "we did not implement it"
and "it does not carry information in this domain" are different claims and only the second
one is ours. A reader who disagrees can weight it themselves; the scorecard's terms are
below in the open.

── Where the card-diversity term comes from, stated because it is a compromise ─────────

A real fraud engine sees the raw BIN. The run manifest does not record one — the gateway
hashes instruments at the observation layer before anything downstream sees them, which is a
privacy property this project wants and is not going to give up for a benchmark.

So the card-diversity term reads `bin_diversity` off the stored decision record: the count of
distinct instruments in the agent's rolling window, which is exactly what the fraud engine
would compute from the raw values. It is the same underlying observation counted the same
way, and it is the one term of the five that the incumbent is handed rather than deriving.

Said plainly because it cuts against the comparison being clean, and a reader who thinks it
matters should discount that term. The four terms that decide the interesting cases —
amount against the agent's own baseline above all — are computed here from the manifest.

── The weights are FITTED, not chosen, and that was not the first attempt ──────────────

The first version hand-weighted the five terms the way a reviewer would expect
(amount-deviation heaviest, since that is what a fraud engine leads with). It caught 0% of
every adversarial class, and publishing that would have been publishing a strawman.

The diagnosis was interesting enough to keep: `legit_shopper` scored a **maximum of 0.677**
against `card_tester`'s **0.551**. A real shopper occasionally buys something ten times its
own median — a laptop after five weeks of milk — and the amount terms fire hard on that. The
card tester's entire method is to stay small, so those same terms read zero for it, and it
saturated its three remaining terms below the level a legitimate shopper reaches on an
ordinary large purchase.

The fix is not to re-weight until we win. That is F-044 in the other direction — tuning until
the number agrees with the story. So the weights are fitted by logistic regression on the
**same bootstrap traffic the risk model was trained on**, with the same binary label. The
incumbent gets the best version of itself that the data supports, and nobody has to take our
word for the weights: they are printed in the report.

── How the threshold is set ────────────────────────────────────────────────────────────

Calibrated to the SAME false-positive rate on legitimate agents that the gateway achieves on
the run being measured. Comparing two detectors at different operating points measures the
operating points. The FPR is printed alongside every table.
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Signal:
    """One term of the scorecard. Named, weighted, and printed in the report."""

    name: str
    weight: float
    detail: str


#: The classic transaction-fraud terms, in the order a reviewer would read them. The WEIGHTS
#: are fitted, not written here — `Scorecard.fit` learns them by logistic regression on the
#: same bootstrap traffic the risk model saw.
#:
#: `amount_vs_own_baseline` and `amount_absolute` are the two the authorization gateway has
#: no equivalent of, and they are the reason this baseline can see things we cannot.
TERMS: tuple[Signal, ...] = (
    Signal("amount_vs_own_baseline", 0.0,
           "this request against this agent's own running median. THE signal a fraud engine "
           "leads with, and the one dwaar/risk/features.py has no equivalent of."),
    Signal("amount_absolute", 0.0,
           "large tickets are riskier in aggregate, independent of who sent them."),
    Signal("velocity", 0.0,
           "requests per minute against the fitted population scale. We have this one too."),
    Signal("card_diversity", 0.0,
           "distinct instruments in the agent's window. The textbook card-testing signal."),
    Signal("decline_ratio", 0.0,
           "refused authorisations over attempts. The other half of card testing."),
    Signal("device_ip_reputation", 0.0,
           "NOT SCORED, and absent from the fit. There is no device or IP in this system to "
           "give it, and on agent traffic a shared cloud egress makes it near-constant. "
           "Excluded as a statement about the domain, not as an omission."),
)

TERM_NAMES: tuple[str, ...] = tuple(t.name for t in TERMS if t.name != "device_ip_reputation")

#: What a fraud analyst sets on day one, before any of this traffic exists.
#:
#: Reported ALONGSIDE the fitted weights rather than instead of them, because the two answer
#: different questions and the difference between them turned out to be the finding. A
#: deployed incumbent arrives with priors from real fraud data; it does not learn its signs
#: from four synthetic archetypes. If the fit disagrees with the textbook on the SIGN of a
#: term, that is evidence about the training traffic and not about fraud.
TEXTBOOK_WEIGHTS: dict[str, float] = {
    "amount_vs_own_baseline": 3.0,
    "amount_absolute": 1.5,
    "velocity": 2.0,
    "card_diversity": 2.0,
    "decline_ratio": 1.5,
}
TEXTBOOK_INTERCEPT = -4.0


@dataclass
class AgentState:
    """Per-agent running state. A fraud engine profiles the account, not the request."""

    amounts: list[int]
    bins: set[str]
    declines: int
    attempts: int
    first_ts: float
    last_ts: float


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(q * (len(ordered) - 1))))
    return ordered[index]


class Scorecard:
    """Fit on one traffic file, scored against another. Stateful per agent, like the real thing."""

    def __init__(self, weights: dict[str, float] | None = None, intercept: float = 0.0) -> None:
        """`weights=TEXTBOOK_WEIGHTS` for the a-priori scorecard; omit to fit them."""
        self.amount_p95 = 0.0
        self.velocity_p95 = 0.0
        self.threshold = 1.0
        self.weights: dict[str, float] = dict(weights) if weights else {}
        self.intercept = intercept
        self.fit_n = 0
        self.fitted = weights is None

    # ── fitting ─────────────────────────────────────────────────────────────────────

    def fit(
        self,
        attempts: list[dict[str, Any]],
        legit_agents: set[str],
        target_fpr: float,
        features: dict[str, dict] | None = None,
    ):
        """Population scales from ALL traffic, decision threshold from LEGITIMATE traffic.

        The threshold is chosen so the scorecard's false-positive rate on legitimate agents
        matches the gateway's. Any other choice compares two detectors at two operating
        points, which measures the operating points.
        """
        amounts = [a["amount_paise"] for a in attempts if a.get("amount_paise")]
        self.amount_p95 = _percentile([float(x) for x in amounts], 0.95) or 1.0

        gaps = defaultdict(list)
        last: dict[str, float] = {}
        for a in sorted(attempts, key=lambda x: x["sent_at"]):
            if a["agent_id"] in last:
                gaps[a["agent_id"]].append(a["sent_at"] - last[a["agent_id"]])
            last[a["agent_id"]] = a["sent_at"]
        rates = [60.0 / max(0.01, statistics.median(g)) for g in gaps.values() if g]
        self.velocity_p95 = _percentile(rates, 0.95) or 1.0

        # ── Learn the weights rather than assert them ───────────────────────────────
        #
        # Same traffic the risk model trained on, same binary label. Balanced class weights,
        # because the adversarial classes are the minority and an unbalanced fit would find
        # the majority solution — "nothing is fraud" — which is exactly the strawman this
        # exists to avoid.
        from sklearn.linear_model import LogisticRegression  # noqa: PLC0415

        vectors = self.terms_stream(attempts, features or {})
        if not self.fitted:
            # Weights supplied a priori. Only the population scales and the threshold are
            # taken from this traffic; the signs and magnitudes are not.
            self.fit_n = len(vectors)
            return self._calibrate(attempts, legit_agents, target_fpr, features or {})
        matrix = [[v[name] for name in TERM_NAMES] for v, _ in vectors]
        labels = [0 if a["agent_id"] in legit_agents else 1 for _, a in vectors]
        model = LogisticRegression(max_iter=2000, class_weight="balanced").fit(matrix, labels)
        self.weights = dict(zip(TERM_NAMES, model.coef_[0], strict=True))
        self.intercept = float(model.intercept_[0])
        self.fit_n = len(labels)

        return self._calibrate(attempts, legit_agents, target_fpr, features or {})

    def _calibrate(self, attempts, legit_agents, target_fpr, features):
        """Threshold at the requested false-positive rate on legitimate agents."""
        legit_scores = sorted(
            (s for s, a in self.score_stream(attempts, features) if a["agent_id"] in legit_agents),
            reverse=True,
        )
        if legit_scores:
            cut = int(target_fpr * len(legit_scores))
            self.threshold = legit_scores[min(cut, len(legit_scores) - 1)]
        return self

    # ── scoring ─────────────────────────────────────────────────────────────────────

    def score_stream(
        self, attempts: list[dict[str, Any]], features: dict[str, dict]
    ) -> list[tuple[float, dict]]:
        """The fitted score per attempt. Before fitting, the unweighted mean of the terms."""
        import math  # noqa: PLC0415

        out = []
        for terms, attempt in self.terms_stream(attempts, features):
            if self.weights:
                z = self.intercept + sum(self.weights[k] * terms[k] for k in TERM_NAMES)
                score = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
            else:
                score = sum(terms[k] for k in TERM_NAMES) / len(TERM_NAMES)
            out.append((score, attempt))
        return out

    def terms_stream(
        self, attempts: list[dict[str, Any]], features: dict[str, dict]
    ) -> list[tuple[dict[str, float], dict]]:
        """Score every attempt in arrival order, carrying per-agent state forward.

        Order matters and is the point: `amount_vs_own_baseline` is only meaningful once the
        agent HAS a baseline, exactly as in production. The first few requests of any agent
        score low on that term for both detectors, and neither gets to peek ahead.
        """
        state: dict[str, AgentState] = {}
        out: list[tuple[dict[str, float], dict]] = []

        for a in sorted(attempts, key=lambda x: x["sent_at"]):
            agent = a["agent_id"]
            s = state.get(agent)
            amount = float(a.get("amount_paise") or 0)

            if s is None:
                s = state[agent] = AgentState([], set(), 0, 0, a["sent_at"], a["sent_at"])

            baseline_term = 0.0
            if len(s.amounts) >= 3:
                median = statistics.median(s.amounts) or 1.0
                ratio = amount / median
                # Saturating at 10x: past an order of magnitude the term is already maximal
                # and a 40x request should not out-score a 12x one on this alone.
                baseline_term = min(1.0, max(0.0, (ratio - 2.0) / 8.0))

            absolute_term = min(1.0, amount / self.amount_p95) if self.amount_p95 else 0.0

            elapsed = max(1e-6, a["sent_at"] - s.first_ts)
            rate = 60.0 * s.attempts / elapsed if s.attempts else 0.0
            velocity_term = min(1.0, rate / self.velocity_p95) if self.velocity_p95 else 0.0

            # The one term handed to the incumbent rather than derived here — see the
            # module docstring. `bin_diversity` is the normalised count of distinct
            # instruments in this agent's window, which is what a fraud engine computes from
            # the raw BINs it would have and we deliberately do not keep.
            record = features.get(a.get("decision_id") or "") or {}
            observed = record.get("bin_diversity")
            if observed is not None:
                card_term = min(1.0, float(observed) / 1_000_000 * 4.0)
            else:
                card_term = min(1.0, len(s.bins) / 6.0)
            decline_term = (s.declines / s.attempts) if s.attempts else 0.0

            out.append((
                {
                    "amount_vs_own_baseline": baseline_term,
                    "amount_absolute": absolute_term,
                    "velocity": velocity_term,
                    "card_diversity": card_term,
                    "decline_ratio": decline_term,
                },
                a,
            ))

            # State updates AFTER scoring — a request must not inform the score of itself.
            s.amounts.append(int(amount))
            s.attempts += 1
            s.last_ts = a["sent_at"]
            if a.get("instrument_bin"):
                s.bins.add(a["instrument_bin"])
            # The PSP's outcome ONLY. An earlier version also counted `decision == "deny"`,
            # which fed the gateway's own verdict back into the incumbent as an input — the
            # baseline would then have been partly scoring our answer rather than the
            # transaction, and any comparison built on it would be circular.
            #
            # `payment_succeeded` is None whenever no payment was attempted, which is every
            # denied request. So a denied agent accumulates no declines here, exactly as a
            # real issuer would report nothing for a transaction that never reached it.
            if a.get("payment_succeeded") is False:
                s.declines += 1

        return out


def load(path: Path) -> tuple[dict, list[dict]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    run = next(r for r in rows if r["kind"] == "run")
    return run, [r for r in rows if r["kind"] == "attempt"]
