# Held-out results — the run

**One run, reported. No retraining afterwards, no threshold adjustment, no second attempt.**

The inputs were locked in `eval/LOCKED_INPUTS.md` before the agents ran: bundle hashes, seeds,
policy version, and the commit of both worktrees. Nothing in it changed afterwards, and the
hashes are there so a reader does not have to take that on trust.

`eval/PREDICTIONS.md` was committed on 28 August, before the held-out agents were written.
Prediction 5 was added on the morning of the run, before the numbers were read. Every
prediction is resolved below, including the two that failed.

---

## The one thing to take from this document

**The model was wrong about two archetypes in two different directions, and not one rupee
moved that a mandate had not authorised — because spending authority was never the model's to
decide.**

That is the claim this run supports, and it is the only claim in the project that does not
depend on traffic we wrote ourselves. Everything below is the evidence for it, including the
parts where the model does badly, which are the parts that make it evidence at all.

---

## The short version

**The model's headline number is 92.2% recall on `sleeper`, and it is not a real result.**
90.2% of those flags land in the period the agent is behaving impeccably. The model is not
detecting the defection; it dislikes the agent. Prediction 3 was registered before the run
specifically to catch this, and it caught it.

**On `compromised` the model is worse than useless: its score goes DOWN when the agent
defects** — 0.366 before, 0.185 after, while the ticket size goes from ₹644 to ₹6,330.

**A fitted fraud baseline matches us on card testing and beats our model on budget
breaching**, using one signal we do not have.

**None of this touches the enforcement claims**, which is why they were registered separately
as prediction 4. Every one of them held.

---

## What ran

| | |
|---|---|
| run | `20260901-1787639331`, 407s wall clock |
| traffic | 2,672 attempts, 50 agents, six archetypes |
| held-out | `compromised` ×4 (160 requests), `sleeper` ×4 (320 requests) |
| model | `risk-0.1.0-e990ef33c5b6`, unchanged before and after |
| gateway | model loaded and enforcing — the system as deployed, not a fixture replay |

Both held-out agents signed correctly and held valid, unexpired mandates for the whole run.
Neither ever breached the per-transaction cap. If invalid credentials or arithmetic had been
the tell, no model would have been needed and the exercise would prove nothing.

---

## Prediction 1 — held-out recall. RESOLVED: the threshold was met and the number is misleading

Registered: **≥ 40% at the deny band for at least one held-out archetype** means
`inter_arrival_variance` carries real behavioural signal; **< 15%** means it is largely our
convention.

| archetype | scored | ≥ deny band | rate | × legitimate base rate |
|---|---|---|---|---|
| `sleeper` | 320 | 295 | **92.2%** | 139× |
| `compromised` | 160 | 30 | **18.8%** | 28× |

Legitimate base rate at the deny band: **0.66%** (n = 2,113).

`sleeper` clears 40% by a wide margin. Taken alone this reads as a decisive vindication.

**It should not be taken alone.** Prediction 3 exists because a per-archetype rate cannot
distinguish "caught the defection" from "disliked the agent", and here it is the second one.

`compromised` at 18.8% falls in the band the prediction called "a real outcome and not a
hedge": some signal transfers, a lot does not, and the importance ranking overstates it.

---

## Prediction 3 — the within-agent control. **FAILED**, and this is the finding

This was registered as "the prediction that does not depend on trusting the held-out author,
and the one worth reading first". It predicted that `sleeper`'s flag rate would be
concentrated *after* its change-point, with the pre-defection rate within roughly 3× of the
legitimate base rate.

The change-point is `CLEAN_SHARE = 0.80`, read from the agent's own source rather than
guessed.

| archetype | phase | n | ≥ deny | rate | mean risk | mean ticket |
|---|---|---|---|---|---|---|
| `sleeper` | **before** | 256 | 231 | **90.2%** | 0.9432 | ₹346 |
| `sleeper` | after | 64 | 64 | 100.0% | 1.0000 | ₹10,056 |
| `compromised` | before | 80 | 21 | 26.2% | 0.3656 | ₹644 |
| `compromised` | after | 80 | 9 | **11.2%** | 0.1852 | ₹6,330 |

**`sleeper` pre-defection: 90.2%, against a predicted ceiling of ~1.7%. That is 158× the
legitimate base rate during the period the agent is doing nothing wrong.**

The prediction stated in advance what this outcome would mean: *"the model is keying on
something about how that agent was written rather than on what it did."* That is the reading,
and it is the reading because it was written down first.

**`compromised` is worse.** Its flag rate and its mean risk both *fall* after it defects,
while its ticket size rises tenfold. The model is not weakly detecting the takeover — it is
anti-correlated with it.

---

## Prediction 2 — which component does the work. **FAILED**, in the opposite direction

Registered: on held-out archetypes, **anomaly recall exceeds supervised recall**. The
reasoning was that a supervised classifier trained on four archetypes has no mechanism for
recognising a fifth, while an isolation forest fitted on legitimate traffic scores distance
from normal.

Recovered by replaying each stored feature vector against the locked bundle:

| archetype | n | supervised ≥ 0.80 | anomaly ≥ 0.80 | combined |
|---|---|---|---|---|
| `legit_shopper` | 1,052 | 0.2% | 0.4% | 0.6% |
| `card_tester` | 640 | 98.8% | 99.4% | 99.4% |
| `budget_breacher` | 82 | 87.8% | 2.4% | 90.2% |
| `injector` | 150 | 76.7% | 0.0% | 76.7% |
| **`compromised`** | 160 | **15.0%** | **3.8%** | 18.8% |
| **`sleeper`** | 320 | **92.2%** | **0.0%** | 92.2% |

**The supervised half does all the work on both held-out archetypes and the anomaly half
contributes nothing — literally zero on `sleeper`.**

The prediction said being wrong here "would be more interesting than being right", and it is,
because it explains prediction 3's failure. The supervised classifier is not recognising a
fifth archetype. It is **forcing `sleeper` into a class it already knows**, and the class is
`card_tester`.

---

## Why: `sleeper`'s honest behaviour is card-testing-shaped

Median feature values. `sleeper` is split at its own change-point.

| feature | legit | card_tester | **sleeper CLEAN** | sleeper defect | compromised |
|---|---|---|---|---|---|
| `inter_arrival_variance` | 4.365 | **0.013** | **0.254** | 0.640 | 3.894 |
| `cadence_entropy` | 0.872 | 0.811 | **0.450** | 0.684 | 0.722 |
| `cart_mutation_rate` | 0.789 | **0.000** | **0.079** | 0.096 | 0.240 |
| `distinct_skus_1h` | 14.0 | **2.0** | **4.0** | 9.0 | 13.0 |
| `amount_entropy` | 0.917 | **0.000** | 0.839 | 0.726 | 0.725 |

On the three features the model weights most, a well-behaved replenishment robot sits beside
a card tester. **It is supposed to.** A standing order runs on a schedule, reorders the same
short list, and does not revise its basket. That is what a purchasing robot is.

The model learned that machine-regularity means card testing, because in the four archetypes
it was trained on, the card tester was the only regular agent anyone wrote.

---

## The open question, resolved: `inter_arrival_variance` at 68% of gain

`eval/PREDICTIONS.md` offered two readings — a real behavioural signal, or our convention.
**The answer is neither, and the third reading is more useful than both.**

**The feature is real.** A session with no sight of the feature list, no thresholds and no
access to `dwaar/risk/` independently produced an agent with low inter-arrival variance,
because that is what a scheduled robot does. Two authors reasoning only about behaviour
arrived at the same numerical signature. That is not a convention.

**The label association is the convention.** Regularity is not adversarial. A standing order
is regular. A cron job is regular. The feature measures something true and the model has
attached it to a conclusion the training traffic never earned, because our four archetypes
contained exactly one regular agent and it happened to be a criminal.

F-030's conclusion stands and now has a second instance: *a leakage threshold catches a
feature that IS the label; it does not catch a feature that correlates with how the generator
was written, and no automated check will.* Cramér's V for `inter_arrival_variance` was 0.665
against a 0.75 threshold — informative, not identifying, which is what a good feature looks
like and also what this looks like.

---

## Why `compromised` is missed: the defect is in the feature set, not the fit

`compromised` is defined by a change in **purpose**: what it buys and how much it spends. Its
cadence deliberately does not change.

Its own first half against its own second half:

| | before | after |
|---|---|---|
| mean ticket | ₹644 | **₹6,330** |
| `velocity_1h` | 10.5 | 30.5 |
| `distinct_skus_1h` | 7.0 | 18.5 |
| `inter_arrival_variance` | 3.551 | 3.933 |
| **mean risk score** | **0.3656** | **0.1852** |

The thirteen features are: `velocity_1m`, `velocity_1h`, `distinct_skus_1h`, `burst_index`,
`cadence_entropy`, `inter_arrival_variance`, `amount_entropy`, `bin_diversity`,
`failure_ratio`, `category_drift`, `cart_mutation_rate`, `price_probe_score`,
`session_duration_s`.

**There is no absolute amount and no measure of an amount against the agent's own baseline.**
`amount_entropy` is a dispersion measure over a window: a step change in level raises it
briefly and then it settles, and it cannot express direction at all. A tenfold increase in
ticket size within one agent's history is invisible.

Every feature is a window aggregate. **Not one of them is a deviation from that agent's own
norm** — which is precisely what "this agent has been taken over" means. The archetype was
not missed because the model is weak. It was missed because nothing in the vector can express
the thing that defines it.

---

## Prediction 5 — the `bin_diversity` confound. RESOLVED: it never fired

Registered on the morning of the run: if the held-out agents made payouts or card-less
requests, F-045 would inflate their anomaly scores for reasons unrelated to behaviour, and
held-out recall would look better than it is.

**Records with `bin_diversity = 0`, across all six archetypes: 0.**

Both held-out agents carry an instrument on every request. The confound never fired, the
figures over all records and excluding confounded records are identical, and no discount is
required. The prediction said this outcome was as informative as the other; it is reported
because it was registered, not because it was convenient.

F-045 remains open and unfixed — see below.

---

## Prediction 4 — what will not move. HELD, all of it

Registered so that a poor model result could not be read as a system result, and a good one
could not launder into one.

| claim | measured |
|---|---|
| per-transaction breach denied by arithmetic, `risk_score` NULL | **495 arithmetic denials, 0 carrying a score** |
| money invariant above the migration-0017 watermark | **0 violations** |
| tampered row detected and named by sequence number | **PASS** — `make demo` beat 6, every run |
| pipeline p99 inside budget | **7.37ms serial gate; 20.61ms recorded under the zoo's concurrency**, budget 25ms |
| `injection_flag` distinguishes unchecked from checked-and-clean | **0 flag/stage disagreements** across 4,369 records |
| no language model reachable from the request path | **0**, enforced three ways in CI |
| chain verification | **PASS over 16,060 records** in scope |

The injection detector, separately: **10/10 held-out payloads caught, 0/5 benign lookalikes
flagged, SKU9001 "Ignore Premium Detergent 2kg" not flagged at confidence 0.193.**

The two latency figures measure different things and both are stated. The **7.37ms** gate is
serial, one request at a time, and is what CI enforces on every push. The **20.61ms** is the
p99 recorded in the rows during this run, with fifty agents transacting concurrently against
one gateway — the more realistic number and the less flattering one. Both are inside the 25ms
budget; only the second one is close to it, and a reader should use the second.

---

## The fraud baseline

A conventional transaction-fraud scorecard, given a signal we deliberately do not have —
**absolute amount and amount against the agent's own baseline** — and calibrated to the same
false-positive rate on legitimate agents. Full method in `eval/baseline.py`.

Two versions, because they disagreed and the disagreement is a finding: weights **fitted** by
logistic regression on the same bootstrap traffic the risk model saw, and **textbook** weights
a fraud analyst would set a priori.

| archetype | n | baseline (fitted) | baseline (textbook) | our model only | our system end-to-end |
|---|---|---|---|---|---|
| `budget_breacher` | 384 | **96.1%** | 0.0% | **90.1%** | 97.9% |
| `card_tester` | 1,280 | **99.4%** | 0.0% | **99.4%** | 99.4% |
| `injector` | 320 | 0.6% | 0.0% | 72.7% | 95.6% |
| `legit_shopper` (false positives) | 2,400 | 0.6% | 0.2% | 0.7% | 13.8% |
| `compromised` | 160 | 0.0% | 0.0% | 18.8% | 24.4% |
| `sleeper` | 320 | 0.0% | 0.0% | 92.2% | 94.4% |

### Where the incumbent wins, stated first

**It beats our model on budget breaching, 96.1% to 90.1%**, and it does it with one term. It
**ties us exactly on card testing at 99.4%** — the class the model's single most important
feature was built for.

Our system still edges it on budget breaching end-to-end (97.9%), but that is the arithmetic
gate doing the work, not the model. The honest reading is: *on the two classes a fraud engine
is designed for, a fitted velocity term is as good as our thirteen-feature two-component
model.*

### What the fitted weights say

| term | fitted | textbook |
|---|---|---|
| `amount_vs_own_baseline` | **−1.717** | +3.000 |
| `amount_absolute` | +3.298 | +1.500 |
| `velocity` | **+9.176** | +2.000 |
| `card_diversity` | **−0.445** | +2.000 |
| `decline_ratio` | **−4.811** | +1.500 |

The fit put **negative** weight on the two textbook card-testing signals and on
amount-deviation. It is a velocity detector wearing a scorecard's name.

That is a fact about our synthetic traffic, not about fraud. In this zoo the card tester's
amounts are tiny and constant, so amount-deviation anti-correlates with the label; and the
gateway denies most adversarial traffic before a payment is attempted, so declines are rare
for exactly the agents that should have many. **Neither detector's fitted weights should be
expected to transfer to real traffic**, and that applies to ours as much as to the baseline.

The textbook scorecard catches **nothing** at a tolerable false-positive rate. That is also a
result: a scorecard tuned for card-present retail fraud, dropped onto agent traffic without
refitting, detects nothing.

### Where the comparison is unfair to the incumbent

Stated because it cuts against us later.

- **The card-diversity term is handed to it**, read from our stored `bin_diversity` feature,
  because the run manifest does not record a raw BIN. Four of five terms are computed
  independently; a reader who thinks that one matters should discount it.
- **The device/IP term is excluded**, weight zero. There is no device or IP in this system to
  give it, and on agent traffic a shared cloud egress makes it near-constant. That is a claim
  about the domain and a reader may disagree.
- **It is fitted on our traffic**, which is the same handicap our model has.

---

## Caveats, all of them

### The isolation was of code, not of the model

The held-out agents were written in a separate session with no access to `dwaar/risk/`, no
sight of the feature list and no thresholds, on a branch, committed by the main session
without being read. That is real and it is checkable in the history.

**It is not what a filesystem enforced.** `models/` is tracked in git, so the model bundle was
present in the held-out worktree the whole time. **The worktree separated the code; it did not
separate the model. Not running it early was a choice, not a control.**

Given that this project has already recorded one instance of a spec being edited to match a
measurement (F-044), the distinction is one worth drawing explicitly rather than leaving to
inference.

### This was a solo build

The held-out agents were **isolated, not independently authored**. `zoo/HELD_OUT_SPEC.md` was
the entire input to a separate session with no sight of the model. That is a weaker guarantee
than a second person, and it is the honest description. Nobody held these out; a session was
prevented from seeing what would have let it cheat.

Rule 5 of the spec was checked before the numbers were read: the held-out agents vary their
incidental fields per agent from their own seeded RNG, and both explicitly removed `free_text`
after noticing that only the `injector` populates it in this zoo — presence alone would have
been a clean label for the held-out pair. That check passing is what makes the result readable
at all.

### The generator confounds

**F-030** — `cart_mutation_rate` once carried 74% of gain and turned out to describe how the
agents were coded. **This run is the second instance of the same class**, on
`inter_arrival_variance` at 68%.

**F-045** — a request without an instrument produces `bin_diversity = 0`, a value no training
request ever had, and the anomaly model reads it as extreme. It did not fire here, and it is
**still unfixed**: changing feature computation before the run would have changed what the run
measured. Three candidate fixes are recorded in FAILURES.md.

**F-048, found during this analysis** — agent identities are `sha256(seed:'agent':index)`,
positional with no archetype in them, so two runs on one seed with different archetype mixes
reuse the same `agent_id` for different archetypes. Joining `decision_records` to a manifest
on `agent_id` merged one run's rows into the other's labels and reported `compromised` at
43.3% when its rate in its own run was 18.8%. The analysis now joins on `decision_id`, which
names the exact row an attempt produced. **The wrong number looked completely reasonable**,
which is the only reason it is worth writing down.

### A defect in the held-out agent itself, found after the run

**F-049.** The held-out session's own test suite ran for the first time when the branch was
merged — it could not have run earlier — and one assertion failed:
`compromised`'s resale-share ramp is not monotone on seed 17. The archetype is specified as
ramping through a probing window rather than flipping, and on that seed the probing phase sits
below the ordinary phase.

**It did not touch these numbers.** All four seeds the run used — `20260901008` through
`20260901011` — ramp monotonically, checked explicitly:

```
index 8   ordinary=0.136  probing=0.290  extraction=0.898
index 9   ordinary=0.182  probing=0.419  extraction=0.864
index 10  ordinary=0.255  probing=0.355  extraction=0.847
index 11  ordinary=0.255  probing=0.387  extraction=0.881
```

**The agent is deliberately not fixed**, for the same reason F-045 is not: it ran, and this
document reports what it did. It is marked `xfail(strict=True)` on that one seed, so the
assertion stays live everywhere else and turns red again the moment somebody does fix it.

That the failure is readable at all is a consequence of the held-out session's discipline: it
wrote behavioural assertions about its own agents and nothing whatsoever about whether the
model catches them. A test asserting "the detector flags `sleeper`" would have closed exactly
the loop the isolation exists to prevent.

### The traffic is synthetic and we wrote it

Unchanged from `DEFENSE.md` entry 8 and restated because this document contains accuracy
figures: every archetype here is one we invented. The held-out pair narrows that — two of the
six were invented without sight of the thing measuring them — and it does not eliminate it.

---

## What we would do next, and what we would not

**Would not:** retrain on this result. The held-out set is spent. Tuning against it converts
it into a validation set and there is no second one.

**Would**, in order:

1. **Add within-agent baseline deviation features.** The single largest finding here is that
   thirteen window aggregates cannot express "this agent stopped behaving like itself", which
   is what both held-out archetypes are. Ticket size against the agent's own running median is
   the obvious first one, and the fraud baseline demonstrates it works.
2. **Stop treating regularity as adversarial.** `inter_arrival_variance` at 68% of gain is an
   artifact of having written exactly one regular agent and made it a criminal. The fix is
   more legitimate regular agents in the training traffic, not a smaller weight.
3. **Fix F-045 properly** — a presence indicator per optional feature, which needs retraining
   and is therefore a post-evaluation change.
4. **Make agent identities carry their archetype** (F-048), so a rerun with a different mix
   cannot relabel history.
5. **Fix `compromised`'s ramp** (F-049) — and regenerate nothing that this document reports.

---

## The claim this evaluation does and does not support

It does **not** support "our model detects compromised agents". On the two archetypes it had
never seen, the model scored 18.8% and 92.2%, and the second figure is 90% false confidence
about an agent doing nothing wrong.

It **does** support the architecture. The arithmetic gate refused 495 requests with
`risk_score` NULL on every record — the model was never consulted and the record proves it.
The money invariant held above its watermark. The chain verified. The injection detector
caught 10/10 held-out payloads with zero false positives including the adversarial lookalike.
No language model was reachable from the request path.

**That separation is the point of the design and this run is the strongest evidence for it in
the project.** The model was wrong about two archetypes in two different directions, and not
one rupee moved that a mandate had not authorised, because nothing about spending authority
was ever the model's to decide.
