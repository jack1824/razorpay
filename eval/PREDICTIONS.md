# Registered predictions

**Written 28 August 2026. The held-out archetypes have not been run against the model, and
at the time of writing they have not been implemented.**

The point of this file is its commit timestamp. A prediction registered before the result is
evidence; the same sentence written afterwards is a rationalisation, and a reader cannot tell
them apart unless the history does it for them.

Whatever these resolve to, they are reported. A prediction that is only published when it
comes true is not a prediction.

---

## The open question

`make eval` prints the model's feature importances and raises an alarm on any single feature
above 40% of total gain. It currently fires:

```
inter_arrival_variance     0.683
price_probe_score          0.132
cart_mutation_rate         0.101
session_duration_s         0.030
velocity_1m                0.021
```

Two readings, and **both are true at once**, which is exactly why the number alone cannot
settle it:

1. **It is the modelled signal.** `10_SIMULATION/SIMULATION.md` says outright that machine
   regularity is itself a tell — a card tester firing on a loop is more *predictable* than a
   human-driven shopper, and low inter-arrival variance is what predictability looks like
   numerically. If that is right, the feature is doing the job it was designed to do.

2. **It is partly our convention.** The card tester's gap distribution is
   `0.15 + Exponential(mean 0.10)` because that is what was written; the legitimate shopper's
   is `Exponential(mean 4s)` with 25-second session breaks. The variance differs by orders of
   magnitude *by construction*. F-030 was precisely this shape — a feature at 74% of gain
   that turned out to describe how the agents were coded rather than how agents behave.

The leakage gate does not settle it either. `inter_arrival_variance` scored Cramér's V 0.665
against a 0.75 threshold — informative, not identifying, which is what a good feature looks
like and also what a mild convention looks like.

**The held-out run on 31 August is the experiment that separates them.** `compromised` and
`sleeper` are written in a session with no sight of the feature list, no thresholds, and no
access to `dwaar/risk/`. Their timing is chosen for behavioural reasons rather than to match
or avoid ours. That is what makes them a test of the feature rather than of the fixture.

---

## Prediction 1 — held-out recall

**If `inter_arrival_variance` is a real behavioural signal:** at least one held-out archetype
is caught at a rate **meaningfully above the legitimate base rate**, which is currently 0.8%
of legitimate records above the deny band. Concretely: **≥ 40% of post-defection records for
at least one of `compromised` or `sleeper`**, at the deny band.

**If it is largely our convention:** **< 15%**, and concentrated in whichever archetype
happens to share our timing habits rather than spread across both.

**Between 15% and 40%** is a real outcome and not a hedge. It would say the feature carries
some signal that transfers and a lot that does not, and the conclusion would be that the
importance ranking overstates it — which is the answer that most changes what we would do
next.

## Prediction 2 — which component does the work

The supervised half is a binary classifier trained on four archetypes. It has no mechanism
for recognising a fifth; it can only force an unfamiliar agent toward whichever known class
it sits nearest. The anomaly half never saw an adversary during training and scores distance
from normal.

**On in-distribution held-out AGENTS, the supervised half is ahead** — measured, from the
current bundle:

| component | AUC | precision | recall | FPR |
|---|---|---|---|---|
| supervised | 0.9787 | 1.000 | 0.8824 | 0.0000 |
| anomaly | 0.8747 | 0.9938 | 0.7195 | 0.0052 |
| combined | 0.9784 | 0.9949 | 0.8869 | 0.0052 |

**Prediction: on held-out ARCHETYPES the ordering flips.** Anomaly recall exceeds supervised
recall on `compromised` and `sleeper`.

This is the sharper of the two predictions because it is the one I would be most surprised to
be wrong about, and being wrong about it would be more interesting than being right: if the
supervised half generalises to an archetype nobody showed it, that is a finding about the
feature space rather than about the model, and it would suggest the four archetypes span more
of the behavioural manifold than they were designed to.

**"Neither" is a live outcome.** Both components performing near the legitimate base rate on
held-out archetypes is the result the architecture was designed to make visible, and it would
be reported as the headline rather than buried.

## Prediction 3 — the within-agent control

This is the prediction that does not depend on trusting the held-out author, and it is the
one worth reading first.

`sleeper` is clean for a long period and then defects. That gives a **within-agent** test
which controls for authorship convention entirely: the same author, the same file, the same
coding habits, on both sides of the change-point.

**Prediction: `sleeper`'s flag rate is concentrated AFTER its change-point.** Specifically,
its pre-defection flag rate should be within a factor of ~3 of the legitimate base rate, and
its post-defection rate should be several times higher.

**If `sleeper` is flagged at a roughly uniform rate from its very first request**, the model
is keying on something about how that agent was written rather than on what it did — and that
is strong evidence for the convention reading of `inter_arrival_variance`, independent of
what Prediction 1 shows.

This is the cleanest experiment available, because a convention cannot change halfway through
one agent's run and a behaviour can.

## Prediction 5 — the `bin_diversity` confound (added 31 August, before the run)

Registered late and registered anyway, because the alternative is explaining it afterwards.

**The mechanism.** F-045: a request carrying no `instrument_bin` produces `bin_diversity = 0`.
Every request in the training traffic carried a card, so the fitted isolation forest has never
seen that value and reads a fabricated 0 as an extreme observation. Measured, on the current
bundle, for an otherwise identical first request:

```
no card:    risk 0.7054   anomaly 0.7054   -> step_up
with card:  risk 0.2999   anomaly 0.1489   -> permit
```

The defect is in the feature layer, not the model. `to_vector()` fills every slot, so a
feature that was never *measured* becomes a 0 that reads as a measurement of zero — the exact
distinction `to_natural()` exists to preserve on the rules side.

**The prediction.** If `compromised` or `sleeper` issue **payouts, refunds, or purchases
without an instrument**, their anomaly scores will be inflated for a reason that has nothing
to do with their behaviour, and held-out recall will look **better than it is**. The
confounded records are identifiable exactly: `features->>'bin_diversity' = '0'`.

**So the held-out numbers will be reported twice** — once over all records, once excluding
records where `bin_diversity = 0` — and the gap between them is the size of the confound.

**If every held-out request carries a card**, the confound never fires, the two figures are
identical, and we say so. That outcome is as informative as the other and is why this is
written before the numbers are read rather than after.

**This does not get fixed first.** Changing feature computation the day before the run would
change what the run measures, and the run is the only evidence that the model generalises at
all. Three candidate fixes are recorded in FAILURES.md F-045 for afterwards.

**Direction of the bias is stated, which is the part that matters.** It inflates recall on
adversaries and inflates the false-positive rate on legitimate traffic. A confound whose
direction is only worked out after seeing which way the numbers went is not a confound anyone
should believe.

## Prediction 4 — what will NOT move

Stated so that a good result on the above is not allowed to launder into a broader claim.

Whatever happens on the 31st, these are unchanged, because none of them depend on the traffic:

- a per-transaction cap breach denied by arithmetic, with `risk_score` NULL on the record
- fifty concurrent writers against one budget overspending by zero
- a tampered row detected and named by sequence number
- pipeline p99 inside its budget with every stage attributed
- `injection_flag` distinguishing unchecked from checked-and-clean
- no language model reachable from the request path

If the held-out numbers are poor, that is a finding about the **model**, and the model was
never load-bearing for any of the above. If they are good, it does not make the synthetic
accuracy figures transferable. `DEFENSE.md` entry 8 is the standing position either way.

---

## Method

- The held-out agents run against the gateway exactly as deployed, over signed HTTP, on the
  31st. First contact.
- One run, reported. No retraining afterwards, no threshold adjustment, no second attempt.
  Re-running until the number improves is how a held-out set becomes a validation set.
- `make eval` gains a held-out section; the four in-distribution archetypes stay on their own
  line, and the held-out two on theirs.
- The result is written into `eval/RESULTS.md` beside this file, whichever way it goes.

## What would make me discard all of it

If the held-out agents turn out to share the four existing agents' generator conventions —
identical identifier lifetimes, the same fixed-in-`__init__` placeholders — then the held-out
test measures the convention rather than the behaviour and **its result is worthless in both
directions**. That is rule 5 of `zoo/HELD_OUT_SPEC.md` and it is checked before the numbers
are read, not after.
