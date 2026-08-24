# Held-out archetypes — build specification

**This file is the whole input to a separate session.** It is written so that the session
implementing `compromised` and `sleeper` needs nothing else: no sight of `dwaar/risk/`, no
feature names, no thresholds, no model.

## Why the isolation exists, and what it is actually worth

Two of the six archetypes are never run against the model during development. Their first
contact is evaluation day, and their numbers are reported on their own line — those are the
numbers worth reading, because every other number in this project describes traffic that was
generated and measured by the same person.

The design called for **different authors**: the person who writes the adversary is not the
person who builds the detector. That is a genuinely strong control, because two people cannot
accidentally share an assumption they never discussed.

What is actually in place is **isolation**: same author, separate session, no access, no
feedback loop. That is strictly weaker, and the same person can independently invent the same
tell twice. Nothing in this repository claims author separation. `DEFENSE.md` entry 8 states
the limitation directly, and it is the honest version.

## Rules for the implementing session

1. **Do not open `dwaar/risk/`.** Not the features, not the model, not the bands. If you
   know what the detector keys on, you will write agents that either trip it or dodge it, and
   either way the held-out result measures your knowledge rather than the system.

2. **Do not open `models/`.** Same reason, with the additional problem that the fitted
   importances are a ranked list of exactly what to avoid.

3. **Do not run these agents against a gateway with a model loaded** until evaluation day.
   Generating traffic is fine — `DWAAR_MODEL_DIR=/nonexistent` — if you need to check that
   the agents work at all. Watching the model's verdicts is not.

4. **Branch, do not merge.** `git checkout -b held-out-archetypes`. The branch is merged on
   evaluation day and not before.

5. **Do not copy the four existing agents' conventions.** This is the addition that came out
   of F-030 and it is the most important rule in this list — see below.

## Rule 5, at length, because it is the one that ruins the result

A previous defect: every adversarial archetype held one cart identifier for its entire run,
because that is how each was written, while the legitimate shopper rotated per session,
because that is what a shopper does. The model gave that single incidental difference 74% of
its total gain. It was not behaviour. It was a coding convention that happened to correlate
perfectly with the label.

If the held-out agents inherit the four existing agents' conventions — the same identifier
lifetimes, the same field-population habits, the same "set it once in `__init__` and never
think about it" placeholders — then **the held-out test measures the convention rather than
the behaviour, and its result is worthless in both directions.** A high score would mean the
model learned our house style. A low score would mean it did not.

Concretely, for every field an agent fills in, ask: *would a real agent of this kind vary
this, and how often?* Then implement that answer, not whatever the file next door does.
Where a field has no behavioural meaning for your archetype, vary it randomly rather than
fixing it — an incidental constant is indistinguishable from a label.

**You may read `zoo/base.py`**, because you have to: it holds the signing, the transport and
the loopback check. Read it for the interface and not for the idioms.

## The two archetypes

Described in behavioural terms only — ticket size, velocity, category, timing. There are
deliberately no feature names here and no thresholds. If a sentence below reads as
under-specified, choose what a real agent of that kind would do; that judgment is the point
of the separation.

### `compromised`

An agent that was legitimate and stopped being legitimate partway through its life.

- Behaves as an ordinary shopping agent for a substantial opening period. Not a token
  warm-up — long enough that its early history is genuinely a normal history.
- Then changes. The change is not a burst of speed; it is a change of **purpose**. Its
  spending moves toward goods that resell easily and convert to cash, and its ticket sizes
  move upward within what its mandate still permits.
- The change is not instantaneous. Someone who has taken over an agent tests the water first.
- It stays inside its mandate throughout. It never breaches a per-transaction cap and never
  requests a forbidden category. **If arithmetic could stop it, it would not be interesting.**
- Expected outcome: escalation to a step-up, then denial, on behaviour alone.

### `sleeper`

An agent that is patient.

- Clean for a long period — the simulation spec says sixty simulated days, and the point is
  that its history is not merely normal but *established*.
- Then defects. The defection should be recognisable as a change-point in its own history
  rather than as an absolute anomaly: at the moment it defects, its behaviour need not look
  unusual for an agent in general, only unusual **for this agent**.
- Consider what a patient adversary does with an established history that a hasty one cannot.
- It stays inside its mandate throughout, for the same reason as above.
- Expected outcome: the change-point is detected and the mandate is revoked.

Both hold valid signatures and valid, unexpired mandates. All six archetypes do. If invalid
credentials were the tell, the problem would be trivial and no model would be needed.

## Mandates

Use `zoo/provision.py` unchanged. Every archetype gets an **identical** mandate — same caps,
same allow list, same deny list, same expiry.

If the held-out agents held different mandates, the mandate would be the label: the gateway
would deny them at different rates for reasons unrelated to behaviour. `tests/zoo/` asserts
the provisioner does not branch on archetype, and that assertion must keep passing.

## What to deliver

```
zoo/agents/compromised.py
zoo/agents/sleeper.py
tests/zoo/test_held_out.py     behavioural assertions only — no model, no features
```

Register both in `zoo/agents/__init__.py` and leave them out of `LEGITIMATE`. Do not add
them to any default in `zoo/run.py`; they are invoked explicitly on evaluation day.

`tests/zoo/test_held_out.py` should assert what the archetypes DO — that `compromised`'s
category mix shifts, that `sleeper` has a change-point, that both stay inside their mandates
throughout, that both are reproducible under a seed. It must not assert anything about
whether the model catches them. That is what evaluation day is for, and a test that asserts
it would be the feedback loop this whole arrangement exists to prevent.

## Why this session did not write them

The session that built `dwaar/risk/` cannot also write the agents held out from it. It has
read every feature, fitted the model, and read the ranked importances — writing the
adversaries afterwards would make "held out" a claim about file organisation rather than
about knowledge, and the resulting numbers would be worth nothing.

That is not a limitation being worked around. It is the control.
