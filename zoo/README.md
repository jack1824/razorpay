# zoo/ — agent archetypes for evaluation

**This code targets `localhost` only. It is not a general-purpose attack tool and it must
never be pointed at a host you do not own.** Every agent refuses to run against a
non-loopback target; that check is in `zoo/base.py`, not in this README, because a README is
not a control.

`zoo/` generates evaluation traffic against a local Dwaar instance: agents making **real
signed HTTP calls**, not replayed fixtures.

## Why real requests

Nothing here builds a feature vector or a decision record. The gateway computes its own
features from its own rolling windows, scores them with its own model and writes its own
chain — so a number in the eval table is a fact about the system rather than about the
generator.

It also means the adversarial agents have to actually work. An agent whose Ed25519 signature
does not verify gets a 401 and produces no behavioural evidence at all, which is much harder
to fake accidentally than a plausible-looking CSV.

## Structural rules

`dwaar/` must never import from `zoo/`. Enforced by `tests/test_import_isolation.py`, which
walks the transitive import closure of every `dwaar.*` module and fails the build on any path
reaching `zoo`.

The reverse is permitted and used: `zoo/` imports `dwaar.crypto` so the agents sign the way
the gateway verifies. Correctness against RFC 9421 and RFC 8785 is pinned by known-answer
vectors in `tests/`, not by the two sides agreeing with each other — if both used the same
wrong implementation, shared code would hide it and the vectors would not.

**No archetype label crosses the boundary.** Agent ids are hashes of the run seed; display
names are `zoo-agent-<suffix>`; every archetype holds an identical mandate. The gateway sees
a request and never a label. `tests/test_no_label_leakage.py` asserts it at the request layer
and `tools/train_risk.py` asserts it at the feature layer.

## The four archetypes

| Archetype | Arrival | Amounts | What actually distinguishes it |
|---|---|---|---|
| `legit_shopper` | Exp(mean 4s), diurnal | log-normal around catalogue price | nothing — this is the baseline |
| `card_tester` | Exp(mean 0.25s), low variance | tight uniform, ₹39–99 | machine regularity, BIN diversity, 70% declines |
| `budget_breacher` | Exp(mean 3s) | over the cap, and probing down toward it | caught by arithmetic; the probing is the behavioural part |
| `injector` | Exp(mean 5s) | ordinary | instruction-shaped `free_text`, plus benign lookalikes |

All four sign correctly and hold valid, unexpired mandates. That is deliberate: if invalid
credentials were the tell, the problem would be trivial and no model would be needed.

**`compromised` and `sleeper` are absent.** They are written in a separate session with no
access to `dwaar/risk/`, kept on a branch, not merged, and not run against the model until
evaluation day. Their results are reported on a separate line and those are the numbers worth
reading. See `DEFENSE.md` entry 8 for what that mitigation is and is not worth.

## The 3% that must produce false positives

Roughly 3% of legitimate agents are marked `bursty` and behave, for at least one session,
exactly like something worth stopping: a rapid run of same-category purchases with a second
card.

**These must generate false positives.** A generator whose classes are cleanly separable is a
generator that lies. It would give the model near-perfect scores and would make the one
number this project has committed to reporting honestly — the false-positive cost in rupees —
pure fiction.

The bursty agents are chosen deterministically from the run seed, the actual fraction is
computed and printed at run time rather than asserted, and `tests/zoo/test_traffic.py`
requires the overlap to exist.

## Running it

The gateway must already be running, with PostgreSQL and Redis reachable.

**Start it with no risk model loaded.** This is not optional for a bootstrap run:

```bash
make bootstrap-local                                       # once

# terminal 1 — note DWAAR_MODEL_DIR
DWAAR_MODEL_DIR=/nonexistent .venv/bin/python -m uvicorn dwaar.api.app:app --port 8080

make traffic                                               # terminal 2, ~9 minutes
make train
```

### Why the model must be off while generating training traffic

Training the first model on traffic a model shaped is circular, and the loop is not
hypothetical — it was measured here. A model trained on one run then denied 636 of the next
run's 640 card-testing requests. Denied requests never reach a card, so the simulated PSP
never reported a decline, so `failure_ratio` — the single feature that most directly
describes card testing — came back near zero for card testers. The second model would have
been trained on the first model's blind spot and would have inherited it.

Feature *values* are unaffected: they are computed at stage 3, before any verdict. What a
loaded model changes is which requests reached a card at all, and therefore what the PSP ever
had an opinion about.

`tools/train_risk.py` refuses to train when any training row carries a `model_version`, which
is a fact the gateway recorded rather than a promise the operator made. `--allow-model-shaped`
overrides it, for the case where you are deliberately retraining on production traffic and
have accounted for the selection bias.

`make traffic` writes a run manifest to `data/traffic/<run_id>.jsonl` — one line per attempt
plus a header naming each agent's archetype. `make train` reads feature vectors from
`decision_records` and labels from that manifest, and the two are never in one process.

Flags worth knowing:

```
--legit N --card-tester N --budget-breacher N --injector N   how many of each
--requests N                                                 per agent, scaled per archetype
--seed N                                                     reproduces identities and streams
--base-url http://127.0.0.1:8080                             loopback only
```

A run takes roughly seven minutes at the default size, and the cadences are **not**
compressed. A feature window is wall-clock, so compressing the generator and not the demo
would train the model on velocities it never sees again.

## The simulated PSP

After the gateway allows a request, the runner decides whether the *card* would have been
accepted and writes that outcome to the rolling window. It stands in for the settlement
webhook until Razorpay test mode lands, and is marked `[MOCK PSP]` wherever it appears.

The agent does not report its own outcome. A card tester telling us its decline rate would be
the model asking the adversary for the answer, and `failure_ratio` would become an
agent-controlled feature.

Note what this means for the feature: `failure_ratio` is a **payment** failure ratio, never an
authorization one. A ratio computed over the gateway's own denials would be a direct readout
of the arithmetic gate, and a budget breacher would score 1.0 for a reason the model deserves
no credit for.
