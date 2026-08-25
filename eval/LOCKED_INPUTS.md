# Locked inputs — 31 August 2026

**Recorded before the held-out agents were run. Nothing below may change afterwards.**

The reason this file exists is narrow and it is not bookkeeping. A held-out result is
only evidence if the thing being tested was fixed before the test. If the model, the
thresholds, the policy or the feature code moved after the agents ran, the number that
comes out measures nothing — and no write-up can repair that, because a reader has no
way to tell from the outside. The hashes are what let them tell.

Every figure here is computed at run time by `tools/lock_inputs.py`. None is typed.

## Code

| | |
|---|---|
| `main` at lock time | `e4a47b7ad75f2bf3da7d0e35fb54247c2162eaa5` |
| `held-out` at lock time | `c03c11c9cc8fef57ca8a91191e67041f5885ec1f` |
| working tree clean | `no` |
| schema migration | `0018` |

## Model

| | |
|---|---|
| risk model version | `risk-0.1.0-e990ef33c5b6` |
| feature names | 13, ordered as in `dwaar/risk/features.py` |
| injection model version | `inj-0.1.0-249870e22da1` |

### Bundle hashes

```
72b22654ff0a0526aca6db3ca9d6526c578e43adc6a58e44bc1417617877d832  models/injection/weights.json
a09f7cbc8d5efa1d71d67b72a1bc3b5b2b518f8430d0469cbe2be5a448f6bf1a  models/risk/anomaly.onnx
cf1ea151459adcee6c989a6bbd4158b4a86b82b2446913a4ec3de9f978375cf2  models/risk/bundle.json
c2394df22ab9e37944b1c84734d66a4a4143058a798a8b35e74f25c965455e42  models/risk/supervised.onnx
```

## Data and seeds

| | |
|---|---|
| TRAFFIC_SEED (training) | `20260828` |
| EVAL_SEED (measurement) | `20260901` |
| approved policies | 24, max version 1 |
| decision_records at lock time | 49,804 |

## What this pins, and what it does not

It pins the artifacts a score is a function of: the two ONNX graphs, the feature ordering
they were fitted against, the calibration breakpoints, and the code that computes the
vector. Replaying any stored row against this bundle reproduces its `risk_score` exactly —
which is the property that makes a record evidence rather than an assertion.

It does not pin the traffic. The held-out agents are seeded and their request streams are
reproducible, but the rolling windows they build up are wall-clock dependent, so a re-run
produces similar rather than identical numbers. That is a property of the measurement and
is stated rather than hidden — see F-044 for what happens when it is not.
