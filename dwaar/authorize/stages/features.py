"""Stage 3 — behavioural feature computation.  [REAL, pure, synchronous]

Budget 2ms; measured well under it, because by the time this runs the I/O has already
happened. **Degrades**: losing behavioural context costs judgment, never authority.

── Three things this stage cannot do, by signature ─────────────────────────────────────

It does not receive the mandate. It does not receive a database connection. It does not
receive a Redis client.

Without the mandate it cannot encode what the arithmetic gate already decided — no feature
can restate the per-transaction cap, the category lists or the expiry, because none of them
are reachable from here. Without a connection or a client it cannot reach authority state by
another route, and it cannot fail for a reason that has nothing to do with the request.

`dwaar/risk/features.py` explains why that matters. `tests/risk/test_feature_leakage.py`
proves the wiring still honours it, by holding a request stream fixed, varying the mandate's
caps and category lists across the gate boundary, and asserting the vector does not move.

The rolling window is read and appended to by the pipeline at step 2.2, *before* the gate,
so the window is not conditioned on the gate's own decision. That ordering is explained in
`dwaar/authorize/pipeline.py` and it is the reason this stage has nothing left to await.

── What lands in the record ────────────────────────────────────────────────────────────

`features` is written into an append-only, hash-chained row that can never be purged, so it
holds **numerics only**. No SKU strings, no free text, no card BINs — the observation store
hashes those before they are counted, and this stage never handles the raw values. Threat
14's stated recovery is "rotate, purge", and purge is impossible by construction on that
table.

── Degradation ─────────────────────────────────────────────────────────────────────────

An unavailable window produces an all-zero vector and the token `features_degraded`. Zeros
are not neutral — a zero velocity reads as a quiet agent — and that is acceptable only
because the model downstream can exclusively tighten. An over-benign score cannot grant
anything the gate, the policy and the ledger have not already permitted.
"""

from __future__ import annotations

from dwaar.authorize.types import AuthorizeRequest, FeatureResult
from dwaar.risk import features as featuremod
from dwaar.risk import observations as obsmod

#: Emitted only when the window could not be read. This stage is no longer a stub, so the
#: token names a runtime condition rather than an unimplemented component.
DEGRADED_TOKEN = "features_degraded"
STAGE_NAME = "compute_features"


def compute_features_from_window(
    request: AuthorizeRequest,
    window: obsmod.WindowSnapshot,
    now: float,
) -> FeatureResult:
    if not window.available:
        return FeatureResult(
            ok=True,
            degraded=DEGRADED_TOKEN,
            features=featuremod.empty(),
            internal_reason="observation_window_unavailable",
        )

    current = obsmod.observation_from_request(request, now=now)
    return FeatureResult(
        ok=True,
        degraded=None,
        features=featuremod.compute(current, window, now=now),
        internal_reason=None,
    )
