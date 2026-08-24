"""Score bands. A separate module so that depending on them costs nothing.

`dwaar/policy/baseline.py` expresses the bands as rules and must therefore know the
numbers. Importing them from `dwaar/risk/model.py` would drag numpy — and, on the first
attempt to score, ONNX Runtime — into the policy engine's import closure, for two floats.

Keeping them here means there is still exactly one definition, which is the property that
matters: the model's own `band` field, the rule that actually decides, and anything the
console renders all read the same constants and cannot drift into a demo that asserts
"deny above 0.80" while the rule says 0.85.
"""

from __future__ import annotations

#: Below this a score is not evidence of anything.
STEP_UP_BAND = 0.55

#: Above this the request is refused.
#:
#: The boundaries are inclusive at the bottom: exactly 0.80 is a step-up, not a deny. Stated
#: because "> 0.80 → deny" leaves the boundary undefined, and an undefined boundary in a
#: money decision is a bug waiting for a round number.
DENY_BAND = 0.80


def band_for(score: float | None) -> str:
    """`None` is not a low score. It means the model was never consulted, and the caller
    must not read it as a permit that the model agreed with."""
    if score is None:
        return "not_scored"
    if score < STEP_UP_BAND:
        return "permit"
    if score <= DENY_BAND:
        return "step_up"
    return "deny"
