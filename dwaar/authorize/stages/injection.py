"""Stage 3.5 — instruction-shaped content in agent-supplied free text.  [REAL, pure]

Budget well under 1ms. Eleven arithmetic features and a dot product; no session, no I/O.
**Fails to RULES-ONLY**, never to silence — see below.

── Why this is its own stage and not part of stage 4 ───────────────────────────────────

The risk scorer takes a feature vector and nothing else. That is asserted by
`tests/risk/test_feature_leakage.py::test_the_scorer_cannot_receive_a_request`, and it is
what makes a stored row replayable: anyone with the bundle can recompute the score from
`decision_records.features` alone.

Injection detection needs the raw text. Folding it into stage 4 would have handed the scorer
the request, and the first casualty would have been that replay property — followed by the
claim that the behavioural model is not an injection target.

So the text goes to a component that produces a boolean and never a score, and the scorer
keeps seeing numbers.

── `injection_flag` is a TRISTATE and this stage is what makes it one ──────────────────

    NULL   this stage did not run
    false  it ran and found nothing
    true   it ran and found something

Before migration 0014 the column was `NOT NULL DEFAULT false`, so every record written
before the detector existed claimed *"we looked and found nothing"* about a check that had
never happened. A reader could only tell by noticing `detect_injection` was absent from
`stages_executed` — a fact inferred by correlating two columns rather than one the record
states, which is F-016 wearing a different costume.

An empty `free_text` is `false`, not NULL. The detector ran; there was nothing to read. That
is a different fact from not running, and the record keeps them apart.

── Fail behaviour ──────────────────────────────────────────────────────────────────────

There is no "detector unavailable" state that produces NULL. If the fitted weights are
missing the named rules still run — the base64 decode, the delimiter break, the explicit
override phrase — because those need no artifact and are the highest-precision signals in
the set. Losing them because a JSON file was absent would be the worst possible trade.

What the record carries in that case is `injection_degraded`: the check happened, and it was
the smaller check. That is a third thing again, and it belongs in `degraded_mode` rather than
in the flag.
"""

from __future__ import annotations

from typing import Any

from dwaar.authorize.types import AuthorizeRequest, InjectionResult

DEGRADED_TOKEN = "injection_degraded"
STAGE_NAME = "detect_injection"


def detect_injection(
    request: AuthorizeRequest, *, detector: Any | None
) -> InjectionResult:
    if detector is None:
        # Only reachable when nothing was wired in at all. The application always supplies
        # one — `load()` never returns None precisely so this cannot happen by accident —
        # so this is the in-process caller's path, and it must report NOT CHECKED rather
        # than clean.
        return InjectionResult(
            ok=True,
            flagged=None,
            degraded=DEGRADED_TOKEN,
            internal_reason="no_detector",
        )

    verdict = detector.inspect(request.free_text)
    return InjectionResult(
        ok=True,
        flagged=bool(verdict.flagged),
        confidence=verdict.confidence,
        matched_pattern=verdict.matched_pattern,
        model_version=getattr(detector, "model_version", None),
        degraded=DEGRADED_TOKEN if verdict.degraded else None,
        internal_reason=verdict.degraded,
    )
