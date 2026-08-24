"""Stage 4 — behavioural risk score.  [REAL]

Budget 2ms. LightGBM plus an isolation forest, both via ONNX Runtime, both pre-warmed at
startup. **Fail-open**: classification is advisory, and the residual is bounded because the
gate, the policy engine and the ledger all still hold.

── What this stage cannot see ──────────────────────────────────────────────────────────

The feature vector, and nothing else. Not the request, not the mandate, not a connection.

That is deliberate on three counts. It cannot encode an authority decision, because no
authority state reaches it. It cannot read agent-supplied free text, so the scorer is not an
injection target. And a score is reproducible from `decision_records.features` alone —
anyone with the bundle can replay a stored row and get the same number, which is what makes
the score evidence rather than an assertion.

── `risk_score = None` means NOT CONSULTED ─────────────────────────────────────────────

Never `0.0`. A score of 0.0 is a real answer meaning "confidently benign"; conflating it
with "no answer" would destroy the audit-trail claim that a NULL proves the model was never
reached. A per-transaction breach short-circuits at the gate and the row carries NULL; that
is the claim, and it is checkable by anyone reading the record.

── Fail-open, concretely ───────────────────────────────────────────────────────────────

No bundle on disk, a corrupt graph, or an exception during inference all produce
`risk_score=None` with the token `risk_model_unavailable`. The request then proceeds to the
policy engine and the ledger, both of which are unchanged.

The distinguisher between "not consulted" and "consulted and unavailable" is the token and
`stages_executed`, not the NULL — a NULL alone cannot carry three different facts.

── Injection detection is not here yet ─────────────────────────────────────────────────

`injection_flag` is `False` on every record this stage produces, and that is currently a
DEFAULT rather than a finding: the detector lands 28 August. Until then the only honest
reading of a `false` in that column is "nothing checked", and the two things that say so are
`stages_executed`, which does not list a detection stage, and `/health`, which reports the
`injection_detector` component as down with its fail mode.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from dwaar.authorize.types import RiskResult
from dwaar.logging import get_logger

log = get_logger("dwaar.authorize.risk")


@runtime_checkable
class ScorerLike(Protocol):
    """What this stage needs from a scorer, and the whole of it.

    A protocol rather than an import of `dwaar.risk.model` so the request path never pulls
    ONNX Runtime and numpy into its import closure. The scorer is built once at startup in
    `dwaar/api/app.py` and injected; here it is a thing with a `score` method.
    """

    def score(self, features: dict[str, int]) -> object: ...

#: Emitted when the model could not score. The stage is no longer a stub, so this names a
#: runtime condition; there is no longer a token meaning "not built".
DEGRADED_TOKEN = "risk_model_unavailable"
STAGE_NAME = "score_risk"


async def score_risk(
    features: dict[str, int], *, scorer: ScorerLike | None
) -> RiskResult:
    if scorer is None:
        return RiskResult(
            ok=True,
            degraded=DEGRADED_TOKEN,
            risk_score=None,
            model_version=None,
            injection_flag=False,
            internal_reason="no_model_loaded",
        )

    try:
        scored = scorer.score(features)
    except Exception as exc:  # noqa: BLE001 — fail-open is the documented behaviour
        log.warning("risk_scoring_failed", error_type=type(exc).__name__)
        return RiskResult(
            ok=True,
            degraded=DEGRADED_TOKEN,
            risk_score=None,
            model_version=None,
            injection_flag=False,
            internal_reason=f"scoring_failed:{type(exc).__name__}",
        )

    return RiskResult(
        ok=True,
        degraded=None,
        risk_score=scored.risk_score,
        model_version=scored.model_version,
        injection_flag=False,
        internal_reason=None,
        band=scored.band,
        supervised_score=scored.supervised_score,
        anomaly_score=scored.anomaly_score,
        top_features=tuple(
            (f["name"], f["contribution"]) for f in scored.top_features
        ),
    )
