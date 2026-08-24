"""Stage 4 — behavioural risk score and injection check.  [STUB — real on 27 Aug]

Budget 2ms. LightGBM via ONNX. **Fail-open**: classification is advisory, and the residual
is bounded because the ledger still holds.

STUB CONTRACT
    returns risk_score=None, model_version=None, injection_flag=False
    degraded token: "risk_model_stubbed"

`risk_score=None` means **not consulted** — never `0.0`. A score of 0.0 is a real answer
meaning "confidently benign"; conflating it with "no answer" would destroy the audit-trail
claim that a NULL proves the model was never reached.

That does mean a stubbed record and a genuine arithmetic deny both carry NULL. The
distinguisher is `degraded_mode`: a real gate denial has no `risk_model_stubbed` token, and
`stages_executed` does not list this stage at all.

The model can only ever *tighten*. It cannot turn a deny into an allow, at any point, by
construction — nothing downstream of here consults it to grant anything.
"""

from __future__ import annotations

from typing import Any

from dwaar.authorize.types import AuthorizeRequest, RiskResult

DEGRADED_TOKEN = "risk_model_stubbed"
STAGE_NAME = "score_risk"


async def score_risk(request: AuthorizeRequest, features: dict[str, Any]) -> RiskResult:
    return RiskResult(
        ok=True,
        degraded=DEGRADED_TOKEN,
        risk_score=None,
        model_version=None,
        injection_flag=False,
        internal_reason="risk_not_scored_stub",
    )
