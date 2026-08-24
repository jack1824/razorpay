"""Stage 5 — compiled policy evaluation.  [STUB — real on 26 Aug]

Budget 1ms. Deterministic rule DSL, compiled offline by an LLM and human-approved.
**Fail-behaviour**: last signed version continues serving; compilation is a build-time
activity that never touches a request.

STUB CONTRACT
    returns verdict="permit", rule_fired=None, policy_version=0
    degraded token: "policy_stubbed"

`policy_version` semantics, which the record depends on:
    NULL  the policy engine was never consulted (the authority gate short-circuited)
    0     consulted; no approved policy exists for this merchant
    >0    the approved version that decided

Those are three different facts and the audit trail keeps them apart.

Policy is deterministic and **beats the model always**. A low risk score never overturns a
policy deny — see FAIL_MATRIX.md, "conflicting signals".
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dwaar.authorize.types import AuthorizeRequest, PolicyResult, RiskResult

DEGRADED_TOKEN = "policy_stubbed"
STAGE_NAME = "evaluate_policy"

NO_COMPILED_POLICY = 0


async def evaluate_policy(
    request: AuthorizeRequest,
    mandate: Mapping[str, Any],
    risk: RiskResult,
    *,
    conn=None,
) -> PolicyResult:
    return PolicyResult(
        ok=True,
        degraded=DEGRADED_TOKEN,
        verdict="permit",
        rule_fired=None,
        policy_version=NO_COMPILED_POLICY,
        internal_reason="policy_not_evaluated_stub",
    )
