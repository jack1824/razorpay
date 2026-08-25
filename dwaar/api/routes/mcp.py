"""POST /v1/mcp/call — a tool call, authorised before it reaches the vendor.

The whole route is thin on purpose. It resolves nothing, decides nothing and enforces
nothing: it turns a tool call into an `AuthorizeRequest` and hands it to the same pipeline
`/v1/authorize` uses. The scope check lives in the arithmetic gate, so an MCP denial is the
same chained record as any other authority denial, with the same `risk_score = NULL` proving
no model was consulted.

If this file ever grows a rule, that is the signal that a second authorization path is being
built, and two authorization paths is one more than can be kept correct.

── Status codes ────────────────────────────────────────────────────────────────────────

    200  a decision was made. A DENIED tool call is a 200 with `"decision": "deny"`,
         exactly like a denied purchase — the question was answered.
    401  signature invalid. Not chained.
    403  mandate unresolvable. No merchant, so no chain to write to.
    502  the decision was `allow` and the UPSTREAM failed. The reservation is already
         committed at that point, so this is reported rather than swallowed.

── What forwarding means, and does not ─────────────────────────────────────────────────

On `allow` the call is forwarded to the upstream MCP server. In `stub` mode the response is
generated locally and carries `simulated: true`, which the console reads to render its badge.

**An agent holding the raw merchant token does not come through here at all.** Nothing in
this route prevents that and nothing could — see `dwaar/mcp/README.md`. This is an
enforcement point for an agent that was given a mandate instead of a token, which is why the
abstraction belongs in the platform rather than in front of it.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from starlette import status

from dwaar import outbox
from dwaar.authorize import pipeline
from dwaar.authorize.types import AuthorizeRequest
from dwaar.errors import ChainError, LedgerError
from dwaar.logging import get_logger
from dwaar.mcp import proxy, scopes
from dwaar.nonce import NonceStoreUnavailable

log = get_logger("dwaar.api.mcp")

router = APIRouter()

AGENT_ID = r"^agt_[a-z0-9]{12}$"
MANDATE_ID = r"^mnd_[a-z0-9]{12}$"


class ToolCallBody(BaseModel):
    model_config = {"extra": "forbid"}

    agent_id: Annotated[str, Field(pattern=AGENT_ID)]
    mandate_id: Annotated[str, Field(pattern=MANDATE_ID)]
    tool: Annotated[str, Field(min_length=1, max_length=64)]
    arguments: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: Annotated[str, Field(min_length=16, max_length=64)]


class ToolCallResponse(BaseModel):
    decision: str
    decision_id: str
    reason_code: str
    rule_fired: str | None = None
    chain_seq: int
    latency_us: int
    result: dict[str, Any] | None = None
    simulated: bool = False


@router.post(
    "/v1/mcp/call",
    response_model=ToolCallResponse,
    summary="Authorize an MCP tool call against the mandate, then forward it",
)
async def call_tool(body: ToolCallBody, request: Request):
    app = request.app
    request_bytes = await request.body()

    rule = scopes.rule_for(body.tool)
    domain_request = AuthorizeRequest(
        agent_id=body.agent_id,
        mandate_id=body.mandate_id,
        # An unmapped tool has no action to map, and `payout` is the most restrictive
        # reading. It is denied by the gate regardless; this only decides what the record
        # calls it, and guessing optimistically about the direction money moves is the wrong
        # way to be wrong.
        action=proxy.action_for(rule) if rule else "payout",
        amount_paise=_amount_or_zero(body.arguments),
        idempotency_key=body.idempotency_key,
        tool=body.tool,
        tool_arguments=body.arguments,
    )

    async with app.state.pool.connection() as conn:
        await conn.set_autocommit(False)
        try:
            outcome = await pipeline.authorize(
                domain_request,
                conn=conn,
                signer=app.state.signer,
                settings=app.state.settings,
                headers=dict(request.headers),
                body=request_bytes,
                method=request.method,
                path=request.url.path,
                nonce_store=app.state.nonce_store,
                policy_store=app.state.policy_store,
                observation_store=app.state.observation_store,
                scorer=app.state.scorer,
                detector=app.state.detector,
            )
        except pipeline.Unauthenticated:
            await conn.rollback()
            log.warning("mcp_unauthenticated", agent_id=body.agent_id)
            return _error("signature_invalid", status.HTTP_401_UNAUTHORIZED)
        except pipeline.Unresolvable:
            await conn.rollback()
            log.warning("mcp_unresolvable", agent_id=body.agent_id)
            return _error("not_authorized", status.HTTP_403_FORBIDDEN)
        except (LedgerError, ChainError, NonceStoreUnavailable) as exc:
            await conn.rollback()
            log.error("mcp_unavailable", error_type=type(exc).__name__)
            return _error("unavailable", status.HTTP_503_SERVICE_UNAVAILABLE)

        await conn.commit()

    # Announce the record on the outbox. AFTER the commit, best effort, never awaited
    # for a result the caller depends on. `dwaar/outbox.py` is deliberately NOT in
    # `dwaar/explain/` — that package is blocklisted from every request path.
    #
    # A replayed outcome is deliberately NOT republished: a retried request is one decision
    # delivered twice, and a second explanation for one record is a row the table's UNIQUE
    # constraint refuses anyway.
    if not outcome.replayed:
        await outbox.publish(
            getattr(app.state, "redis", None),
            record_id=outcome.record_id or "",
            merchant_id=outcome.merchant_id or "",
            seq=outcome.seq or 0,
        )

    log.info(
        "mcp_call",
        agent_id=body.agent_id,
        mandate_id=body.mandate_id,
        decision=outcome.decision.decision,
        reason_code=outcome.decision.reason_code,
        rule_fired=outcome.decision.rule_fired,
        chain_seq=outcome.seq,
        latency_us=outcome.latency_us,
    )

    result = None
    simulated = False
    if outcome.decision.decision in ("allow", "bound"):
        # Forwarded only after the decision is COMMITTED. A tool call forwarded before the
        # record is durable is a call whose authorisation might not survive a crash — the
        # money would have moved and the evidence would not exist.
        forwarded = await _forward(app, body)
        result, simulated = forwarded, bool(forwarded.get("simulated"))

    return ToolCallResponse(
        decision=outcome.decision.decision,
        decision_id=outcome.record_id or "",
        reason_code=outcome.decision.reason_code,
        rule_fired=outcome.decision.rule_fired,
        chain_seq=outcome.seq or 0,
        latency_us=outcome.latency_us,
        result=result,
        simulated=simulated,
    )


def _amount_or_zero(arguments: dict[str, Any]) -> int:
    """The pipeline needs a non-negative integer. A read-only tool has no amount.

    A malformed amount is reported as zero here and refused by the gate's own scope check,
    which raises on a non-integer. Duplicating that validation would mean two definitions of
    what an amount is.
    """
    try:
        return proxy._amount_from(arguments) or 0
    except ValueError:
        return 0


async def _forward(app, body: ToolCallBody) -> dict[str, Any]:
    """Hand the call to the upstream MCP server.

    Stub mode returns a locally-generated response marked `simulated: true`. The console
    reads that FIELD rather than a config flag, so a badge cannot be stale.
    """
    settings = app.state.settings
    if settings.mcp_upstream_mode != "live":
        return {
            "tool": body.tool,
            "status": "ok",
            "id": f"{body.tool}_STUB{uuid.uuid4().hex[:10]}",
            "simulated": True,
        }

    import httpx  # noqa: PLC0415 — deferred; stub mode must not need the dependency

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(
                settings.mcp_upstream_url,
                json={"tool": body.tool, "arguments": body.arguments},
            )
        response.raise_for_status()
        return response.json()
    except Exception as exc:  # noqa: BLE001
        # The reservation is committed. Reporting the upstream failure is the only honest
        # option: swallowing it would leave budget held against a call that never happened.
        log.error("mcp_upstream_failed", error_type=type(exc).__name__)
        return {"tool": body.tool, "status": "upstream_error", "simulated": False}


def _error(reason: str, code: int) -> Response:
    return Response(
        content=f'{{"reason_code":"{reason}"}}',
        media_type="application/json",
        status_code=code,
    )
