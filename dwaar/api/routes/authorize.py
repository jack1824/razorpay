"""POST /v1/authorize — the hot path.

Status codes follow `openapi.yaml`, and the split is deliberate:

    200  a decision was rendered. allow AND deny are both 200 — a deny is an answer, not
         an error, and it is chained.
    401  signature invalid. Counter and log only, never a chained record.
    403  mandate unresolvable. No merchant, so no chain to write to.
    422  malformed body.
    503  the ledger or the chain is unavailable. Fail-closed.

401 and 403 write nothing to the chain on purpose. An unattributable request is a security
event, not an authorization decision; chaining it would let anyone with an HTTP client
write into the evidence the whole design exists to protect.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field
from starlette import status

from dwaar.authorize import pipeline
from dwaar.authorize.types import AuthorizeRequest
from dwaar.errors import ChainError, LedgerError
from dwaar.logging import get_logger
from dwaar.money import MAX_AMOUNT_PAISE

log = get_logger("dwaar.api.authorize")

router = APIRouter()

AGENT_ID = r"^agt_[a-z0-9]{12}$"
MANDATE_ID = r"^mnd_[a-z0-9]{12}$"


class AuthorizeBody(BaseModel):
    """Constraints ported from the package's `authorize.json`, which is stricter than its
    `openapi.yaml`. The strict one wins: bounds on an untrusted input are not optional."""

    model_config = {"extra": "forbid"}

    agent_id: Annotated[str, Field(pattern=AGENT_ID)]
    mandate_id: Annotated[str, Field(pattern=MANDATE_ID)]
    action: Literal["purchase", "refund", "payout", "payment_link"]
    amount_paise: Annotated[int, Field(ge=1, le=MAX_AMOUNT_PAISE)]
    idempotency_key: Annotated[str, Field(min_length=16, max_length=64)]
    category: Annotated[str | None, Field(default=None, max_length=64)]
    sku: Annotated[str | None, Field(default=None, max_length=128)]
    free_text: dict[str, Annotated[str, Field(max_length=2000)]] = Field(default_factory=dict)


class DecisionResponse(BaseModel):
    decision: Literal["allow", "bound", "throttle", "step_up", "deny"]
    decision_id: str
    reason_code: str
    latency_us: int
    chain_seq: int
    bounded_amount_paise: int | None = None
    budget_remaining_paise: int | None = None
    retry_after_ms: int | None = None


@router.post(
    "/v1/authorize",
    response_model=DecisionResponse,
    responses={
        401: {"description": "Signature invalid or missing (fail-closed). Not chained."},
        403: {"description": "Mandate unresolvable (fail-closed). Not chained."},
        422: {"description": "Malformed request body."},
        503: {"description": "Ledger or chain unavailable — fail-closed."},
    },
    summary="Authorize an agent money action (THE HOT PATH — p99 target 25ms, zero LLM calls)",
)
async def authorize(body: AuthorizeBody, request: Request, response: Response):
    app = request.app
    settings = app.state.settings
    signer = app.state.signer

    request_bytes = await request.body()
    domain_request = AuthorizeRequest(
        agent_id=body.agent_id,
        mandate_id=body.mandate_id,
        action=body.action,
        amount_paise=body.amount_paise,
        idempotency_key=body.idempotency_key,
        category=body.category,
        sku=body.sku,
        free_text=body.free_text,
    )

    async with app.state.pool.connection() as conn:
        await conn.set_autocommit(False)
        try:
            outcome = await pipeline.authorize(
                domain_request,
                conn=conn,
                signer=signer,
                settings=settings,
                headers=dict(request.headers),
                body=request_bytes,
            )
        except pipeline.Unauthenticated:
            await conn.rollback()
            # Threat 1 detection is a counter and a log line, not a chain entry.
            log.warning(
                "authorize_unauthenticated",
                agent_id=body.agent_id,
                mandate_id=body.mandate_id,
                reason_code="signature_invalid",
            )
            response.status_code = status.HTTP_401_UNAUTHORIZED
            return Response(
                content='{"reason_code":"signature_invalid"}',
                media_type="application/json",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        except pipeline.Unresolvable:
            await conn.rollback()
            log.warning(
                "authorize_unresolvable",
                agent_id=body.agent_id,
                mandate_id=body.mandate_id,
                reason_code="not_authorized",
            )
            return Response(
                content='{"reason_code":"not_authorized"}',
                media_type="application/json",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        except (LedgerError, ChainError) as exc:
            await conn.rollback()
            log.error("authorize_unavailable", error_type=type(exc).__name__)
            return Response(
                content='{"reason_code":"unavailable"}',
                media_type="application/json",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        # Stages 6 and 8 shared this transaction. Committing here is what makes "a
        # committed reservation always has a record" true.
        await conn.commit()

    return DecisionResponse(
        decision=outcome.decision.decision,
        decision_id=outcome.record_id or "",
        reason_code=outcome.decision.reason_code,
        latency_us=outcome.latency_us,
        chain_seq=outcome.seq or 0,
        bounded_amount_paise=outcome.decision.bounded_amount_paise,
        budget_remaining_paise=outcome.budget_remaining_paise,
        retry_after_ms=outcome.decision.retry_after_ms,
    )
