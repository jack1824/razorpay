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
from dwaar.nonce import NonceStoreUnavailable

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

    # Behavioural context. Both are hashed before they are stored and neither reaches the
    # decision record in raw form — BIN *diversity* and cart *mutation* are the signals, and
    # counting distinct things does not require keeping the values.
    #
    # The BIN is six digits and nothing more. A pattern rather than a length check, because
    # "the first six digits of a card number" has a shape, and accepting a full PAN here —
    # which a caller will eventually send by accident — would put a card number into a
    # rolling window and a hash of one into an append-only row.
    instrument_bin: Annotated[str | None, Field(default=None, pattern=r"^[0-9]{6}$")]
    cart_id: Annotated[str | None, Field(default=None, max_length=64)]

    # Create a Razorpay order for the RESERVED amount when the decision permits.
    #
    # Opt-in rather than automatic, for two reasons. It is an outbound HTTP call in
    # `live_test` mode and does not belong in every authorize by default; and collection is
    # a separate concern from authorisation, so making it implicit would blur the line this
    # whole service exists to draw.
    collect: bool = False


class OrderResponse(BaseModel):
    """The created order. `simulated` comes from the RESPONSE BODY, not from configuration.

    The console renders its SIMULATED badge from this field, so the badge cannot be stale:
    there is no separate flag anyone has to remember to flip. The failure that prevents is
    standing in front of judges describing a stub as a live integration.
    """

    order_id: str
    amount_paise: int
    currency: str
    status: str
    simulated: bool
    was_clamped: bool = False
    requested_paise: int | None = None


class DecisionResponse(BaseModel):
    decision: Literal["allow", "bound", "throttle", "step_up", "deny"]
    decision_id: str
    reason_code: str
    latency_us: int
    chain_seq: int
    bounded_amount_paise: int | None = None
    budget_remaining_paise: int | None = None
    retry_after_ms: int | None = None
    order: OrderResponse | None = None


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
        instrument_bin=body.instrument_bin,
        cart_id=body.cart_id,
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
        except (LedgerError, ChainError, NonceStoreUnavailable) as exc:
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

    # AFTER the commit, and only on a permitting decision. The order is created for what the
    # LEDGER reserved, never for what the request asked — see dwaar/integrations/razorpay.py.
    # Outside the transaction because a payment provider being slow must not be able to hold
    # a database transaction open, and outside the pipeline because it is not a decision.
    order = None
    if body.collect and outcome.decision.decision in ("allow", "bound") and outcome.reservation:
        try:
            created = await app.state.razorpay.create_order(
                outcome.reservation,
                receipt=(outcome.record_id or "")[:40],
                requested_paise=body.amount_paise,
                notes={"decision_id": outcome.record_id or "", "agent_id": body.agent_id},
            )
            order = OrderResponse(
                order_id=created.order_id,
                amount_paise=created.amount_paise,
                currency=created.currency,
                status=created.status,
                simulated=created.simulated,
                was_clamped=created.was_clamped,
                requested_paise=created.requested_paise,
            )
            log.info(
                "order_created",
                decision_id=outcome.record_id,
                order_id=created.order_id,
                simulated=created.simulated,
            )
        except Exception as exc:  # noqa: BLE001
            # The reservation is committed and the decision is chained. Reporting the
            # failure and returning the decision is correct: the authorisation genuinely
            # happened, and pretending it did not because a downstream call failed would
            # lose the record of it.
            log.error("order_failed", error_type=type(exc).__name__)

    return DecisionResponse(
        decision=outcome.decision.decision,
        decision_id=outcome.record_id or "",
        reason_code=outcome.decision.reason_code,
        latency_us=outcome.latency_us,
        chain_seq=outcome.seq or 0,
        bounded_amount_paise=outcome.decision.bounded_amount_paise,
        budget_remaining_paise=outcome.budget_remaining_paise,
        retry_after_ms=outcome.decision.retry_after_ms,
        order=order,
    )
