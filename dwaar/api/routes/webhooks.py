"""POST /webhooks/razorpay — settlement outcomes, delivered more than once.

── Duplicate delivery is the normal case, not the error case ───────────────────────────

Razorpay retries a webhook until it gets a 2xx, and a delivery that succeeded but whose
response was lost is retried anyway. So the same event arrives twice routinely, and the
integration that treats the second delivery as an error is the integration that pages someone
at 3am about the network working correctly.

Absorbing it is the same shape as `reserve()`: a namespaced idempotency key and a database
constraint, so that "already processed" is a fact the storage layer establishes rather than
something the application remembers.

The key is `rzp:<event-id>` — prefixed, for the reason F-017 exists. An unprefixed external
identifier shares a namespace with our own derived keys, and a collision there silently
no-ops a real ledger entry.

── Why the signature is checked over RAW BYTES ─────────────────────────────────────────

`hmac(secret, request.body)` over exactly what arrived. Not over a re-serialisation of the
parsed JSON: `json.dumps(json.loads(x))` reorders keys and changes whitespace, and the
signature covers what was sent. This is the same reason `decision_records` stores
`canonical_json` instead of rebuilding it on read.

Getting this wrong produces an integration that works in testing — where the round trip
happens to be identity — and fails against the real sender.

── Fail-closed, and what that means here ───────────────────────────────────────────────

No configured secret means every webhook is REJECTED, not accepted-with-a-warning. A webhook
endpoint that accepts unsigned bodies is an unauthenticated way to move a merchant's ledger,
and it is reachable from the internet by definition.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from dwaar.integrations import razorpay
from dwaar.logging import get_logger

log = get_logger("dwaar.api.webhooks")

router = APIRouter()

SIGNATURE_HEADER = "x-razorpay-signature"
EVENT_ID_HEADER = "x-razorpay-event-id"


@router.post("/webhooks/razorpay", include_in_schema=True)
async def razorpay_webhook(request: Request):
    """Settlement outcome for a reservation. Idempotent by construction.

    Always returns 200 once the signature verifies, including for a duplicate. A non-2xx on
    a duplicate would make the sender retry it forever.
    """
    raw = await request.body()
    settings = request.app.state.settings
    secret = settings.razorpay_webhook_secret

    if not secret:
        log.error("webhook_rejected", reason_code="no_secret_configured")
        return JSONResponse(
            {"reason_code": "unavailable"},
            status_code=503,
        )

    signature = request.headers.get(SIGNATURE_HEADER, "")
    if not razorpay.verify_webhook_signature(raw, signature, secret):
        log.warning("webhook_rejected", reason_code="signature_invalid")
        return JSONResponse({"reason_code": "signature_invalid"}, status_code=401)

    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        return JSONResponse({"reason_code": "malformed"}, status_code=400)

    # The delivery identifier, which a retry REUSES — that reuse is what makes duplicate
    # delivery absorbable at all. Falling back to the body's own field so a sender that
    # omits the header is still idempotent rather than silently double-counting.
    event_id = request.headers.get(EVENT_ID_HEADER) or event.get("event_id")
    if not event_id:
        log.warning("webhook_rejected", reason_code="no_event_id")
        return JSONResponse({"reason_code": "malformed"}, status_code=400)

    key = razorpay.webhook_idempotency_key(event_id)
    kind = event.get("event", "unknown")

    async with request.app.state.pool.connection() as conn:
        await conn.set_autocommit(False)
        applied = await _apply(conn, kind=kind, key=key, event=event)
        await conn.commit()

    log.info("webhook", event_type=kind, applied=applied)
    return {"status": "ok", "applied": applied, "duplicate": not applied}


async def _apply(conn, *, kind: str, key: str, event: dict) -> bool:
    """Record the outcome. Returns False when this delivery was a duplicate.

    Settlement does not currently move the ledger: a reservation is already deducted at
    authorize time, so a successful capture confirms what was reserved rather than changing
    it. What a FAILED payment should do — release the reservation with a compensating entry —
    is deliberately not implemented yet, because doing it wrong is worse than not doing it:
    releasing against the wrong reservation would hand budget back that was genuinely spent.

    So this records the delivery and its idempotency, which is the part the duplicate test
    is about, and the release path lands with the settlement work it belongs to.
    """
    from dwaar.db.repositories.base import fetch_one

    row = await fetch_one(
        conn,
        "INSERT INTO webhook_deliveries (idempotency_key, event_type, payload) "
        "VALUES (%s, %s, %s) "
        "ON CONFLICT ON CONSTRAINT webhook_deliveries_idempotency_key_key DO NOTHING "
        "RETURNING delivery_id",
        (key, kind, json.dumps(event, separators=(",", ":"))),
    )
    # A NAMED conflict target, like the ledger's. A bare `ON CONFLICT DO NOTHING` would
    # absorb every future constraint on this table as well, including ones added to catch
    # something — see DEFENSE.md entry 1.
    return row is not None
