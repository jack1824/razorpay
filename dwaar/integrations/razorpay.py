"""Razorpay test mode, behind a mode switch.

── The amount is bounded by the RESERVATION, never by the request ──────────────────────

This is the only load-bearing line in the file.

The request says what the agent asked for. The ledger reservation says what the principal's
mandate actually permitted after the cap, the category rules and the remaining balance were
applied — and those can differ, most obviously when the policy engine returns `bound` and
reduces the amount.

Creating an order for the requested amount would mean the enforcement decided one number and
the money moved on another. Every control upstream of this file would still be correct, every
test would still pass, and the merchant would be charged the amount the agent asked for. The
gap between "we decided" and "we did" is where an authorization layer stops being one.

So `create_order` takes a `ReserveResult` and not an amount, and there is no parameter for
passing the request's figure. `tests/db/test_razorpay.py` drives a bounded decision through
the pipeline and asserts the order carries the bounded number.

── Modes ───────────────────────────────────────────────────────────────────────────────

    live_test   real HTTP to api.razorpay.com in TEST mode, with test keys from the
                environment. Real API, no real money.
    stub        recorded-shape responses, generated locally.

Stub is the default, and it is the default because the keys are read from the environment and
may not be there. **A stub response is marked `simulated: true` and the console renders a
SIMULATED badge from that field**, which is a demo safety net rather than a nicety: the
failure it prevents is standing in front of judges describing a stub as a live integration.
The badge comes from the response, so it cannot be forgotten — there is no separate flag
anyone has to remember to set.

── Credentials ─────────────────────────────────────────────────────────────────────────

`RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` come from the environment via `Settings`, never
from source, and `.env` is gitignored. `live_test` mode with no key configured is an ERROR
rather than a silent downgrade to stub: silently falling back is how a demo ends up
reporting simulated results while everyone believes the real API is being called.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from dwaar.db.repositories.budget_ledger import ReserveResult
from dwaar.logging import get_logger
from dwaar.money import Paise

log = get_logger("dwaar.razorpay")

API_BASE = "https://api.razorpay.com/v1"

Mode = Literal["live_test", "stub"]


class RazorpayError(Exception):
    """A call failed. Never swallowed: the reservation is already committed at this point,
    so a silent failure would leave budget held against an order that does not exist."""


class RazorpayNotConfigured(RazorpayError):
    """`live_test` was requested and no key is present.

    Deliberately an error rather than a fallback to stub. A demo that quietly downgrades is
    a demo that reports simulated results while everyone in the room believes otherwise.
    """


@dataclass(frozen=True)
class Order:
    order_id: str
    amount_paise: Paise
    currency: str
    receipt: str
    status: str
    simulated: bool
    """True when this came from stub mode. The console reads THIS field to render its
    SIMULATED badge — not a separate config flag, so it cannot be left stale."""

    requested_paise: Paise | None = None
    """What the agent asked for, when it differs from what was created. Kept so a record
    shows the clamp happened rather than merely showing the final number."""

    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def was_clamped(self) -> bool:
        return (
            self.requested_paise is not None
            and self.requested_paise != self.amount_paise
        )


class RazorpayClient:
    """Test-mode Orders and Payment Links.

    Constructed once at startup. Holds no mutable state, so it is safe to share across the
    request path.
    """

    def __init__(
        self,
        *,
        mode: Mode = "stub",
        key_id: str | None = None,
        key_secret: str | None = None,
        timeout_seconds: float = 8.0,
    ) -> None:
        self.mode: Mode = mode
        self._key_id = key_id
        self._key_secret = key_secret
        self._timeout = timeout_seconds

        if mode == "live_test" and not (key_id and key_secret):
            raise RazorpayNotConfigured(
                "RAZORPAY_MODE=live_test but RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET are not "
                "set. Put them in .env (which is gitignored) — never in source. Falling "
                "back to stub silently is not an option: it would report simulated results "
                "while everyone believes the API was called."
            )
        if mode == "live_test" and not str(key_id).startswith("rzp_test_"):
            # A live key in a project that generates deliberately abusive traffic is the one
            # mistake with a real-money consequence, so it is refused rather than warned about.
            raise RazorpayNotConfigured(
                f"RAZORPAY_KEY_ID does not look like a TEST key (expected rzp_test_ prefix, "
                f"got {str(key_id)[:8]!r}). This repository drives adversarial traffic; it "
                "must never hold a live key."
            )

    @property
    def simulated(self) -> bool:
        return self.mode == "stub"

    # ── orders ──────────────────────────────────────────────────────────────────────

    async def create_order(
        self,
        reservation: ReserveResult,
        *,
        receipt: str,
        requested_paise: Paise | None = None,
        notes: dict[str, str] | None = None,
    ) -> Order:
        """Create an order for exactly what the ledger reserved.

        Takes a `ReserveResult` rather than an amount, and there is deliberately no
        parameter for the requested figure other than for the record. The amount is derived:

            amount = balance_before - balance_after

        which is the reservation's own arithmetic and cannot disagree with the ledger,
        because it IS the ledger. An `amount_paise` parameter would be a place for the
        request's number to get back in.
        """
        amount = reservation.balance_before - reservation.balance_after
        if amount <= 0:
            raise RazorpayError(
                f"reservation {reservation.entry_id} reserved {amount} paise; an order "
                "cannot be created for a non-positive amount"
            )
        if requested_paise is not None and requested_paise < amount:
            # The clamp may only ever reduce. If the reservation exceeds the request, some
            # arithmetic upstream is wrong and charging the larger figure would be the worst
            # possible way to find out.
            raise RazorpayError(
                f"reservation is {amount} paise against a request of {requested_paise}. "
                "A bound may only reduce an amount; refusing to create an order for more "
                "than was asked."
            )

        payload = {
            "amount": amount,
            "currency": "INR",
            "receipt": receipt[:40],
            "notes": {k: str(v)[:250] for k, v in (notes or {}).items()},
        }

        if self.mode == "stub":
            body = _stub_order(payload)
        else:
            body = await self._post("/orders", payload)

        return Order(
            order_id=body["id"],
            amount_paise=int(body["amount"]),
            currency=body.get("currency", "INR"),
            receipt=body.get("receipt", receipt),
            status=body.get("status", "created"),
            simulated=self.mode == "stub",
            requested_paise=requested_paise,
            raw=body,
        )

    async def create_payment_link(
        self,
        reservation: ReserveResult,
        *,
        description: str,
        reference_id: str,
    ) -> Order:
        """Same bound, different collection surface."""
        amount = reservation.balance_before - reservation.balance_after
        if amount <= 0:
            raise RazorpayError("cannot create a payment link for a non-positive amount")

        payload = {
            "amount": amount,
            "currency": "INR",
            "description": description[:255],
            "reference_id": reference_id[:40],
        }
        body = (
            _stub_payment_link(payload)
            if self.mode == "stub"
            else await self._post("/payment_links", payload)
        )
        return Order(
            order_id=body["id"],
            amount_paise=int(body["amount"]),
            currency=body.get("currency", "INR"),
            receipt=reference_id,
            status=body.get("status", "created"),
            simulated=self.mode == "stub",
            raw=body,
        )

    # ── transport ───────────────────────────────────────────────────────────────────

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        import httpx  # noqa: PLC0415 — deferred; stub mode must not need the dependency

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{API_BASE}{path}",
                    json=payload,
                    auth=(self._key_id or "", self._key_secret or ""),
                )
        except Exception as exc:  # noqa: BLE001
            raise RazorpayError(f"{type(exc).__name__} calling {path}") from exc

        if response.status_code >= 400:
            # The body may echo request fields; the STATUS is logged and the body is not,
            # because the log allowlist is a control and an upstream error string is exactly
            # the free-form text it exists to keep out.
            log.error("razorpay_error", path=path, status_code=response.status_code)
            raise RazorpayError(f"razorpay returned {response.status_code} for {path}")
        return response.json()


# ── webhooks ────────────────────────────────────────────────────────────────────────


def verify_webhook_signature(body: bytes, signature: str, secret: str) -> bool:
    """HMAC-SHA256 over the raw body, compared in constant time.

    Over the RAW bytes, not a re-serialisation: JSON round-tripping reorders keys and
    changes whitespace, and the signature is over what was sent. This is the same reason
    `decision_records` stores `canonical_json` rather than rebuilding it.
    """
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def webhook_idempotency_key(event_id: str) -> str:
    """Namespaced, like every other key that reaches the ledger.

    Razorpay's `x-razorpay-event-id` is the delivery identifier and a retry reuses it, which
    is what makes duplicate delivery absorbable. Prefixed for the same reason agent-supplied
    keys are (F-017): an unprefixed external identifier shares a namespace with our own
    derived keys, and a collision there silently no-ops a real ledger entry.
    """
    return f"rzp:{event_id}"


# ── stub responses ──────────────────────────────────────────────────────────────────
#
# Shaped like the real ones and marked. `simulated: true` travels in the response body so the
# console renders its badge from data rather than from configuration — a badge driven by a
# config flag is a badge that is wrong the first time someone changes the flag.


def _stub_order(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"order_STUB{uuid.uuid4().hex[:10]}",
        "entity": "order",
        "amount": payload["amount"],
        "amount_paid": 0,
        "amount_due": payload["amount"],
        "currency": payload["currency"],
        "receipt": payload["receipt"],
        "status": "created",
        "notes": payload["notes"],
        "simulated": True,
    }


def _stub_payment_link(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"plink_STUB{uuid.uuid4().hex[:10]}",
        "entity": "payment_link",
        "amount": payload["amount"],
        "currency": payload["currency"],
        "description": payload["description"],
        "reference_id": payload["reference_id"],
        "short_url": "https://rzp.io/i/STUBLINK",
        "status": "created",
        "simulated": True,
    }


def stub_webhook(event: str, *, event_id: str, order_id: str, amount_paise: int) -> bytes:
    """A webhook body for the duplicate-delivery test. Bytes, because the signature is over
    bytes and a test that signs a re-serialisation is testing something else."""
    return json.dumps(
        {
            "entity": "event",
            "event": event,
            "contains": ["payment"],
            "payload": {
                "payment": {
                    "entity": {
                        "id": f"pay_STUB{uuid.uuid4().hex[:8]}",
                        "order_id": order_id,
                        "amount": amount_paise,
                        "status": "captured",
                    }
                }
            },
            "created_at": 0,
            "simulated": True,
            "event_id": event_id,
        },
        separators=(",", ":"),
    ).encode()
