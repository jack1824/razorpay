"""Razorpay: the amount is bounded by the RESERVATION, and duplicates are free.

Two claims, and the first is the one that matters.

An order created for the amount the REQUEST asked for would mean the enforcement decided one
number and the money moved on another. Every control upstream would still be correct, every
other test would still pass, and the merchant would be charged what the agent wanted. The gap
between "we decided" and "we did" is where an authorization layer stops being one.
"""

from __future__ import annotations

import psycopg
import pytest

from dwaar.crypto.signer import ensure_registered
from dwaar.db.repositories.budget_ledger import ReserveResult
from dwaar.integrations import razorpay
from dwaar.risk import injection as _injection
from dwaar.risk.observations import InMemoryObservationStore
from tests._support.fakes import FixedScorer
from tests.conftest import rand_id

pytestmark = pytest.mark.db

DETECTOR = _injection.load()


def reservation(before: int, after: int) -> ReserveResult:
    return ReserveResult(
        entry_id=1, balance_before=before, balance_after=after, duplicate=False
    )


# ── the bound ───────────────────────────────────────────────────────────────────────


async def test_the_order_is_created_for_what_the_LEDGER_reserved():
    """`balance_before - balance_after` IS the reserved amount and cannot disagree with the
    ledger, because it is the ledger."""
    client = razorpay.RazorpayClient(mode="stub")
    order = await client.create_order(
        reservation(5_000_000, 4_880_000), receipt="rcpt", requested_paise=200_000
    )
    assert order.amount_paise == 120_000
    assert order.requested_paise == 200_000
    assert order.was_clamped is True


async def test_create_order_takes_no_amount_parameter():
    """The structural half of the claim.

    There is no argument through which the request's figure could reach the order. A
    signature that accepted one would be a signature someone eventually passes the wrong
    number to, and no test would notice because both numbers are plausible.
    """
    import inspect

    parameters = set(inspect.signature(razorpay.RazorpayClient.create_order).parameters)
    assert "amount_paise" not in parameters
    assert "reservation" in parameters


async def test_a_reservation_larger_than_the_request_is_REFUSED():
    """A bound may only ever reduce.

    If the reservation exceeds the request, some arithmetic upstream is wrong, and charging
    the larger figure would be the worst possible way to find out.
    """
    client = razorpay.RazorpayClient(mode="stub")
    with pytest.raises(razorpay.RazorpayError, match="may only reduce"):
        await client.create_order(
            reservation(5_000_000, 4_800_000), receipt="r", requested_paise=100_000
        )


async def test_a_zero_reservation_cannot_produce_an_order():
    client = razorpay.RazorpayClient(mode="stub")
    with pytest.raises(razorpay.RazorpayError):
        await client.create_order(reservation(5_000_000, 5_000_000), receipt="r")


@pytest.mark.db
async def test_a_BOUND_decision_creates_an_order_for_the_bounded_amount(
    owner_dsn, app_dsn, make_mandate, signer, authorize_signed
):
    """End to end, through the pipeline, with the policy engine reducing the amount.

    This is the case the whole design of `create_order` exists for: the request asks for one
    number, the policy engine bounds it to another, and the money must move on the second.
    """
    from dwaar.authorize.types import AuthorizeRequest
    from dwaar.db.repositories import policies as policy_repo

    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(
        setup, merchant_id=merchant, max_total_paise=50_000_000, max_per_txn_paise=2_000_000
    )
    await ensure_registered(setup, signer)
    policy_id = rand_id("pol")
    await policy_repo.create(
        setup, policy_id=policy_id, merchant_id=merchant, version=1,
        source_nl="Cap groceries at Rs 500.",
        compiled_rules={"rules": [{
            "id": "grocery_bound",
            "when": {">": [{"var": "request.amount_paise"}, {"lit": 50_000}]},
            "action": "bound", "reason_code": "allowed", "bound_to_paise": 50_000,
        }]},
        generated_tests={}, tests_passed=True,
    )
    await policy_repo.approve(setup, policy_id, approved_by="arpit", signature=b"\x04" * 64)
    await setup.commit()
    await setup.close()

    from dwaar.policy.store import PolicyStore

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await authorize_signed(
            conn,
            AuthorizeRequest(
                agent_id=mandate["agent_id"], mandate_id=mandate["mandate_id"],
                action="purchase", amount_paise=180_000,
                idempotency_key=f"{rand_id('k')}-xxxxxxxx", category="groceries",
            ),
            policy_store=PolicyStore(ttl_seconds=0),
            observation_store=InMemoryObservationStore(),
            scorer=FixedScorer(0.02),
            detector=DETECTOR,
        )

    assert outcome.decision.decision == "bound"
    assert outcome.reservation is not None

    client = razorpay.RazorpayClient(mode="stub")
    order = await client.create_order(
        outcome.reservation, receipt="rcpt", requested_paise=180_000
    )
    assert order.amount_paise == 50_000, (
        f"the order was created for {order.amount_paise} paise against a bound of 50,000. "
        "The enforcement decided one number and the money moved on another."
    )
    assert order.was_clamped is True


# ── the SIMULATED badge ─────────────────────────────────────────────────────────────


async def test_a_stub_order_is_marked_simulated():
    """The badge is driven by the RESPONSE, not by configuration.

    A badge read from a config flag is a badge that is wrong the first time someone changes
    the flag. The failure it prevents is standing in front of judges describing a stub as a
    live integration.
    """
    order = await razorpay.RazorpayClient(mode="stub").create_order(
        reservation(1_000_000, 900_000), receipt="r"
    )
    assert order.simulated is True
    assert order.raw["simulated"] is True


def test_stub_mode_needs_no_credentials():
    assert razorpay.RazorpayClient(mode="stub").simulated is True


def test_live_test_without_a_key_is_an_ERROR_not_a_downgrade():
    """A demo that quietly falls back to stub reports simulated results while everyone in
    the room believes the API was called."""
    with pytest.raises(razorpay.RazorpayNotConfigured, match="never in source"):
        razorpay.RazorpayClient(mode="live_test")


def test_a_key_that_is_not_a_TEST_key_is_refused():
    """This repository drives deliberately abusive traffic. A live key here is the one
    mistake with a real-money consequence."""
    with pytest.raises(razorpay.RazorpayNotConfigured, match="TEST key"):
        razorpay.RazorpayClient(
            mode="live_test", key_id="rzp_live_abc123", key_secret="s"
        )


def test_credentials_never_appear_in_source():
    """They come from the environment via Settings, and `.env` is gitignored."""
    from tests._support import sourcescan
    from tests._support.importgraph import REPO_ROOT

    result = sourcescan.scan(
        [REPO_ROOT / "dwaar", REPO_ROOT / "zoo", REPO_ROOT / "tools"],
        ["rzp_live_", "rzp_test_5", "rzp_test_1"],
        relative_to=REPO_ROOT,
    )
    assert result.files_scanned > 20
    assert not result.findings, sourcescan.render(result.findings)


# ── webhooks ────────────────────────────────────────────────────────────────────────


def test_the_signature_is_over_the_RAW_bytes():
    """`json.dumps(json.loads(x))` reorders keys and changes whitespace, and the signature
    covers what was SENT. A verifier that re-serialises works in testing — where the round
    trip happens to be identity — and fails against the real sender."""
    import hashlib
    import hmac
    import json

    secret = "whsec"
    # Whitespace, which is what a real sender's body has and what a compact re-serialisation
    # removes. Key ORDER survives a Python round trip, so ordering alone would not have
    # demonstrated anything — the first version of this test used it and passed vacuously.
    body = b'{\n  "event": "payment.captured",\n  "amount": 12000\n}'
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    assert razorpay.verify_webhook_signature(body, signature, secret)

    reserialised = json.dumps(json.loads(body), separators=(",", ":")).encode()
    assert reserialised != body, "the round trip was identity; this test proves nothing"
    assert not razorpay.verify_webhook_signature(reserialised, signature, secret)


def test_a_wrong_signature_is_rejected():
    assert not razorpay.verify_webhook_signature(b"{}", "deadbeef", "whsec")
    assert not razorpay.verify_webhook_signature(b"{}", "", "whsec")


def test_the_webhook_key_is_namespaced():
    """F-017: an unprefixed external identifier shares a namespace with our own derived
    keys, and a collision there silently no-ops a real ledger entry."""
    key = razorpay.webhook_idempotency_key("evt_123")
    assert key.startswith("rzp:")
    assert key != "evt_123"


async def test_a_duplicate_webhook_does_not_double_count(app_dsn):
    """The normal case, not the error case.

    Razorpay retries until it gets a 2xx, and a delivery that succeeded but whose response
    was lost is retried anyway. Absorbing it is the same shape as `reserve()`: a namespaced
    key and a named conflict target, so "already processed" is a fact the database
    establishes rather than something the application remembers.
    """
    from dwaar.api.routes.webhooks import _apply

    key = razorpay.webhook_idempotency_key(f"evt_{rand_id('x')}")
    event = {"event": "payment.captured", "payload": {}}

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        first = await _apply(conn, kind="payment.captured", key=key, event=event)
        await conn.commit()
        second = await _apply(conn, kind="payment.captured", key=key, event=event)
        await conn.commit()

        cur = await conn.execute(
            "SELECT count(*) FROM webhook_deliveries WHERE idempotency_key = %s", (key,)
        )
        stored = (await cur.fetchone())[0]

    assert first is True, "the first delivery was not applied"
    assert second is False, "the duplicate was applied a second time"
    assert stored == 1, f"{stored} rows for one event; the duplicate double-counted"


async def test_the_app_role_cannot_edit_a_delivery(app_dsn):
    """A delivery record that can be edited is one that can be made to look like it never
    arrived — the same reasoning as append-only on `decision_records`."""
    import psycopg.errors

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await conn.execute("UPDATE webhook_deliveries SET event_type = 'x'")
        await conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await conn.execute("DELETE FROM webhook_deliveries")
        await conn.rollback()
