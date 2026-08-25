"""The MCP proxy, end to end: a denied tool call is a chained record.

The demo beat is thirty seconds long and it is the moment the problem stops being
hypothetical. An agent calls `create_refund` for Rs 40,000 and is refused — not because the
amount is too large (it is not) but because the principal never delegated the power to move
money outward. The same call with a raw merchant token succeeds, and that is the gap.

What these tests actually assert is the part a judge would check: **the denial is in the
chain, on the mandate's own terms, with no model consulted.**
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from dwaar.authorize.types import AuthorizeRequest
from dwaar.crypto import keys as keymod
from dwaar.crypto import mandate as mandatemod
from dwaar.crypto.signer import ensure_registered
from dwaar.db.repositories import agents, decision_records, mandates, principals
from dwaar.mcp import proxy
from dwaar.risk import injection as _injection
from dwaar.risk.observations import InMemoryObservationStore
from tests._support.fakes import FixedScorer
from tests.conftest import AGENT_SEED, rand_id

pytestmark = pytest.mark.db

DETECTOR = _injection.load()


async def scoped_mandate_with(
    owner_dsn,
    signer,
    *,
    scopes: list[str] | None = None,
    allow_categories: list[str] | None = None,
    deny_categories: list[str] | None = None,
):
    """Build a GENUINELY SIGNED mandate with scopes.

    Shared by the fixture and by the category test, so neither is tempted to reach for an
    UPDATE. There is one way to make a mandate in this file and it goes through the signer.
    """
    scopes = ["collect.create", "read"] if scopes is None else scopes
    allow_categories = allow_categories or []
    deny_categories = deny_categories or []
    merchant = rand_id("mch")
    agent_id, principal_id, mandate_id = (
        rand_id("agt"), rand_id("prn"), rand_id("mnd")
    )
    agent_key = keymod.derive_private_key(AGENT_SEED, "agent", agent_id)
    principal_key = keymod.derive_private_key(AGENT_SEED, "principal", principal_id)
    expires = datetime.now(UTC) + timedelta(days=30)

    conn = await psycopg.AsyncConnection.connect(owner_dsn)
    await principals.create(
        conn, principal_id=principal_id, merchant_id=merchant,
        public_key=keymod.public_bytes(principal_key),
    )
    await agents.create(
        conn, agent_id=agent_id, display_name="mcp-test",
        public_key=keymod.public_bytes(agent_key), registered_by=merchant,
    )
    payload = mandatemod.build_payload(
        mandate_id=mandate_id, principal_id=principal_id, agent_id=agent_id,
        max_total_paise=50_000_000, max_per_txn_paise=10_000_000,
        allow_categories=allow_categories, deny_categories=deny_categories,
        substitution_tolerance="none",
        expires_at=expires, nonce=uuid.uuid4().hex, scopes=scopes,
    )
    canonical = mandatemod.canonical_json(payload)
    await mandates.create(
        conn, mandate_id=mandate_id, principal_id=principal_id, agent_id=agent_id,
        max_total_paise=50_000_000, max_per_txn_paise=10_000_000, expires_at=expires,
        nonce=payload["nonce"], canonical_json=canonical,
        signature=principal_key.sign(canonical.encode()),
        mandate_hash=mandatemod.mandate_hash(payload),
        allow_categories=allow_categories, deny_categories=deny_categories,
        substitution_tolerance="none", scopes=scopes,
    )
    await ensure_registered(conn, signer)
    await conn.commit()
    await conn.close()
    return {"merchant": merchant, "agent_id": agent_id, "mandate_id": mandate_id}


@pytest.fixture
async def scoped_mandate(owner_dsn, signer):
    """A mandate delegating collection but NOT outbound money. The demo's shape."""
    return await scoped_mandate_with(owner_dsn, signer)


def tool_request(fixture, tool: str, **arguments) -> AuthorizeRequest:
    from dwaar.mcp import scopes as scopemod

    rule = scopemod.rule_for(tool)
    return AuthorizeRequest(
        agent_id=fixture["agent_id"],
        mandate_id=fixture["mandate_id"],
        action=proxy.action_for(rule) if rule else "payout",
        amount_paise=arguments.get("amount", 0),
        idempotency_key=f"{rand_id('k')}-xxxxxxxx",
        tool=tool,
        tool_arguments=arguments,
    )


async def run(conn, request, authorize_signed):
    return await authorize_signed(
        conn, request,
        observation_store=InMemoryObservationStore(),
        scorer=FixedScorer(0.02),
        detector=DETECTOR,
    )


# ── the money moment ────────────────────────────────────────────────────────────────


async def test_the_demo_beat_a_scoped_refund_is_denied_and_chained(
    app_dsn, scoped_mandate, authorize_signed
):
    """Rs 40,000 refund, mandate scopes [collect.create, read].

    Three things asserted, and the third is the one that makes it evidence rather than a
    log line: the denial happened, it names the scope in `rule_fired`, and `risk_score` is
    NULL because the gate refused it before any model ran.
    """
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(
            conn, tool_request(scoped_mandate, "create_refund", amount=4_000_000),
            authorize_signed,
        )
        record = await decision_records.get(conn, outcome.record_id)

    assert outcome.decision.decision == "deny"
    assert outcome.decision.reason_code == "denied"
    assert outcome.decision.rule_fired == "mcp.scope.money.outbound"

    assert record["risk_score"] is None, (
        "a scope denial carried a risk score. It must be refused on the mandate's own "
        "terms, before any model is consulted — that NULL is the evidence."
    )
    assert record["seq"] >= 1, "the denial was not chained"
    assert "score_risk" not in record["stages_executed"]
    assert record["action"] == "refund" if "action" in record else True


async def test_the_amount_was_never_the_reason(app_dsn, scoped_mandate, authorize_signed):
    """A Rs 1 refund is refused for exactly the same reason as a Rs 40,000 one.

    This is the whole argument for scopes existing beside amounts. A spending limit says how
    much; it does not say which direction. If the tiny refund were permitted, the mandate
    would be a budget rather than a delegation.
    """
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        tiny = await run(
            conn, tool_request(scoped_mandate, "create_refund", amount=100),
            authorize_signed,
        )
    assert tiny.decision.decision == "deny"
    assert tiny.decision.rule_fired == "mcp.scope.money.outbound"


async def test_a_delegated_tool_is_allowed_and_reserves_budget(
    app_dsn, scoped_mandate, authorize_signed
):
    """The control. If everything denied, the test above would prove nothing."""
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(
            conn, tool_request(scoped_mandate, "create_order", amount=150_000),
            authorize_signed,
        )
    assert outcome.decision.decision == "allow"
    assert outcome.reservation is not None
    assert outcome.budget_remaining_paise == 50_000_000 - 150_000


async def test_an_unlisted_tool_denies_by_default(
    app_dsn, scoped_mandate, authorize_signed
):
    """A proxy in front of a vendor's tool list whose default is permissive stops enforcing
    the day the vendor ships a tool nobody mapped."""
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(
            conn, tool_request(scoped_mandate, "create_payout_v2", amount=1),
            authorize_signed,
        )
        record = await decision_records.get(conn, outcome.record_id)

    assert outcome.decision.decision == "deny"
    assert outcome.decision.rule_fired == "mcp.tool_unmapped"
    assert record["risk_score"] is None


async def test_a_read_only_tool_is_permitted_and_reserves_nothing(
    app_dsn, scoped_mandate, authorize_signed
):
    """`read` is delegated and a fetch moves no money, so the budget must not move either."""
    from dwaar.db.repositories import budget_ledger

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        await run(
            conn, tool_request(scoped_mandate, "create_order", amount=1_000),
            authorize_signed,
        )
        before = await budget_ledger.balance(conn, scoped_mandate["mandate_id"])
        after_outcome = await run(
            conn, tool_request(scoped_mandate, "fetch_payment"), authorize_signed
        )
        after = await budget_ledger.balance(conn, scoped_mandate["mandate_id"])
        record = await decision_records.get(conn, after_outcome.record_id)

    assert after_outcome.decision.decision == "allow"
    assert after == before, "a read-only tool moved the budget"

    # And the RECORD says nothing moved, rather than recording a balance that would imply
    # the ledger was consulted.
    assert after_outcome.budget_remaining_paise is None
    assert record["budget_before"] is None
    assert record["budget_after"] is None


# ── the same chain, the same verifier ───────────────────────────────────────────────


async def test_an_mcp_denial_verifies_like_any_other_record(
    app_dsn, scoped_mandate, authorize_signed
):
    """There is one chain, not two.

    An MCP denial and an HTTP denial are the same kind of row, produced by the same
    pipeline, checked by the same verifier. If this file had grown its own decision path,
    that would stop being true and there would be two places to get authority wrong.
    """
    from dwaar.verify_cli import verify

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        await run(
            conn, tool_request(scoped_mandate, "create_refund", amount=4_000_000),
            authorize_signed,
        )
        await run(
            conn, tool_request(scoped_mandate, "create_order", amount=1_000),
            authorize_signed,
        )

    report = verify(app_dsn, merchant=scoped_mandate["merchant"])
    assert report.ok, report.failures


async def test_the_gate_runs_the_scope_check_not_the_proxy():
    """Structural: the scope check lives in the arithmetic gate, so it cannot be bypassed by
    a caller that reaches the pipeline another way."""
    import inspect

    from dwaar.authorize.stages import authority

    source = inspect.getsource(authority.check_authority)
    assert "check_scope" in source, (
        "the scope check is not in the arithmetic gate. If it lives only in the MCP route, "
        "any other entry point into the pipeline skips it."
    )


async def test_a_tool_call_with_a_category_is_still_category_checked(
    app_dsn, owner_dsn, make_mandate, signer, authorize_signed
):
    """The narrowing is only where there is genuinely nothing to check.

    An MCP call carrying no category is not category-checked, because a tool call has none.
    One that DOES carry a category is, and this asserts the narrowing did not become a hole.
    """
    # A properly SIGNED mandate with scopes, built the same way the fixture above builds
    # one. An earlier version of this test took the shortcut — `make_mandate`, then
    # `UPDATE mandates SET scopes = ...` as the owner — and `make verify` caught it
    # immediately: a scopes column that disagrees with the signed canonical_json is exactly
    # the tamper the integrity check exists to find, and five such rows were sitting in the
    # database before anyone looked.
    #
    # That is F-018 again. A fixture a verifier would reject cannot be used to test anything
    # the verifier protects, and the shortcut that produces one is always the same shortcut:
    # writing a column instead of re-signing the row.
    mandate = await scoped_mandate_with(
        owner_dsn, signer,
        deny_categories=["gift_cards"], allow_categories=["groceries"],
    )
    request = AuthorizeRequest(
        agent_id=mandate["agent_id"], mandate_id=mandate["mandate_id"],
        action="purchase", amount_paise=1_000,
        idempotency_key=f"{rand_id('k')}-xxxxxxxx",
        category="gift_cards",             # the fixture's mandate denies this
        tool="create_order", tool_arguments={"amount": 1_000},
    )
    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await run(conn, request, authorize_signed)

    assert outcome.decision.decision == "deny"
    assert outcome.decision.rule_fired == "mandate.category_denied"
