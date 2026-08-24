"""Stage 1 against a real database: rotation, replay, suspension.

`tests/crypto/test_http_sig.py` proves the signature scheme is correct in isolation. This
proves the *stage* is correct — which is a different claim, because the stage is where a
signature meets a registered key, a rotation window, an agent status and a nonce store.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from dwaar.authorize import pipeline
from dwaar.authorize.stages import signature as sig_stage
from dwaar.authorize.types import AuthorizeRequest
from dwaar.crypto import http_sig
from dwaar.crypto import keys as keymod
from dwaar.crypto.signer import ensure_registered
from dwaar.db.repositories import agents as agent_repo
from dwaar.nonce import InMemoryNonceStore, NonceStoreUnavailable
from tests.conftest import AGENT_SEED, rand_id

pytestmark = pytest.mark.db


@pytest.fixture
async def scenario(owner_dsn, make_mandate, signer):
    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(setup, merchant_id=merchant)
    await ensure_registered(setup, signer)
    await setup.commit()
    await setup.close()

    yield merchant, mandate

    cleanup = await psycopg.AsyncConnection.connect(owner_dsn)
    async with cleanup.cursor() as cur:
        await cur.execute("DELETE FROM decision_records WHERE merchant_id = %s", (merchant,))
        await cur.execute(
            "DELETE FROM budget_ledger WHERE mandate_id = %s", (mandate["mandate_id"],)
        )
        await cur.execute("DELETE FROM mandates WHERE mandate_id = %s", (mandate["mandate_id"],))
        await cur.execute("DELETE FROM agents WHERE agent_id = %s", (mandate["agent_id"],))
        await cur.execute(
            "DELETE FROM principals WHERE principal_id = %s", (mandate["principal_id"],)
        )
    await cleanup.commit()
    await cleanup.close()


def build(mandate, *, key=None, nonce=None, created=None, agent_id=None):
    agent = agent_id or mandate["agent_id"]
    request = AuthorizeRequest(
        agent_id=agent, mandate_id=mandate["mandate_id"], action="purchase",
        amount_paise=1_000, idempotency_key=f"{rand_id('k')}-xxxxxxxx", category="groceries",
    )
    body = json.dumps({"agent_id": agent}, separators=(",", ":")).encode()
    private = key or keymod.derive_private_key(AGENT_SEED, "agent", agent)
    headers = http_sig.sign_request(
        private, method="POST", path="/v1/authorize", body=body, keyid=agent,
        created=created if created is not None else int(time.time()),
        nonce=nonce or uuid.uuid4().hex,
    )
    return request, headers, body


async def verify(conn, mandate, settings, *, store=None, now=None, **kw):
    request, headers, body = build(mandate, **kw)
    return await sig_stage.verify_signature(
        request, headers, settings=settings, conn=conn, body=body,
        nonce_store=store, now=now,
    )


# ── the happy path ──────────────────────────────────────────────────────────────────

async def test_a_correctly_signed_request_verifies(app_conn, scenario, settings):
    _merchant, mandate = scenario
    result = await verify(app_conn, mandate, settings, store=InMemoryNonceStore())
    assert result.ok is True
    assert result.key_used == "current"
    assert result.degraded is None, "stage 1 is real; it must not claim a degradation"


# ── key rotation, both sides of the window ──────────────────────────────────────────

async def test_the_previous_key_is_accepted_inside_the_overlap_window(
    owner_dsn, app_conn, scenario, settings
):
    """A rotation is what you do when you suspect a key is compromised. Making it reject
    in-flight requests makes people delay it, which is the opposite of what you want."""
    _merchant, mandate = scenario
    old_key = keymod.derive_private_key(AGENT_SEED, "agent", mandate["agent_id"])
    new_key = keymod.derive_private_key(999_111, "agent", mandate["agent_id"])

    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    await agent_repo.rotate_key(setup, mandate["agent_id"], keymod.public_bytes(new_key))
    await setup.commit()
    await setup.close()

    inside = datetime.now(UTC) + sig_stage.KEY_OVERLAP - timedelta(minutes=1)
    result = await verify(
        app_conn, mandate, settings, store=InMemoryNonceStore(), key=old_key, now=inside
    )
    assert result.ok is True
    assert result.key_used == "previous"


async def test_the_previous_key_is_refused_outside_the_overlap_window(
    owner_dsn, app_conn, scenario, settings
):
    """The overlap is a window, not a permanent second credential."""
    _merchant, mandate = scenario
    old_key = keymod.derive_private_key(AGENT_SEED, "agent", mandate["agent_id"])
    new_key = keymod.derive_private_key(999_111, "agent", mandate["agent_id"])

    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    await agent_repo.rotate_key(setup, mandate["agent_id"], keymod.public_bytes(new_key))
    await setup.commit()
    await setup.close()

    outside = datetime.now(UTC) + sig_stage.KEY_OVERLAP + timedelta(minutes=1)
    result = await verify(
        app_conn, mandate, settings, store=InMemoryNonceStore(), key=old_key, now=outside
    )
    assert result.ok is False
    assert "does not verify" in result.internal_reason


async def test_the_new_key_works_immediately(owner_dsn, app_conn, scenario, settings):
    _merchant, mandate = scenario
    new_key = keymod.derive_private_key(999_111, "agent", mandate["agent_id"])

    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    await agent_repo.rotate_key(setup, mandate["agent_id"], keymod.public_bytes(new_key))
    await setup.commit()
    await setup.close()

    result = await verify(app_conn, mandate, settings, store=InMemoryNonceStore(), key=new_key)
    assert result.ok is True
    assert result.key_used == "current"


# ── replay ──────────────────────────────────────────────────────────────────────────

async def test_a_replayed_nonce_is_refused(app_conn, scenario, settings):
    """`created` bounds replay to ±120s, which without a nonce is 120 seconds of free
    replays."""
    _merchant, mandate = scenario
    store = InMemoryNonceStore()
    nonce = uuid.uuid4().hex

    first = await verify(app_conn, mandate, settings, store=store, nonce=nonce)
    assert first.ok is True

    second = await verify(app_conn, mandate, settings, store=store, nonce=nonce)
    assert second.ok is False
    assert second.internal_reason == sig_stage.REASON_REPLAYED


async def test_a_missing_nonce_is_refused(app_conn, scenario, settings):
    """A signature with no nonce is replayable for the whole skew window."""
    _merchant, mandate = scenario
    request, headers, body = build(mandate)
    # Re-sign without a nonce.
    private = keymod.derive_private_key(AGENT_SEED, "agent", mandate["agent_id"])
    headers = http_sig.sign_request(
        private, method="POST", path="/v1/authorize", body=body,
        keyid=mandate["agent_id"], created=int(time.time()), nonce=None,
    )
    result = await sig_stage.verify_signature(
        request, headers, settings=settings, conn=app_conn, body=body,
        nonce_store=InMemoryNonceStore(),
    )
    assert result.ok is False
    assert result.internal_reason == sig_stage.REASON_NO_NONCE


async def test_one_agents_nonce_does_not_burn_anothers(app_conn, scenario, settings, make_agent):
    """Keyed on (agent_id, nonce). A global nonce space would let one agent deny another."""
    _merchant, mandate = scenario
    store = InMemoryNonceStore()
    shared = uuid.uuid4().hex

    other = await make_agent(app_conn, merchant_id=_merchant)
    assert (await store.claim(other["agent_id"], shared)) is True

    result = await verify(app_conn, mandate, settings, store=store, nonce=shared)
    assert result.ok is True, "a different agent's nonce must not block this one"


async def test_the_nonce_store_fails_closed(app_conn, scenario, settings):
    """Redis down means we cannot tell a first use from a replay.

    Threat 2 is replay of a *signed* request, so answering "probably fine" here would be
    fail-open on identity — unlike the rest of the Redis surface, which is judgment.
    """
    _merchant, mandate = scenario

    class Broken:
        async def claim(self, agent_id: str, nonce: str) -> bool:
            raise NonceStoreUnavailable("redis is down")

    with pytest.raises(NonceStoreUnavailable):
        await verify(app_conn, mandate, settings, store=Broken())


# ── identity ────────────────────────────────────────────────────────────────────────

async def test_a_suspended_agent_is_refused(owner_dsn, app_conn, scenario, settings):
    """`agents.status` had no enforcement point before stage 1 became real: a revoked
    agent could still authorize, because nothing read the column."""
    _merchant, mandate = scenario
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    await agent_repo.set_status(setup, mandate["agent_id"], "suspended")
    await setup.commit()
    await setup.close()

    result = await verify(app_conn, mandate, settings, store=InMemoryNonceStore())
    assert result.ok is False
    assert sig_stage.REASON_AGENT_NOT_ACTIVE in result.internal_reason


async def test_an_unknown_agent_is_refused(app_conn, scenario, settings):
    _merchant, mandate = scenario
    result = await verify(
        app_conn, mandate, settings, store=InMemoryNonceStore(), agent_id="agt_doesnotexis"
    )
    assert result.ok is False
    assert result.internal_reason == sig_stage.REASON_UNKNOWN_AGENT


async def test_a_keyid_naming_another_agent_is_refused(
    app_conn, scenario, settings, make_agent
):
    """Without this an agent could present a signature made by a DIFFERENT agent's key and
    have it accepted, because the acceptable-key list is built from the claimed agent_id."""
    _merchant, mandate = scenario
    other = await make_agent(app_conn, merchant_id=_merchant)
    other_key = keymod.derive_private_key(AGENT_SEED, "agent", other["agent_id"])

    request = AuthorizeRequest(
        agent_id=mandate["agent_id"], mandate_id=mandate["mandate_id"], action="purchase",
        amount_paise=1_000, idempotency_key=f"{rand_id('k')}-xxxxxxxx", category="groceries",
    )
    body = b"{}"
    headers = http_sig.sign_request(
        other_key, method="POST", path="/v1/authorize", body=body,
        keyid=other["agent_id"], created=int(time.time()), nonce=uuid.uuid4().hex,
    )
    result = await sig_stage.verify_signature(
        request, headers, settings=settings, conn=app_conn, body=body,
        nonce_store=InMemoryNonceStore(),
    )
    assert result.ok is False


# ── through the whole pipeline ──────────────────────────────────────────────────────

async def test_an_unsigned_request_is_unauthenticated_and_never_chained(
    app_dsn, scenario, signer, settings
):
    """401, a counter and a log line — never a chain entry.

    An unattributable request is a security event, not an authorization decision. Chaining
    it would hand anyone with an HTTP client write access to the evidence.
    """
    from dwaar.db.repositories import decision_records

    merchant, mandate = scenario
    request, _headers, body = build(mandate)

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        before = len(await decision_records.iter_chain(conn, merchant))
        with pytest.raises(pipeline.Unauthenticated):
            await pipeline.authorize(
                request, conn=conn, signer=signer, settings=settings,
                headers={}, body=body, nonce_store=InMemoryNonceStore(),
            )
        await conn.rollback()
        after = len(await decision_records.iter_chain(conn, merchant))

    assert after == before


async def test_no_record_still_claims_an_unverified_signature(
    app_dsn, scenario, signer, settings
):
    """Stage 1 is real, so `signature_unverified` must be absent from every new record —
    not merely unused, but gone."""
    from dwaar.db.repositories import decision_records

    merchant, mandate = scenario
    request, headers, body = build(mandate)

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await pipeline.authorize(
            request, conn=conn, signer=signer, settings=settings,
            headers=headers, body=body, nonce_store=InMemoryNonceStore(),
        )
        await conn.commit()
        record = await decision_records.get(conn, outcome.record_id)

    assert "signature_unverified" not in record["degraded_mode"]
