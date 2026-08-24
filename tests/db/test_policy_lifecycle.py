"""A policy from compiled to live, and the gate it cannot skip.

`approved_by IS NULL` means NOT LIVE. That is enforced three ways — a `WHERE` clause in the
store, a database CHECK tying approval to passing tests, and the compiler refusing to
auto-promote — and each is tested here, because the whole argument for letting a model write
these rules is that a human looks at the result before it can move money.
"""

from __future__ import annotations

import json

import psycopg
import pytest

from dwaar.authorize import pipeline
from dwaar.authorize.types import AuthorizeRequest
from dwaar.crypto.signer import ensure_registered
from dwaar.db.repositories import policies as policy_repo
from dwaar.policy.store import NO_COMPILED_POLICY, PolicyStore
from tests._support.fakes import FixedScorer
from tests.conftest import rand_id

pytestmark = pytest.mark.db

DENY_GIFT_CARDS = {
    "rules": [
        {
            "id": "no_gift_cards",
            "when": {"in": [{"var": "request.category"}, {"lit": ["gift_cards"]}]},
            "action": "deny",
            "reason_code": "denied",
        }
    ]
}


@pytest.fixture
async def merchant_policy(owner_dsn):
    merchant = rand_id("mch")
    policy_id = rand_id("pol")

    conn = await psycopg.AsyncConnection.connect(owner_dsn)
    await policy_repo.create(
        conn,
        policy_id=policy_id,
        merchant_id=merchant,
        version=1,
        source_nl="Never allow gift cards.",
        compiled_rules=DENY_GIFT_CARDS,
        generated_tests={"tests": []},
        tests_passed=True,
    )
    await conn.commit()
    await conn.close()

    yield merchant, policy_id

    cleanup = await psycopg.AsyncConnection.connect(owner_dsn)
    async with cleanup.cursor() as cur:
        await cur.execute("DELETE FROM policies WHERE merchant_id = %s", (merchant,))
    await cleanup.commit()
    await cleanup.close()


# ── the human gate ──────────────────────────────────────────────────────────────────

async def test_an_unapproved_policy_cannot_serve_traffic(owner_dsn, merchant_policy):
    """The load-bearing assertion. A compiled, tested, unapproved ruleset is inert."""
    merchant, _policy_id = merchant_policy
    store = PolicyStore(ttl_seconds=0)

    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        live = await store.get(conn, merchant)

    assert live.exists is False
    assert live.version == NO_COMPILED_POLICY
    assert live.ruleset is None


async def test_approval_makes_it_live(owner_dsn, merchant_policy):
    merchant, policy_id = merchant_policy
    store = PolicyStore(ttl_seconds=0)

    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        await policy_repo.approve(conn, policy_id, approved_by="arpit", signature=b"\x01" * 64)
        await conn.commit()
        live = await store.get(conn, merchant)

    assert live.exists is True
    assert live.version == 1
    assert [rule.id for rule in live.ruleset.rules] == ["no_gift_cards"]


async def test_approval_requires_passing_tests(owner_dsn):
    """Enforced by the database, so an application that forgets to check cannot skip it."""
    from psycopg.errors import CheckViolation

    policy_id = rand_id("pol")
    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        await policy_repo.create(
            conn, policy_id=policy_id, merchant_id=rand_id("mch"), version=1,
            source_nl="x", compiled_rules=DENY_GIFT_CARDS, generated_tests={},
            tests_passed=False,
        )
        with pytest.raises(CheckViolation):
            await policy_repo.approve(conn, policy_id, approved_by="arpit")
        await conn.rollback()


async def test_version_zero_is_reserved_and_refused(owner_dsn):
    """0 means 'consulted, none exists'. A real version 0 would make the two
    indistinguishable in every record."""
    from dwaar.policy.dsl import PolicyError

    merchant = rand_id("mch")
    policy_id = rand_id("pol")
    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO policies (policy_id, merchant_id, version, source_nl, "
                " compiled_rules, generated_tests, tests_passed, approved_by) "
                "VALUES (%s,%s,0,'x',%s,'{}'::jsonb,true,'arpit')",
                (policy_id, merchant, json.dumps(DENY_GIFT_CARDS)),
            )
        await conn.commit()

        store = PolicyStore(ttl_seconds=0)
        with pytest.raises(PolicyError, match="reserved"):
            await store.get(conn, merchant)

        async with conn.cursor() as cur:
            await cur.execute("DELETE FROM policies WHERE policy_id = %s", (policy_id,))
        await conn.commit()


# ── hot reload ──────────────────────────────────────────────────────────────────────

async def test_a_newly_approved_version_takes_over_without_a_restart(
    owner_dsn, merchant_policy
):
    merchant, policy_id = merchant_policy
    store = PolicyStore(ttl_seconds=0)

    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        await policy_repo.approve(conn, policy_id, approved_by="arpit", signature=b"\x01" * 64)
        await conn.commit()
        assert (await store.get(conn, merchant)).version == 1

        second = rand_id("pol")
        await policy_repo.create(
            conn, policy_id=second, merchant_id=merchant, version=2, source_nl="v2",
            compiled_rules={"rules": [{"id": "v2_rule", "when": {"lit": False},
                                       "action": "deny", "reason_code": "denied"}]},
            generated_tests={}, tests_passed=True,
        )
        await policy_repo.approve(conn, second, approved_by="arpit", signature=b"\x02" * 64)
        await conn.commit()

        live = await store.get(conn, merchant)

    assert live.version == 2
    assert [rule.id for rule in live.ruleset.rules] == ["v2_rule"]


async def test_the_last_signed_version_keeps_serving_when_the_store_fails(
    owner_dsn, merchant_policy
):
    """A policy can only TIGHTEN — it runs after the arithmetic gate and before the ledger,
    and neither consults it to permit anything. Serving a stale one risks an out-of-date
    restriction, never an unauthorised spend."""
    merchant, policy_id = merchant_policy
    store = PolicyStore(ttl_seconds=60)

    async with await psycopg.AsyncConnection.connect(owner_dsn) as conn:
        await policy_repo.approve(conn, policy_id, approved_by="arpit", signature=b"\x01" * 64)
        await conn.commit()
        warm = await store.get(conn, merchant)
    assert warm.version == 1

    class Broken:
        def cursor(self):
            raise RuntimeError("connection lost")

    store._ttl = 0  # force a reload attempt
    served = await store.get(Broken(), merchant)
    assert served.version == 1, "the last signed version must keep serving"


# ── conflict resolution, end to end ─────────────────────────────────────────────────

async def test_policy_deny_beats_a_benign_risk_score_through_the_pipeline(
    owner_dsn, app_dsn, make_mandate, signer, settings, nonce_store, monkeypatch
):
    """Deterministic rules override probabilistic ones, ALWAYS.

    Asserted through the real pipeline with the model forced to report the request as
    confidently benign — not left to rule ordering inside `render_decision`.
    """
    import time
    import uuid

    from dwaar.crypto import http_sig
    from dwaar.crypto import keys as keymod
    from tests.conftest import AGENT_SEED

    merchant = rand_id("mch")
    policy_id = rand_id("pol")

    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(setup, merchant_id=merchant)
    await ensure_registered(setup, signer)
    await policy_repo.create(
        setup, policy_id=policy_id, merchant_id=merchant, version=1,
        source_nl="Never allow groceries over Rs 100.",
        compiled_rules={"rules": [{
            "id": "grocery_cap",
            "when": {">": [{"var": "request.amount_paise"}, {"lit": 10_000}]},
            "action": "deny", "reason_code": "denied",
        }]},
        generated_tests={}, tests_passed=True,
    )
    await policy_repo.approve(setup, policy_id, approved_by="arpit", signature=b"\x03" * 64)
    await setup.commit()
    await setup.close()

    # The model says this is fine. The policy says it is not.
    #
    # Injected as a SCORER rather than by monkeypatching the stage, so the real stage 4
    # runs: a patched stage would prove the pipeline honours whatever `score_risk` returns,
    # which is not the claim. The claim is that a policy deny survives a genuine, confident,
    # benign score travelling the whole way through the real code.
    benign = FixedScorer(0.01, model_version="lgbm-test")

    request = AuthorizeRequest(
        agent_id=mandate["agent_id"], mandate_id=mandate["mandate_id"], action="purchase",
        amount_paise=50_000, idempotency_key=f"{rand_id('k')}-xxxxxxxx", category="groceries",
    )
    body = b"{}"
    private = keymod.derive_private_key(AGENT_SEED, "agent", request.agent_id)
    headers = http_sig.sign_request(
        private, method="POST", path="/v1/authorize", body=body,
        keyid=request.agent_id, created=int(time.time()), nonce=uuid.uuid4().hex,
    )

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        outcome = await pipeline.authorize(
            request, conn=conn, signer=signer, settings=settings, headers=headers,
            body=body, nonce_store=nonce_store, policy_store=PolicyStore(ttl_seconds=0),
            scorer=benign,
        )
        await conn.commit()
        from dwaar.db.repositories import decision_records

        record = await decision_records.get(conn, outcome.record_id)

    assert outcome.decision.decision == "deny"
    assert outcome.decision.rule_fired == "policy.grocery_cap"
    assert record["policy_version"] == 1
    assert float(record["risk_score"]) == pytest.approx(0.01), (
        "the score is RECORDED — the policy overrode it, it was not ignored"
    )

    cleanup = await psycopg.AsyncConnection.connect(owner_dsn)
    async with cleanup.cursor() as cur:
        await cur.execute("DELETE FROM decision_records WHERE merchant_id = %s", (merchant,))
        await cur.execute("DELETE FROM policies WHERE merchant_id = %s", (merchant,))
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


async def test_a_record_carries_policy_version_zero_when_none_is_approved(
    owner_dsn, app_dsn, make_mandate, signer, settings, nonce_store
):
    """0 = consulted, none exists. NULL = never consulted. Different facts."""
    import time
    import uuid

    from dwaar.crypto import http_sig
    from dwaar.crypto import keys as keymod
    from dwaar.db.repositories import decision_records
    from tests.conftest import AGENT_SEED

    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(setup, merchant_id=merchant)
    await ensure_registered(setup, signer)
    await setup.commit()
    await setup.close()

    request = AuthorizeRequest(
        agent_id=mandate["agent_id"], mandate_id=mandate["mandate_id"], action="purchase",
        amount_paise=1_000, idempotency_key=f"{rand_id('k')}-xxxxxxxx", category="groceries",
    )
    body = b"{}"
    private = keymod.derive_private_key(AGENT_SEED, "agent", request.agent_id)
    headers = http_sig.sign_request(
        private, method="POST", path="/v1/authorize", body=body,
        keyid=request.agent_id, created=int(time.time()), nonce=uuid.uuid4().hex,
    )

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        allowed = await pipeline.authorize(
            request, conn=conn, signer=signer, settings=settings, headers=headers,
            body=body, nonce_store=nonce_store, policy_store=PolicyStore(ttl_seconds=0),
        )
        await conn.commit()
        record = await decision_records.get(conn, allowed.record_id)

    assert record["policy_version"] == 0
