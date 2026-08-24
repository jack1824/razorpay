"""Repository layer, and the schema constraints the repositories rely on."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from psycopg.errors import CheckViolation, ForeignKeyViolation, UniqueViolation

from dwaar.db.repositories import agents, budget_ledger, decision_records, mandates, policies
from dwaar.db.repositories.base import from_hex, to_hex
from tests.conftest import rand_hash, rand_id, rand_key, rand_sig

pytestmark = pytest.mark.db


# ── base: the bytes/hex boundary ────────────────────────────────────────────────────

def test_hex_roundtrip():
    raw = rand_hash()
    assert from_hex(to_hex(raw), expect_len=32) == raw


def test_hex_conversion_rejects_wrong_length():
    """Length is validated at the boundary so a bad value fails with a useful message."""
    with pytest.raises(ValueError, match="expected 32 bytes"):
        from_hex("aabb", expect_len=32)


def test_hex_output_is_lowercase():
    assert to_hex(b"\xab\xcd") == "abcd"


# ── agents ──────────────────────────────────────────────────────────────────────────

async def test_agent_create_and_get(owner_conn, make_agent):
    created = await make_agent(owner_conn)
    fetched = await agents.get(owner_conn, created["agent_id"])
    assert fetched["display_name"] == "test-agent"
    assert fetched["status"] == "active"
    assert len(bytes(fetched["public_key"])) == 32


async def test_agent_public_key_must_be_32_bytes(owner_conn):
    """Ed25519 keys are exactly 32 bytes. Rejected at the repository boundary.

    ``from_hex(..., expect_len=32)`` catches this before the statement is sent, which is
    the better error — it names the expected length instead of surfacing a constraint
    violation from three frames down.
    """
    with pytest.raises(ValueError, match="expected 32 bytes"):
        await agents.create(
            owner_conn,
            agent_id=rand_id("agt"),
            display_name="bad",
            public_key=b"\x01" * 16,
            registered_by="mch_test0001",
        )


async def test_agent_public_key_length_is_also_enforced_by_the_database(owner_conn, migrated):
    """The boundary check is convenience; the CHECK is the control.

    Asserted separately by going around the repository entirely — otherwise a future
    refactor that drops the boundary validation would leave this schema constraint
    untested and nobody would notice.
    """
    with pytest.raises(CheckViolation):
        async with owner_conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO agents (agent_id, display_name, public_key, registered_by) "
                "VALUES (%s, %s, %s, %s)",
                (rand_id("agt"), "bad", b"\x01" * 16, "mch_test0001"),
            )


async def test_agent_status_is_constrained(owner_conn, make_agent):
    agent = await make_agent(owner_conn)
    assert await agents.set_status(owner_conn, agent["agent_id"], "suspended")
    assert (await agents.get(owner_conn, agent["agent_id"]))["status"] == "suspended"

    with pytest.raises(ValueError):
        await agents.set_status(owner_conn, agent["agent_id"], "banished")


async def test_key_rotation_keeps_the_old_key(owner_conn, make_agent):
    """Overlap window: requests signed with the old key must not fail mid-rotation."""
    agent = await make_agent(owner_conn)
    original = bytes(agent["public_key"])
    new_key = rand_key()

    rotated = await agents.rotate_key(owner_conn, agent["agent_id"], new_key)
    assert bytes(rotated["public_key"]) == new_key
    assert bytes(rotated["previous_public_key"]) == original
    assert rotated["key_rotated_at"] is not None


# ── mandates ────────────────────────────────────────────────────────────────────────

async def test_mandate_create_writes_genesis_ledger_entry(owner_conn, make_mandate):
    """ADR 0001 Q3. The opening balance IS the mandate total."""
    mandate = await make_mandate(owner_conn, max_total_paise=5_000_000)

    entries = await budget_ledger.history(owner_conn, mandate["mandate_id"])
    assert len(entries) == 1
    genesis = entries[0]
    assert genesis["prev_entry_id"] is None
    assert genesis["delta_paise"] == 5_000_000
    assert genesis["balance_after"] == 5_000_000
    assert genesis["reason"] == "mandate_created"
    assert genesis["idempotency_key"] == f"genesis:{mandate['mandate_id']}"

    assert await budget_ledger.balance(owner_conn, mandate["mandate_id"]) == 5_000_000


async def test_mandate_per_txn_cannot_exceed_total(owner_conn, make_agent, make_principal):
    agent = await make_agent(owner_conn)
    principal = await make_principal(owner_conn)
    with pytest.raises(CheckViolation):
        await mandates.create(
            owner_conn,
            mandate_id=rand_id("mnd"),
            principal_id=principal["principal_id"],
            agent_id=agent["agent_id"],
            max_total_paise=100_000,
            max_per_txn_paise=200_000,  # > total
            expires_at=datetime.now(UTC) + timedelta(days=1),
            nonce=rand_id("n"),
            canonical_json="{}",
            signature=rand_sig(),
            mandate_hash=rand_hash(),
        )


async def test_mandate_nonce_is_unique(owner_conn, make_agent, make_principal):
    """Replay defence at the mandate level."""
    agent = await make_agent(owner_conn)
    principal = await make_principal(owner_conn)
    nonce = rand_id("nonce")

    common = {
        "principal_id": principal["principal_id"],
        "agent_id": agent["agent_id"],
        "max_total_paise": 100_000,
        "max_per_txn_paise": 10_000,
        "expires_at": datetime.now(UTC) + timedelta(days=1),
        "nonce": nonce,
        "canonical_json": "{}",
        "signature": rand_sig(),
        "mandate_hash": rand_hash(),
    }
    await mandates.create(owner_conn, mandate_id=rand_id("mnd"), **common)
    with pytest.raises(UniqueViolation):
        await mandates.create(owner_conn, mandate_id=rand_id("mnd"), **common)


async def test_mandate_defaults_are_materialised(owner_conn, make_agent, make_principal):
    """ADR 0001 item 9: the three defaulted fields are never NULL.

    Under RFC 8785 an absent key and an empty array hash differently, so the same mandate
    would otherwise have two valid mandate_hash values.
    """
    agent = await make_agent(owner_conn)
    principal = await make_principal(owner_conn)
    mandate = await mandates.create(
        owner_conn,
        mandate_id=rand_id("mnd"),
        principal_id=principal["principal_id"],
        agent_id=agent["agent_id"],
        max_total_paise=100_000,
        max_per_txn_paise=10_000,
        expires_at=datetime.now(UTC) + timedelta(days=1),
        nonce=rand_id("n"),
        canonical_json="{}",
        signature=rand_sig(),
        mandate_hash=rand_hash(),
    )
    assert mandate["allow_categories"] == []
    assert mandate["deny_categories"] == []
    assert mandate["substitution_tolerance"] == "none"


async def test_revoke_is_idempotent(owner_conn, make_mandate):
    mandate = await make_mandate(owner_conn)
    assert await mandates.revoke(owner_conn, mandate["mandate_id"]) is True
    assert await mandates.revoke(owner_conn, mandate["mandate_id"]) is False


async def test_list_active_excludes_revoked_and_expired(owner_conn, make_mandate):
    live = await make_mandate(owner_conn)
    revoked = await make_mandate(owner_conn)
    await mandates.revoke(owner_conn, revoked["mandate_id"])

    active = await mandates.list_active_for_agent(owner_conn, live["agent_id"])
    assert [m["mandate_id"] for m in active] == [live["mandate_id"]]

    assert await mandates.list_active_for_agent(owner_conn, revoked["agent_id"]) == []


# ── budget ledger ───────────────────────────────────────────────────────────────────

async def test_reserve_is_arithmetic(owner_conn, make_mandate):
    """`if amount > balance: deny`. No score involved, at any point."""
    mandate = await make_mandate(owner_conn, max_total_paise=100_000)
    mid = mandate["mandate_id"]

    r = await budget_ledger.reserve(
        conn=owner_conn, mandate_id=mid, amount_paise=40_000, idempotency_key=rand_id("k")
    )
    assert r.balance_before == 100_000
    assert r.balance_after == 60_000
    assert r.duplicate is False

    from dwaar.errors import InsufficientBudget

    with pytest.raises(InsufficientBudget):
        await budget_ledger.reserve(
            conn=owner_conn, mandate_id=mid, amount_paise=60_001, idempotency_key=rand_id("k")
        )


async def test_reserve_to_exactly_zero_is_allowed(owner_conn, make_mandate):
    """Spending the last paise is not an overspend. Off-by-one guard."""
    mandate = await make_mandate(owner_conn, max_total_paise=100_000)
    r = await budget_ledger.reserve(
        conn=owner_conn,
        mandate_id=mandate["mandate_id"],
        amount_paise=100_000,
        idempotency_key=rand_id("k"),
    )
    assert r.balance_after == 0


async def test_balance_after_cannot_go_negative_even_by_raw_sql(owner_conn, make_mandate):
    """The CHECK is the last line of defence, below the application entirely."""
    mandate = await make_mandate(owner_conn, max_total_paise=1_000)
    with pytest.raises(CheckViolation):
        async with owner_conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO budget_ledger "
                "(mandate_id, prev_entry_id, delta_paise, balance_after, idempotency_key, reason) "
                "VALUES (%s, NULL, %s, %s, %s, %s)",
                (mandate["mandate_id"], -5_000, -4_000, rand_id("k"), "forced"),
            )


async def test_reserve_rejects_unknown_mandate(owner_conn, migrated):
    from dwaar.errors import LedgerError

    with pytest.raises(LedgerError, match="unknown mandate"):
        await budget_ledger.reserve(
            conn=owner_conn,
            mandate_id="mnd_doesnotexist",
            amount_paise=100,
            idempotency_key=rand_id("k"),
        )


async def test_money_must_be_int(owner_conn, make_mandate):
    """Money is BIGINT paise, never float. A float here is a bug, not a conversion."""
    mandate = await make_mandate(owner_conn)
    with pytest.raises((TypeError, ValueError)):
        await budget_ledger.reserve(
            conn=owner_conn,
            mandate_id=mandate["mandate_id"],
            amount_paise=100.5,  # type: ignore[arg-type]
            idempotency_key=rand_id("k"),
        )


# ── decision records ────────────────────────────────────────────────────────────────

# There is one insert path and it signs. `write_record` builds the payload, canonicalises
# it, signs it and appends — the same code stage 8 runs.


async def test_chain_starts_at_seq_one_with_zero_prev_hash(owner_conn, make_mandate, write_record):
    merchant = rand_id("mch")
    mandate = await make_mandate(owner_conn, merchant_id=merchant)

    first = await write_record(owner_conn, merchant_id=merchant, mandate=mandate)
    assert first["seq"] == 1
    assert bytes(first["prev_hash"]) == decision_records.GENESIS_PREV_HASH
    assert to_hex(first["prev_hash"]) == "0" * 64


async def test_chain_links_each_record_to_its_predecessor(owner_conn, make_mandate, write_record):
    merchant = rand_id("mch")
    mandate = await make_mandate(owner_conn, merchant_id=merchant)

    records = [
        await write_record(owner_conn, merchant_id=merchant, mandate=mandate)
        for _ in range(5)
    ]

    assert [r["seq"] for r in records] == [1, 2, 3, 4, 5]
    for previous, current in zip(records, records[1:], strict=False):
        assert bytes(current["prev_hash"]) == bytes(previous["payload_hash"])


async def test_chains_are_independent_per_merchant(owner_conn, make_mandate, write_record):
    """ADR 0001 Q4: the chain is sharded by merchant, so each starts at seq 1."""
    merchant_a, merchant_b = rand_id("mch"), rand_id("mch")
    mandate_a = await make_mandate(owner_conn, merchant_id=merchant_a)
    mandate_b = await make_mandate(owner_conn, merchant_id=merchant_b)

    a1 = await write_record(owner_conn, merchant_id=merchant_a, mandate=mandate_a)
    b1 = await write_record(owner_conn, merchant_id=merchant_b, mandate=mandate_b)
    a2 = await write_record(owner_conn, merchant_id=merchant_a, mandate=mandate_a)

    assert a1["seq"] == 1 and b1["seq"] == 1
    assert a2["seq"] == 2
    assert bytes(b1["prev_hash"]) == decision_records.GENESIS_PREV_HASH


async def test_risk_score_is_null_when_the_model_was_not_consulted(
    owner_conn, make_mandate, write_record
):
    """The NULL is the audit-trail proof the limit was enforced by arithmetic.

    Demo beat 2 depends on this column being NULL on a budget-breach deny.
    """
    merchant = rand_id("mch")
    mandate = await make_mandate(owner_conn, merchant_id=merchant)

    record = await write_record(
        owner_conn,
        merchant_id=merchant,
        mandate=mandate,
        decision="deny",
        rule_fired="mandate.max_per_txn",
        risk_score=None,
        amount_paise=1_200_000,
    )
    assert record["risk_score"] is None
    assert record["rule_fired"] == "mandate.max_per_txn"


async def test_risk_score_is_bounded(owner_conn, make_mandate, write_record):
    merchant = rand_id("mch")
    mandate = await make_mandate(owner_conn, merchant_id=merchant)

    ok = await write_record(
        owner_conn, merchant_id=merchant, mandate=mandate,
        risk_score=1.0, model_version="lgbm-test",
    )
    assert float(ok["risk_score"]) == 1.0

    with pytest.raises(CheckViolation):
        await write_record(
            owner_conn, merchant_id=merchant, mandate=mandate,
            risk_score=1.5, model_version="lgbm-test",
        )


async def test_invalid_decision_is_rejected(owner_conn, make_mandate, write_record):
    merchant = rand_id("mch")
    mandate = await make_mandate(owner_conn, merchant_id=merchant)

    with pytest.raises(psycopg.errors.CheckViolation):
        await write_record(owner_conn, merchant_id=merchant, mandate=mandate, decision="maybe")


async def test_signing_key_is_required_and_must_exist(owner_conn, make_mandate, write_record):
    """Q5: a record must name the key that signed it, and that key must be on file."""
    merchant = rand_id("mch")
    mandate = await make_mandate(owner_conn, merchant_id=merchant)

    with pytest.raises(ForeignKeyViolation):
        await write_record(
            owner_conn, merchant_id=merchant, mandate=mandate,
            signing_key_id="key_nonexistent",
        )


async def test_hash_lengths_are_enforced(owner_conn, make_mandate, write_record):
    merchant = rand_id("mch")
    mandate = await make_mandate(owner_conn, merchant_id=merchant)

    with pytest.raises(ValueError, match="expected 32 bytes"):
        await write_record(
            owner_conn, merchant_id=merchant, mandate=mandate, request_digest=b"\x01" * 16
        )


async def test_concurrent_chain_appends_do_not_break_the_chain(
    app_dsn, owner_dsn, make_mandate, write_record
):
    """The failure BIGSERIAL would have caused, asserted directly.

    20 concurrent appends on one merchant must produce seq 1..20 with no gaps, no
    duplicates, and every prev_hash matching its predecessor's payload_hash.
    """
    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(setup, merchant_id=merchant)
    await setup.commit()
    await setup.close()

    async def append_one() -> str:
        async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
            try:
                await write_record(conn, merchant_id=merchant, mandate=mandate)
                await conn.commit()
                return "ok"
            except Exception as exc:  # noqa: BLE001
                await conn.rollback()
                return f"error:{type(exc).__name__}:{exc}"

    results = await asyncio.gather(*(append_one() for _ in range(20)))
    errors = [r for r in results if r.startswith("error:")]
    assert not errors, f"concurrent chain appends failed: {errors[:3]}"

    verify = await psycopg.AsyncConnection.connect(owner_dsn)
    try:
        chain = await decision_records.iter_chain(verify, merchant)
        gaps = await decision_records.check_contiguity(verify, merchant)
    finally:
        await verify.close()

    assert [r["seq"] for r in chain] == list(range(1, 21)), "seq must be 1..20 with no gaps"
    assert gaps == [], f"chain has gaps at {gaps}"

    assert bytes(chain[0]["prev_hash"]) == decision_records.GENESIS_PREV_HASH
    for previous, current in zip(chain, chain[1:], strict=False):
        assert bytes(current["prev_hash"]) == bytes(previous["payload_hash"]), (
            f"chain broken between seq {previous['seq']} and {current['seq']}"
        )

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


# ── policies ────────────────────────────────────────────────────────────────────────

async def test_policy_cannot_be_approved_before_tests_pass(owner_conn, migrated):
    """The human gate, enforced by the database rather than by remembering to check."""
    policy_id = rand_id("pol")
    merchant = rand_id("mch")
    await policies.create(
        owner_conn,
        policy_id=policy_id,
        merchant_id=merchant,
        version=1,
        source_nl="Deny gift cards.",
        compiled_rules={"deny": ["gift_cards"]},
        generated_tests={"cases": []},
        tests_passed=False,
    )

    with pytest.raises(CheckViolation):
        await policies.approve(owner_conn, policy_id, approved_by="arpit")


async def test_policy_approval_requires_a_named_person(owner_conn, migrated):
    policy_id = rand_id("pol")
    await policies.create(
        owner_conn,
        policy_id=policy_id,
        merchant_id=rand_id("mch"),
        version=1,
        source_nl="x",
        compiled_rules={},
        generated_tests={},
        tests_passed=True,
    )
    with pytest.raises(ValueError, match="must name a person"):
        await policies.approve(owner_conn, policy_id, approved_by="   ")


async def test_get_live_returns_only_approved(owner_conn, migrated):
    merchant = rand_id("mch")
    for version, approved in ((1, True), (2, False)):
        pid = rand_id("pol")
        await policies.create(
            owner_conn,
            policy_id=pid,
            merchant_id=merchant,
            version=version,
            source_nl="x",
            compiled_rules={},
            generated_tests={},
            tests_passed=True,
        )
        if approved:
            await policies.approve(owner_conn, pid, approved_by="arpit")

    live = await policies.get_live(owner_conn, merchant)
    assert live["version"] == 1, "an unapproved higher version must not go live"
