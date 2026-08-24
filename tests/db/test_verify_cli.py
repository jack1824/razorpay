"""The verifier, and the tamper it exists to catch.

The acceptance bar is specific: **mutate any single column on decision_records, mandates or
policies and the verifier must FAIL and name the row.** Not "detect a broken chain" —
detect a *column* edit, which leaves every hash and signature intact and is exactly what
demo beat 6 does.

Every tamper here runs as SUPERUSER and succeeds at the storage layer. That is required,
not tolerated: the control being demonstrated is detection by cryptography, not prevention
by DBMS, and blocking the write would leave nothing to detect.
"""

from __future__ import annotations

import json
import time
import uuid

import psycopg
import pytest

from dwaar.authorize import pipeline
from dwaar.authorize.types import AuthorizeRequest
from dwaar.crypto import http_sig
from dwaar.crypto import keys as keymod
from dwaar.crypto.signer import ensure_registered

#: A REAL detector, so the record under test is a COMPLETE one.
#:
#: Migration 0014 constrains `injection_flag` to agree with `stages_executed`, so a
#: record written without a detector carries NULL — and the tamper case that flips the
#: flag to `true` would then be refused by the constraint rather than by the verifier.
#: A tamper test blocked before it happens proves nothing about detection.
from dwaar.risk import injection as _injection
from dwaar.verify_cli import main as verify_main
from dwaar.verify_cli import verify
from tests.conftest import AGENT_SEED, rand_id

DETECTOR = _injection.load()

pytestmark = pytest.mark.db


@pytest.fixture
async def chained(owner_dsn, app_dsn, make_mandate, signer, settings, nonce_store):
    """A merchant with a short, genuinely signed chain."""
    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    mandate = await make_mandate(setup, merchant_id=merchant)
    await ensure_registered(setup, signer)
    await setup.commit()
    await setup.close()

    async with await psycopg.AsyncConnection.connect(app_dsn) as conn:
        for i in range(4):
            request = AuthorizeRequest(
                agent_id=mandate["agent_id"], mandate_id=mandate["mandate_id"],
                action="purchase", amount_paise=1_000 + i,
                idempotency_key=f"vfy-{i:04d}-{'x' * 8}", category="groceries",
            )
            body = json.dumps({"i": i}, separators=(",", ":")).encode()
            private = keymod.derive_private_key(AGENT_SEED, "agent", request.agent_id)
            headers = http_sig.sign_request(
                private, method="POST", path="/v1/authorize", body=body,
                keyid=request.agent_id, created=int(time.time()), nonce=uuid.uuid4().hex,
            )
            await pipeline.authorize(
                request, conn=conn, signer=signer, settings=settings,
                headers=headers, body=body, nonce_store=nonce_store, detector=DETECTOR,
            )
            await conn.commit()

    yield merchant, mandate

    cleanup = await psycopg.AsyncConnection.connect(owner_dsn)
    async with cleanup.cursor() as cur:
        # By AGENT, not merchant: one of the tamper tests rewrites merchant_id, which moves
        # the row out of a merchant-scoped delete and leaks it into every later run.
        await cur.execute(
            "DELETE FROM decision_records WHERE merchant_id = %s OR agent_id = %s",
            (merchant, mandate["agent_id"]),
        )
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


async def tamper(superuser_dsn: str, sql: str, params: tuple) -> None:
    """Succeeds, on purpose. See the module docstring."""
    async with await psycopg.AsyncConnection.connect(superuser_dsn) as su:
        async with su.cursor() as cur:
            await cur.execute(sql, params)
            assert cur.rowcount >= 1, "the tamper must land, or the test proves nothing"
        await su.commit()


# ── clean ───────────────────────────────────────────────────────────────────────────

async def test_an_untampered_chain_verifies(app_dsn, chained):
    merchant, _mandate = chained
    findings = verify(app_dsn, merchant=merchant)
    assert findings.ok, findings.failures
    assert findings.checked["decision_records.chain"] == 4


async def test_the_cli_exits_zero_when_clean(app_dsn, chained, capsys):
    merchant, _mandate = chained
    assert verify_main(["--dsn", app_dsn, "--merchant", merchant]) == 0
    assert "PASS" in capsys.readouterr().out


# ── decision_records: every signed column ───────────────────────────────────────────

@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("amount_paise", "999999"),
        ("decision", "'deny'"),
        ("reason_code", "'denied'"),
        ("rule_fired", "'policy.something_else'"),
        ("agent_id", "'agt_someoneelse'"),
        ("principal_id", "'prn_someoneelse'"),
        ("budget_after", "0"),
        ("latency_us", "1"),
        ("injection_flag", "true"),
        ("policy_version", "99"),
        ("merchant_id", "'mch_elsewhere'"),
        # Note the `detect_injection` entry. Migration 0014 constrains `injection_flag` to
        # agree with `stages_executed`, so `ARRAY['nothing']` is refused by the DATABASE
        # before the verifier ever sees it — and a tamper blocked before it happens proves
        # nothing about detection.
        #
        # That is worth stating rather than working around quietly: a CHECK constraint is a
        # second, weaker control that narrows the space of forgeries an attacker with
        # UPDATE but not DDL can produce. It does not replace the chain, because a superuser
        # can drop it — but dropping it is itself a visible act, and the chain still catches
        # every forgery that remains inside it. This case is one of those.
        ("stages_executed", "ARRAY['nothing','detect_injection']"),
        ("degraded_mode", "ARRAY[]::text[]"),
    ],
)
async def test_mutating_any_signed_column_fails_verification(
    app_dsn, superuser_dsn, chained, column, value
):
    """THE acceptance criterion, one column at a time.

    Each of these leaves canonical_json, payload_hash, prev_hash and the signature intact.
    Before the columns-vs-canonical check existed, every one of them verified clean.
    """
    merchant, _mandate = chained
    await tamper(
        superuser_dsn,
        f"UPDATE decision_records SET {column} = {value} "  # noqa: S608
        "WHERE merchant_id = %s AND seq = 2",
        (merchant,),
    )

    # Verified GLOBALLY: moving a record to another merchant removes it from the scoped
    # view, and "the row vanished from my chain" must not read as "my chain is fine".
    findings = verify(app_dsn)
    assert not findings.ok, f"tampering with {column} was not detected"
    assert any("decision_records" in f for f in findings.failures)


async def test_the_cli_exits_nonzero_and_names_the_row(app_dsn, superuser_dsn, chained, capsys):
    merchant, _mandate = chained
    await tamper(
        superuser_dsn,
        "UPDATE decision_records SET amount_paise = 500000 WHERE merchant_id = %s AND seq = 3",
        (merchant,),
    )
    assert verify_main(["--dsn", app_dsn, "--merchant", merchant]) == 1
    output = capsys.readouterr().out
    assert "FAIL" in output
    assert "decision_records 3" in output or "seq=3" in output


async def test_rewriting_the_signed_bytes_is_also_caught(app_dsn, superuser_dsn, chained):
    """The smarter attacker rewrites canonical_json to match the column.

    Then payload_hash no longer matches, and forging that needs the signing key.
    """
    merchant, _mandate = chained
    await tamper(
        superuser_dsn,
        "UPDATE decision_records "
        "SET canonical_json = replace(canonical_json, '\"allow\"', '\"deny\"') "
        "WHERE merchant_id = %s AND seq = 2",
        (merchant,),
    )
    findings = verify(app_dsn, merchant=merchant)
    assert not findings.ok


async def test_repointing_a_record_at_another_key_is_caught(
    app_dsn, superuser_dsn, chained, owner_dsn
):
    """signing_key_id is inside the signed payload precisely so this fails."""
    merchant, _mandate = chained
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    async with setup.cursor() as cur:
        await cur.execute(
            "INSERT INTO signing_keys (key_id, public_key) VALUES (%s, %s) "
            "ON CONFLICT DO NOTHING",
            ("key_attacker0", b"\x01" * 32),
        )
    await setup.commit()
    await setup.close()

    await tamper(
        superuser_dsn,
        "UPDATE decision_records SET signing_key_id = 'key_attacker0' "
        "WHERE merchant_id = %s AND seq = 2",
        (merchant,),
    )
    findings = verify(app_dsn, merchant=merchant)
    assert not findings.ok


async def test_deleting_a_record_is_reported_as_a_break_not_a_gap(
    app_dsn, superuser_dsn, chained
):
    """A deletion in the MIDDLE breaks the link. Only trailing absence is a gap."""
    merchant, _mandate = chained
    await tamper(
        superuser_dsn,
        "DELETE FROM decision_records WHERE merchant_id = %s AND seq = 2",
        (merchant,),
    )
    findings = verify(app_dsn, merchant=merchant)
    assert not findings.ok
    assert any("CHAIN BROKEN" in f for f in findings.failures)


# ── mandates: the F-013 residual ────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("max_total_paise", "999999999"),
        ("max_per_txn_paise", "999999"),
        ("expires_at", "now() + interval '100 years'"),
        ("allow_categories", "ARRAY['gift_cards']"),
        ("deny_categories", "ARRAY[]::text[]"),
        ("substitution_tolerance", "'similar'"),
        ("nonce", "'rewritten'"),
    ],
)
async def test_mutating_a_mandate_column_fails_verification(
    app_dsn, superuser_dsn, chained, column, value
):
    """The residual F-013 left open: a superuser can still rewrite the terms, and the
    principal's signature keeps verifying because canonical_json is untouched.

    The application can no longer do it (migration 0010, column grants). The verifier is
    what catches an attacker who owns the database.
    """
    _merchant, mandate = chained
    await tamper(
        superuser_dsn,
        f"UPDATE mandates SET {column} = {value} WHERE mandate_id = %s",  # noqa: S608
        (mandate["mandate_id"],),
    )
    findings = verify(app_dsn)
    assert not findings.ok, f"tampering with mandates.{column} was not detected"
    assert any(mandate["mandate_id"] in f for f in findings.failures), (
        "the verifier must name the mandate"
    )


# ── policies: the third instance ────────────────────────────────────────────────────

async def test_mutating_an_approved_policy_fails_verification(
    app_dsn, owner_dsn, superuser_dsn
):
    """Found by generalising, not by a bug report.

    Signing compiled_rules alone would leave version, merchant_id and approved_by free —
    so an approved v3 ruleset could be repointed at another merchant with the signature
    still valid.
    """
    from dwaar.db.repositories import policies

    policy_id = rand_id("pol")
    merchant = rand_id("mch")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    await policies.create(
        setup, policy_id=policy_id, merchant_id=merchant, version=1,
        source_nl="Deny gift cards.", compiled_rules={"deny": ["gift_cards"]},
        generated_tests={"cases": []}, tests_passed=True,
    )
    await policies.approve(setup, policy_id, approved_by="arpit", signature=b"\x07" * 64)
    await setup.commit()
    await setup.close()

    try:
        await tamper(
            superuser_dsn,
            "UPDATE policies SET compiled_rules = '{\"deny\":[]}'::jsonb WHERE policy_id = %s",
            (policy_id,),
        )
        findings = verify(app_dsn)
        assert not findings.ok
        assert any(policy_id in f for f in findings.failures)
    finally:
        cleanup = await psycopg.AsyncConnection.connect(superuser_dsn)
        async with cleanup.cursor() as cur:
            await cur.execute("DELETE FROM policies WHERE policy_id = %s", (policy_id,))
        await cleanup.commit()
        await cleanup.close()


async def test_an_unapproved_policy_is_skipped_not_failed(app_dsn, owner_dsn):
    """A policy with no signature was never attested. Nothing is being claimed about it,
    so there is nothing to contradict."""
    from dwaar.db.repositories import policies

    policy_id = rand_id("pol")
    setup = await psycopg.AsyncConnection.connect(owner_dsn)
    await policies.create(
        setup, policy_id=policy_id, merchant_id=rand_id("mch"), version=1,
        source_nl="x", compiled_rules={}, generated_tests={}, tests_passed=False,
    )
    await setup.commit()
    await setup.close()

    try:
        findings = verify(app_dsn)
        assert not any(policy_id in f for f in findings.failures)
    finally:
        cleanup = await psycopg.AsyncConnection.connect(owner_dsn)
        async with cleanup.cursor() as cur:
            await cur.execute("DELETE FROM policies WHERE policy_id = %s", (policy_id,))
        await cleanup.commit()
        await cleanup.close()


# ── the verifier itself ─────────────────────────────────────────────────────────────

async def test_the_verifier_cannot_write(app_dsn, chained):
    """A verifier that could modify the chain would be no more credible than the app.

    Asserted at the server: `default_transaction_read_only` means the database refuses the
    write, rather than the verifier merely choosing not to attempt one.
    """
    from dwaar.verify_cli import _connect

    conn = _connect(app_dsn)
    try:
        with pytest.raises(psycopg.Error, match="read-only"):
            conn.execute("INSERT INTO eval_runs (seed, model_version, policy_version, results) "
                         "VALUES (1, 'x', 1, '{}'::jsonb)")
    finally:
        conn.close()


def test_the_verifier_imports_no_write_path():
    """Structural, not behavioural: the write repositories must be unreachable from it."""
    from tests._support.importgraph import build_graph, find_path_to

    graph = build_graph("dwaar")
    for forbidden in ("dwaar.authorize", "dwaar.api", "dwaar.db.repositories.budget_ledger"):
        path = find_path_to(graph, "dwaar.verify_cli", forbidden)
        assert path is None, (
            f"the verifier reaches {forbidden}: " + " | ".join(str(e) for e in path)
        )
