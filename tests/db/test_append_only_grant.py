"""`decision_records` is append-only, enforced by GRANT — and the tamper still works.

Three claims, and the third is as important as the first two:

1. As ``dwaar_app``, UPDATE and DELETE raise ``InsufficientPrivilege``.
2. As ``dwaar_app``, INSERT and SELECT succeed — the control does not break the app.
3. As **superuser**, UPDATE succeeds. This is required, not tolerated.

Claim 3 is why there is no BEFORE UPDATE trigger. The control being demonstrated is
detection by cryptography, not prevention by DBMS: the demo tamper is performed from a
superuser connection, it must *succeed* at the storage layer, and the hash chain is what
catches it and names the seq. A trigger would block the superuser too and there would be
nothing left to detect.
"""

from __future__ import annotations

import psycopg
import pytest
from psycopg.errors import InsufficientPrivilege

from dwaar.db.repositories import decision_records

pytestmark = pytest.mark.db


async def _seed_record(conn, make_mandate, write_record, merchant_id="mch_grant01"):
    mandate = await make_mandate(conn, merchant_id=merchant_id)
    return await write_record(
        conn, merchant_id=merchant_id, mandate=mandate, amount_paise=124_000
    )


async def test_app_role_is_not_the_table_owner(app_conn):
    """The whole control rests on this. A REVOKE cannot strip an owner."""
    async with app_conn.cursor() as cur:
        await cur.execute("SELECT current_user")
        current = (await cur.fetchone())[0]
        await cur.execute(
            "SELECT tableowner FROM pg_tables WHERE tablename = 'decision_records'"
        )
        owner = (await cur.fetchone())[0]

    assert current == "dwaar_app"
    assert owner == "dwaar_owner"
    assert owner != current, (
        "dwaar_app must not own decision_records. An owner retains every privilege "
        "regardless of REVOKE, which is exactly why the strategy package's "
        "`REVOKE ... FROM PUBLIC` was a no-op."
    )


async def test_app_role_has_exactly_select_and_insert(app_conn):
    async with app_conn.cursor() as cur:
        await cur.execute(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE table_name = 'decision_records' AND grantee = 'dwaar_app' "
            "ORDER BY privilege_type"
        )
        granted = {r[0] for r in await cur.fetchall()}

    assert granted == {"SELECT", "INSERT"}, (
        f"dwaar_app must hold SELECT+INSERT on decision_records and nothing else, got {granted}"
    )


async def test_update_raises_insufficient_privilege(app_conn, make_mandate, write_record):
    """THE acceptance criterion."""
    record = await _seed_record(app_conn, make_mandate, write_record)

    with pytest.raises(InsufficientPrivilege):
        async with app_conn.cursor() as cur:
            await cur.execute(
                "UPDATE decision_records SET amount_paise = 500000 WHERE record_id = %s",
                (record["record_id"],),
            )


async def test_delete_raises_insufficient_privilege(app_conn, make_mandate, write_record):
    record = await _seed_record(app_conn, make_mandate, write_record)

    with pytest.raises(InsufficientPrivilege):
        async with app_conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM decision_records WHERE record_id = %s", (record["record_id"],)
            )


async def test_truncate_raises(app_conn):
    with pytest.raises(psycopg.Error):
        async with app_conn.cursor() as cur:
            await cur.execute("TRUNCATE decision_records")


async def test_budget_ledger_is_also_append_only(app_conn, make_mandate):
    """Releases are compensating entries, never edits.

    If the ledger could be updated, `balance == sum(deltas)` would stop being an invariant
    and the property test asserting it would assert nothing.

    Each denial gets its own SAVEPOINT. A failed statement aborts the whole transaction in
    PostgreSQL, so without one the second assertion would see ``InFailedSqlTransaction``
    rather than ``InsufficientPrivilege`` — and would have "passed" for the wrong reason
    if it had been written to catch a broader exception.
    """
    mandate = await make_mandate(app_conn)

    async with app_conn.transaction(force_rollback=True):
        with pytest.raises(InsufficientPrivilege):
            async with app_conn.cursor() as cur:
                await cur.execute(
                    "UPDATE budget_ledger SET balance_after = 999 WHERE mandate_id = %s",
                    (mandate["mandate_id"],),
                )

    async with app_conn.transaction(force_rollback=True):
        with pytest.raises(InsufficientPrivilege):
            async with app_conn.cursor() as cur:
                await cur.execute(
                    "DELETE FROM budget_ledger WHERE mandate_id = %s",
                    (mandate["mandate_id"],),
                )


async def test_insert_and_select_still_work(app_conn, make_mandate, write_record):
    """The control must not break the application it protects."""
    record = await _seed_record(app_conn, make_mandate, write_record)
    fetched = await decision_records.get(app_conn, record["record_id"])
    assert fetched is not None
    assert fetched["decision"] == "allow"
    assert fetched["seq"] >= 1


async def test_superuser_can_tamper_because_the_demo_requires_it(
    superuser_dsn, app_conn, make_mandate, write_record
):
    """Demo beat 6: the tamper MUST succeed at the database.

    This is the test that would fail if someone "hardened" the table with a BEFORE UPDATE
    trigger. It is here so that hardening is a conscious decision to break the demo rather
    than an accident.
    """
    record = await _seed_record(app_conn, make_mandate, write_record)
    await app_conn.commit()

    try:
        async with await psycopg.AsyncConnection.connect(superuser_dsn) as su:
            async with su.cursor() as cur:
                await cur.execute(
                    "UPDATE decision_records SET amount_paise = 500000 WHERE record_id = %s",
                    (record["record_id"],),
                )
                assert cur.rowcount == 1, (
                    "The superuser tamper must succeed. Detection is by cryptography, not "
                    "prevention by DBMS — if this is blocked, demo beat 6 has nothing to "
                    "detect. See THREAT_MODEL.md."
                )
            await su.commit()
    finally:
        # This test commits, so clean up after itself.
        async with await psycopg.AsyncConnection.connect(superuser_dsn) as su:
            async with su.cursor() as cur:
                await cur.execute(
                    "DELETE FROM decision_records WHERE record_id = %s", (record["record_id"],)
                )
            await su.commit()


# ── Authority columns are not writable by the app (migration 0010) ──────────────────
#
# The two-role grant protects decision_records. Table-wide UPDATE on `mandates` left the
# same class of hole one table over: the app could extend its own expiry or raise its own
# per-transaction cap, and nothing would detect it — the principal's signature covers
# canonical_json, which stays untouched, while the hot path reads the denormalised columns.


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("expires_at", "now() + interval '100 years'"),
        ("max_total_paise", "999999999"),
        ("max_per_txn_paise", "999999999"),
        ("allow_categories", "ARRAY['gift_cards']"),
        ("deny_categories", "ARRAY[]::text[]"),
        ("canonical_json", "'{}'"),
        ("signature", "decode(repeat('00', 64), 'hex')"),
        ("mandate_hash", "decode(repeat('00', 32), 'hex')"),
        ("principal_id", "'prn_someone_else'"),
    ],
)
async def test_app_cannot_rewrite_mandate_authority(app_conn, make_mandate, column, value):
    mandate = await make_mandate(app_conn)
    async with app_conn.transaction(force_rollback=True):
        with pytest.raises(InsufficientPrivilege):
            async with app_conn.cursor() as cur:
                await cur.execute(
                    f"UPDATE mandates SET {column} = {value} WHERE mandate_id = %s",
                    (mandate["mandate_id"],),
                )


async def test_app_can_still_revoke(app_conn, make_mandate):
    """The one mandate UPDATE the app legitimately needs must keep working."""
    from dwaar.db.repositories import mandates

    mandate = await make_mandate(app_conn)
    assert await mandates.revoke(app_conn, mandate["mandate_id"]) is True
    assert (await mandates.get(app_conn, mandate["mandate_id"]))["revoked_at"] is not None


async def test_app_cannot_move_an_agent_to_another_merchant(app_conn, make_agent):
    agent = await make_agent(app_conn)
    async with app_conn.transaction(force_rollback=True):
        with pytest.raises(InsufficientPrivilege):
            async with app_conn.cursor() as cur:
                await cur.execute(
                    "UPDATE agents SET registered_by = 'mch_attacker' WHERE agent_id = %s",
                    (agent["agent_id"],),
                )


async def test_app_can_still_suspend_and_rotate(app_conn, make_agent):
    from dwaar.db.repositories import agents as agentrepo

    agent = await make_agent(app_conn)
    assert await agentrepo.set_status(app_conn, agent["agent_id"], "suspended") is True
    rotated = await agentrepo.rotate_key(app_conn, agent["agent_id"], b"\x02" * 32)
    assert bytes(rotated["public_key"]) == b"\x02" * 32


async def test_app_cannot_rewrite_an_approved_policys_rules(app_conn, migrated):
    """An approved policy's rules are frozen. A change is a new version, which is an INSERT."""
    from dwaar.db.repositories import policies
    from tests.conftest import rand_id

    policy_id = rand_id("pol")
    await policies.create(
        app_conn,
        policy_id=policy_id,
        merchant_id=rand_id("mch"),
        version=1,
        source_nl="Deny gift cards.",
        compiled_rules={"deny": ["gift_cards"]},
        generated_tests={"cases": []},
        tests_passed=True,
    )
    async with app_conn.transaction(force_rollback=True):
        with pytest.raises(InsufficientPrivilege):
            async with app_conn.cursor() as cur:
                await cur.execute(
                    "UPDATE policies SET compiled_rules = '{}'::jsonb WHERE policy_id = %s",
                    (policy_id,),
                )


async def test_app_cannot_rewrite_a_signing_keys_public_half(app_conn, make_signing_key):
    """Rewriting a key that has already signed records invalidates every one of them,
    and invalidation is indistinguishable from forgery."""
    key_id = await make_signing_key(app_conn)
    async with app_conn.transaction(force_rollback=True):
        with pytest.raises(InsufficientPrivilege):
            async with app_conn.cursor() as cur:
                await cur.execute(
                    "UPDATE signing_keys SET public_key = %s WHERE key_id = %s",
                    (b"\x00" * 32, key_id),
                )


async def test_mandate_hash_is_unique(app_conn, make_mandate):
    """The verifier resolves a record to its authority by this hash; a collision would
    make that join ambiguous with no way to choose."""
    from psycopg.errors import UniqueViolation

    first = await make_mandate(app_conn)
    async with app_conn.transaction(force_rollback=True):
        with pytest.raises(UniqueViolation):
            async with app_conn.cursor() as cur:
                await cur.execute(
                    "UPDATE mandates SET revoked_at = NULL WHERE mandate_id = %s",
                    (first["mandate_id"],),
                )
                await cur.execute(
                    "INSERT INTO mandates (mandate_id, principal_id, agent_id, "
                    " max_total_paise, max_per_txn_paise, expires_at, nonce, "
                    " canonical_json, signature, mandate_hash) "
                    "VALUES (%s,%s,%s,%s,%s,now()+interval '1 day',%s,'{}',%s,%s)",
                    (
                        "mnd_collision01",
                        first["principal_id"],
                        first["agent_id"],
                        100000,
                        10000,
                        "collision-nonce",
                        bytes(first["signature"]),
                        bytes(first["mandate_hash"]),  # same hash
                    ),
                )
