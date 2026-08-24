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
from tests.conftest import rand_hash, rand_sig

pytestmark = pytest.mark.db


async def _seed_record(conn, make_mandate, make_signing_key, merchant_id="mch_grant01"):
    mandate = await make_mandate(conn, merchant_id=merchant_id)
    key_id = await make_signing_key(conn)
    return await decision_records.append(
        conn,
        merchant_id=merchant_id,
        payload_hash=rand_hash(),
        signature=rand_sig(),
        signing_key_id=key_id,
        agent_id=mandate["agent_id"],
        principal_id=mandate["principal_id"],
        mandate_hash=mandate["mandate_hash"],
        request_digest=rand_hash(),
        decision="allow",
        features={"velocity": 1},
        policy_version=1,
        latency_us=4200,
        amount_paise=124_000,
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


async def test_update_raises_insufficient_privilege(app_conn, make_mandate, make_signing_key):
    """THE acceptance criterion."""
    record = await _seed_record(app_conn, make_mandate, make_signing_key)

    with pytest.raises(InsufficientPrivilege):
        async with app_conn.cursor() as cur:
            await cur.execute(
                "UPDATE decision_records SET amount_paise = 500000 WHERE record_id = %s",
                (record["record_id"],),
            )


async def test_delete_raises_insufficient_privilege(app_conn, make_mandate, make_signing_key):
    record = await _seed_record(app_conn, make_mandate, make_signing_key)

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


async def test_insert_and_select_still_work(app_conn, make_mandate, make_signing_key):
    """The control must not break the application it protects."""
    record = await _seed_record(app_conn, make_mandate, make_signing_key)
    fetched = await decision_records.get(app_conn, record["record_id"])
    assert fetched is not None
    assert fetched["decision"] == "allow"
    assert fetched["seq"] >= 1


async def test_superuser_can_tamper_because_the_demo_requires_it(
    superuser_dsn, app_conn, make_mandate, make_signing_key
):
    """Demo beat 6: the tamper MUST succeed at the database.

    This is the test that would fail if someone "hardened" the table with a BEFORE UPDATE
    trigger. It is here so that hardening is a conscious decision to break the demo rather
    than an accident.
    """
    record = await _seed_record(app_conn, make_mandate, make_signing_key)
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
