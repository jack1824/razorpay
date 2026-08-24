"""Shared fixtures.

Database tests are marked ``db`` and skip when no PostgreSQL is reachable, so ``make test``
is green on a laptop with nothing running while still being the real gate in CI and under
``docker compose up``. The skip reason names the DSN it tried, because "1 skipped" with no
explanation is how a test that never runs becomes a test that never worked.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from dwaar.config import Settings
from dwaar.db.migrate import migrate
from dwaar.logging import configure_logging

MIGRATE_DSN = os.environ.get(
    "DATABASE_URL_MIGRATE", "postgresql://dwaar_owner:owner_pw@localhost:5432/dwaar"
)
APP_DSN = os.environ.get(
    "DATABASE_URL_APP", "postgresql://dwaar_app:app_pw@localhost:5432/dwaar"
)
SUPERUSER_DSN = os.environ.get(
    "DATABASE_URL_SUPERUSER", "postgresql://postgres:postgres_pw@localhost:5432/dwaar"
)


def _reachable(dsn: str) -> bool:
    try:
        with psycopg.connect(dsn, connect_timeout=2) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:  # noqa: BLE001
        return False


@pytest.fixture(scope="session")
def db_available() -> bool:
    return _reachable(MIGRATE_DSN)


@pytest.fixture(scope="session", autouse=True)
def _logging():
    configure_logging("WARNING")


@pytest.fixture(scope="session")
def migrated(db_available):
    """Apply migrations once per session."""
    if not db_available:
        pytest.skip(f"no PostgreSQL at {MIGRATE_DSN.split('@')[-1]} — start it with `make up`")
    migrate(MIGRATE_DSN)
    return True


@pytest.fixture
def owner_dsn(migrated) -> str:
    return MIGRATE_DSN


@pytest.fixture
def app_dsn(migrated) -> str:
    return APP_DSN


@pytest.fixture
def migrate_dsn_for_http(migrated) -> str:
    """The owner DSN, for tests that build a real app.

    Named separately so a test that needs it has to ask, rather than the app silently
    inheriting `.env` (which carries Docker hostnames that do not resolve from the host).
    """
    return MIGRATE_DSN


@pytest.fixture
def superuser_dsn(migrated) -> str:
    if not _reachable(SUPERUSER_DSN):
        pytest.skip("superuser DSN not reachable")
    return SUPERUSER_DSN


@pytest.fixture
async def owner_conn(owner_dsn):
    """Owner connection, rolled back after the test. Nothing here persists."""
    conn = await psycopg.AsyncConnection.connect(owner_dsn, autocommit=False)
    try:
        yield conn
    finally:
        await conn.rollback()
        await conn.close()


@pytest.fixture
async def app_conn(app_dsn):
    """App-role connection. Non-owner: this is what the API uses."""
    conn = await psycopg.AsyncConnection.connect(app_dsn, autocommit=False)
    try:
        yield conn
    finally:
        await conn.rollback()
        await conn.close()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        DATABASE_URL_MIGRATE=MIGRATE_DSN,
        DATABASE_URL_APP=APP_DSN,
        DATABASE_URL_SUPERUSER=SUPERUSER_DSN,
    )


# ── Fixture builders ────────────────────────────────────────────────────────────────
#
# Real 32-byte keys and 64-byte signatures, because the schema CHECKs enforce those
# lengths. They are not *valid* Ed25519 pairs — the crypto layer is day 4 — and nothing
# here verifies a signature. Using correctly-sized random bytes keeps these tests honest
# about what they do and do not prove.


def rand_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def rand_key() -> bytes:
    return os.urandom(32)


def rand_sig() -> bytes:
    return os.urandom(64)


def rand_hash() -> bytes:
    return os.urandom(32)


@pytest.fixture
def make_agent():
    async def _make(conn, *, merchant_id: str = "mch_test0001", agent_id: str | None = None):
        from dwaar.db.repositories import agents

        return await agents.create(
            conn,
            agent_id=agent_id or rand_id("agt"),
            display_name="test-agent",
            public_key=rand_key(),
            registered_by=merchant_id,
        )

    return _make


@pytest.fixture
def make_principal():
    async def _make(conn, *, merchant_id: str = "mch_test0001"):
        from dwaar.db.repositories import principals

        return await principals.create(
            conn,
            principal_id=rand_id("prn"),
            merchant_id=merchant_id,
            public_key=rand_key(),
        )

    return _make


@pytest.fixture
def make_mandate(make_agent, make_principal):
    """Create a mandate and its genesis ledger entry.

    Defaults mirror the demo fixtures: ₹50,000 total, ₹5,000 per transaction.
    """

    async def _make(
        conn,
        *,
        max_total_paise: int = 5_000_000,
        max_per_txn_paise: int | None = None,
        merchant_id: str = "mch_test0001",
    ):
        # The schema enforces max_per_txn <= max_total. A fixed default would make every
        # test that lowers the total fail on a CHECK violation that has nothing to do with
        # what it is testing, so the per-txn cap follows the total unless asked otherwise.
        if max_per_txn_paise is None:
            max_per_txn_paise = min(500_000, max_total_paise)

        from dwaar.db.repositories import mandates

        agent = await make_agent(conn, merchant_id=merchant_id)
        principal = await make_principal(conn, merchant_id=merchant_id)
        return await mandates.create(
            conn,
            mandate_id=rand_id("mnd"),
            principal_id=principal["principal_id"],
            agent_id=agent["agent_id"],
            max_total_paise=max_total_paise,
            max_per_txn_paise=max_per_txn_paise,
            expires_at=datetime.now(UTC) + timedelta(days=30),
            nonce=uuid.uuid4().hex,
            canonical_json='{"test":true}',
            signature=rand_sig(),
            mandate_hash=rand_hash(),
            allow_categories=["groceries", "apparel"],
            deny_categories=["gift_cards"],
            substitution_tolerance="same_price",
        )

    return _make


@pytest.fixture(scope="session")
def signer(tmp_path_factory):
    """Dwaar's signing identity for tests, derived from a test seed.

    Private half goes to a tmp dir, never the repo's .keys/, so a test run can never
    overwrite the seeded demo key.
    """
    from dwaar.crypto.signer import derive_signer

    return derive_signer(999, keys_dir=tmp_path_factory.mktemp("keys"))


@pytest.fixture
def write_record(signer):
    """Write a genuinely signed, chained decision record.

    There is one insert path and it signs — the unsigned `append()` was removed when
    stage 8 became real. This helper exists so tests stay readable, not so they can skip
    signing.
    """
    from datetime import datetime

    from dwaar.crypto import record as recordmod
    from dwaar.crypto.signer import ensure_registered
    from dwaar.db.repositories import decision_records

    async def _write(conn, *, merchant_id, mandate, decision="allow", **overrides):
        await ensure_registered(conn, signer)
        await decision_records.lock_chain(conn, merchant_id)
        position = await decision_records.next_position(conn, merchant_id)

        fields = {
            "seq": position.seq,
            "merchant_id": merchant_id,
            "prev_hash": position.prev_hash,
            "signing_key_id": signer.key_id,
            "agent_id": mandate["agent_id"],
            "principal_id": mandate["principal_id"],
            "mandate_hash": bytes(mandate["mandate_hash"]),
            "request_digest": rand_hash(),
            "decision": decision,
            "reason_code": "allowed" if decision == "allow" else "denied",
            "injection_flag": False,
            "features": {},
            "degraded_mode": [],
            "stages_executed": ["render_decision"],
            "latency_us": 3000,
            "created_at": datetime.now(UTC),
        }
        fields.update(overrides)
        payload = recordmod.build_payload(**fields)
        canonical = recordmod.canonical_json(payload)
        digest = recordmod.payload_hash(payload)
        return await decision_records.append_signed(
            conn,
            merchant_id=merchant_id,
            position=position,
            payload=payload,
            canonical_json=canonical,
            payload_hash=digest,
            signature=signer.sign(canonical.encode()),
            created_at=fields["created_at"],
        )

    return _write


@pytest.fixture
def make_signing_key():
    async def _make(conn, key_id: str | None = None):
        kid = key_id or rand_id("key")
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO signing_keys (key_id, public_key) VALUES (%s, %s) "
                "ON CONFLICT (key_id) DO NOTHING",
                (kid, rand_key()),
            )
        return kid

    return _make
