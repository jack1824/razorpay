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
# `.env` carries Docker service hostnames. Any test that builds a real app must override
# them or the app fails closed on an unreachable Redis — which is correct behaviour, and
# an unhelpful test failure.
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


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
        REDIS_URL=REDIS_URL,
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


AGENT_SEED = 20260905


@pytest.fixture
def make_agent():
    """Registers the PUBLIC half of a key the test suite can actually sign with.

    Random bytes would make every agent unable to authenticate, so signature tests would
    have to build their own agents — and the rest of the suite would quietly stop
    exercising the authenticated path.
    """

    async def _make(conn, *, merchant_id: str = "mch_test0001", agent_id: str | None = None):
        from dwaar.crypto import keys as keymod
        from dwaar.db.repositories import agents

        aid = agent_id or rand_id("agt")
        private = keymod.derive_private_key(AGENT_SEED, "agent", aid)
        return await agents.create(
            conn,
            agent_id=aid,
            display_name="test-agent",
            public_key=keymod.public_bytes(private),
            registered_by=merchant_id,
        )

    return _make


@pytest.fixture
def make_principal():
    """Derived key, like agents — so mandates can be genuinely signed by their principal."""

    async def _make(conn, *, merchant_id: str = "mch_test0001"):
        from dwaar.crypto import keys as keymod
        from dwaar.db.repositories import principals

        pid = rand_id("prn")
        private = keymod.derive_private_key(AGENT_SEED, "principal", pid)
        return await principals.create(
            conn,
            principal_id=pid,
            merchant_id=merchant_id,
            public_key=keymod.public_bytes(private),
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

        from dwaar.crypto import keys as keymod
        from dwaar.crypto import mandate as mandatemod
        from dwaar.db.repositories import mandates

        agent = await make_agent(conn, merchant_id=merchant_id)
        principal = await make_principal(conn, merchant_id=merchant_id)

        # A GENUINELY signed mandate, not a placeholder.
        #
        # An earlier version wrote canonical_json='{"test":true}' with a random hash. The
        # verifier caught it immediately — correctly, because such a row is exactly the
        # shape of a tampered mandate: columns that disagree with the bytes that were
        # signed. Fixtures that a verifier would reject are fixtures that cannot be used to
        # test a verifier.
        mandate_id = rand_id("mnd")
        expires_at = datetime.now(UTC) + timedelta(days=30)
        payload = mandatemod.build_payload(
            mandate_id=mandate_id,
            principal_id=principal["principal_id"],
            agent_id=agent["agent_id"],
            max_total_paise=max_total_paise,
            max_per_txn_paise=max_per_txn_paise,
            allow_categories=["groceries", "apparel"],
            deny_categories=["gift_cards"],
            substitution_tolerance="same_price",
            expires_at=expires_at,
            nonce=uuid.uuid4().hex,
        )
        canonical = mandatemod.canonical_json(payload)
        principal_key = keymod.derive_private_key(
            AGENT_SEED, "principal", principal["principal_id"]
        )

        return await mandates.create(
            conn,
            mandate_id=mandate_id,
            principal_id=principal["principal_id"],
            agent_id=agent["agent_id"],
            max_total_paise=max_total_paise,
            max_per_txn_paise=max_per_txn_paise,
            expires_at=expires_at,
            nonce=payload["nonce"],
            canonical_json=canonical,
            signature=principal_key.sign(canonical.encode()),
            mandate_hash=mandatemod.mandate_hash(payload),
            allow_categories=["groceries", "apparel"],
            deny_categories=["gift_cards"],
            substitution_tolerance="same_price",
        )

    return _make


@pytest.fixture
def nonce_store():
    """In-memory. Named so its unsuitability for production is visible at the call site —
    under multiple workers it is several disjoint sets and the control stops working."""
    from dwaar.nonce import InMemoryNonceStore

    return InMemoryNonceStore()


@pytest.fixture
def sign_headers():
    """Produce real RFC 9421 headers for a request body.

    Every pipeline test signs for real. A helper that skipped signing would mean the
    authenticated path is exercised only by the tests that specifically test signing —
    which is how an auth regression reaches a demo.
    """
    import json as _json
    import time as _time
    import uuid as _uuid

    from dwaar.crypto import http_sig
    from dwaar.crypto import keys as keymod

    def _sign(agent_id: str, body: dict, *, seed: int = 20260905,
              method: str = "POST", path: str = "/v1/authorize",
              created: int | None = None, nonce: str | None = None,
              private_key=None):
        raw = _json.dumps(body, separators=(",", ":")).encode()
        key = private_key or keymod.derive_private_key(seed, "agent", agent_id)
        headers = http_sig.sign_request(
            key, method=method, path=path, body=raw, keyid=agent_id,
            created=created if created is not None else int(_time.time()),
            nonce=nonce or _uuid.uuid4().hex,
        )
        return headers, raw

    return _sign


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
            "request_idempotency_key": None,
            "decision": decision,
            "reason_code": "allowed" if decision == "allow" else "denied",
            # NULL, not False. This fixture writes a record without running the detection
            # stage, so claiming "checked and clean" would be a fixture asserting something
            # the verifier — and migration 0014's constraint — would reject. Same lesson as
            # F-018: a fixture a control would refuse cannot be used to test that control.
            "injection_flag": None,
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


@pytest.fixture
def authorize_signed(nonce_store, signer, settings):
    """Run the pipeline with a REAL signature. The only way tests call authorize.

    There is deliberately no unsigned path in the test suite: if one existed, most tests
    would use it and the authenticated path would be exercised only by the tests that
    specifically test authentication.
    """
    import json as _json
    import time as _time
    import uuid as _uuid

    from dwaar.authorize import pipeline
    from dwaar.authorize.types import AuthorizeRequest
    from dwaar.crypto import http_sig
    from dwaar.crypto import keys as keymod

    # Real stages need real collaborators. A pipeline test run without an observation store
    # and without a scorer exercises the two degraded paths and nothing else — every record
    # it writes would carry `features_degraded` and `risk_model_unavailable`, and the tests
    # asserting on `degraded_mode` would be asserting about the test harness.
    #
    # One store per fixture instance, so windows do not leak between tests. The scorer
    # returns a fixed, confidently-benign score: tests that care about a specific score pass
    # their own, and a low default keeps an `allow` an `allow`.
    from dwaar.risk import injection as injectionmod
    from dwaar.risk.observations import InMemoryObservationStore
    from tests._support.fakes import FixedScorer

    default_store = InMemoryObservationStore()
    default_scorer = FixedScorer(0.05)

    # The REAL detector, not a double. It needs no database and no session — eleven
    # arithmetic features and a dot product — so there is no reason for a test to run
    # without it, and running without one would make `injection_flag` NULL on every record
    # and quietly break the tristate constraint added in migration 0014.
    default_detector = injectionmod.load()

    async def _run(conn, request: AuthorizeRequest, *, commit=True, private_key=None,
                   created=None, nonce=None, path="/v1/authorize", **kw):
        body = _json.dumps(
            {
                "agent_id": request.agent_id,
                "mandate_id": request.mandate_id,
                "action": request.action,
                "amount_paise": request.amount_paise,
                "idempotency_key": request.idempotency_key,
                "category": request.category,
            },
            separators=(",", ":"),
        ).encode()
        key = private_key or keymod.derive_private_key(AGENT_SEED, "agent", request.agent_id)
        # Sign at the pipeline's clock. The signature stage now holds ONE clock — `now`
        # governs skew as well as the key-rotation window — so a test that advances `now` to
        # reach an expiry or a rotation boundary must sign at the advanced clock too. A
        # request that claims to happen at time T and is signed at time T is also what
        # actually happens; the previous arrangement was signing in the present and claiming
        # to be from a year hence.
        stamped = kw.get("now")
        if created is None and stamped is not None:
            created = int(stamped.timestamp())
        headers = http_sig.sign_request(
            key, method="POST", path=path, body=body, keyid=request.agent_id,
            created=created if created is not None else int(_time.time()),
            nonce=nonce or _uuid.uuid4().hex,
        )
        kw.setdefault("observation_store", default_store)
        kw.setdefault("scorer", default_scorer)
        kw.setdefault("detector", default_detector)
        outcome = await pipeline.authorize(
            request, conn=conn, signer=signer, settings=settings,
            headers=headers, body=body, path=path, nonce_store=nonce_store, **kw
        )
        if commit:
            await conn.commit()
        return outcome

    return _run
