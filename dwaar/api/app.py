"""FastAPI application factory.

Note what this module does *not* import: no LLM client, no `zoo`, and no training
framework. That is not incidental — `tests/test_hot_path_purity.py` walks the transitive
import closure from here and fails the build if either an LLM or a trainer becomes
reachable from a request path.

It DOES import `dwaar.risk.model`, and only here. The scorer is built once at startup and
injected into the pipeline, so the request path itself never imports ONNX Runtime or numpy:
`dwaar/authorize/stages/risk.py` accepts anything satisfying a small protocol. The point is
not to hide a dependency but to keep the thing that loads a 20MB inference runtime at the
composition root, where startup can pay for it and a failure to load can be reported as a
degraded component rather than a crash.

The pool opened here uses ``DATABASE_URL_APP``: the non-owner role. The API has no
connection capable of UPDATE or DELETE on ``decision_records``, and that is what makes the
append-only claim a control rather than a convention.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from psycopg_pool import AsyncConnectionPool
from redis.asyncio import Redis

from dwaar import __version__
from dwaar.api.middleware import BodySizeLimitMiddleware, TraceIDMiddleware
from dwaar.api.routes import authorize, console, health
from dwaar.config import Settings, get_settings
from dwaar.crypto.signer import derive_signer, ensure_registered
from dwaar.logging import configure_logging, get_logger
from dwaar.nonce import RedisNonceStore
from dwaar.policy.store import PolicyStore
from dwaar.risk import model as riskmodel
from dwaar.risk.observations import RedisObservationStore

log = get_logger("dwaar.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings

    pool = AsyncConnectionPool(
        conninfo=settings.database_url_app,
        min_size=settings.pool_min_size,
        max_size=settings.pool_max_size,
        open=False,
        # Do not block startup on the database. A Postgres outage must leave the API
        # running and denying (FAIL_MATRIX.md), not prevent it from booting.
        check=AsyncConnectionPool.check_connection,
    )
    app.state.pool = pool
    try:
        await pool.open(wait=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("pool_open_deferred", error_type=type(exc).__name__)

    # Dwaar's own signing identity. Derived from the seed, so the whole system is
    # reproducible from one integer; the public half is registered so the verifier can
    # resolve any record's key by the id the record names.
    signer = derive_signer(settings.signing_seed, keys_dir=settings.keys_dir)
    app.state.signer = signer
    try:
        async with pool.connection(timeout=2.0) as conn:
            await ensure_registered(conn, signer)
            await conn.commit()
        log.info("signing_key_registered", signing_key_id=signer.key_id)
    except Exception as exc:  # noqa: BLE001
        # Fail-closed is enforced per request by stage 8, which cannot write without a
        # registered key. Startup stays up so /health can report the condition.
        log.error("signing_key_registration_failed", error_type=type(exc).__name__)

    # Replay defence. Fails CLOSED if unreachable — see dwaar/nonce.py: we cannot tell a
    # first use from a replay, and guessing would be fail-open on identity.
    redis = Redis.from_url(settings.redis_url)
    app.state.redis = redis
    app.state.nonce_store = RedisNonceStore(redis)

    # Rolling behavioural windows. Same Redis, different failure posture from the nonce
    # store above: this one DEGRADES. Losing behavioural context costs judgment; losing
    # replay defence would cost authentication.
    app.state.observation_store = RedisObservationStore(redis)

    # One store per process, TTL-bounded. Hot-reloadable without a restart; replaced
    # wholesale so a request never sees a half-swapped ruleset.
    app.state.policy_store = PolicyStore()

    # The risk model. Loaded and PRE-WARMED here, never lazily on a request: ONNX Runtime
    # specialises kernels on first use, and paying that on the first authorize would be a
    # p99 breach caused entirely by the first request being first.
    #
    # `load()` returns None rather than raising when there is no bundle. A missing model is
    # a degraded state, not a broken one — the gate, the policy engine and the ledger are
    # unaffected, and every record made in that window says `risk_model_unavailable`.
    app.state.scorer = riskmodel.load(settings.model_dir)
    log.info(
        "risk_model",
        loaded=app.state.scorer is not None,
        model_version=getattr(app.state.scorer, "model_version", None),
        directory=str(settings.model_dir),
    )

    log.info("startup", version=__version__, component="api")
    try:
        yield
    finally:
        await pool.close()
        await redis.aclose()
        log.info("shutdown", component="api")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Dwaar — Agent Authorization Gateway",
        version=__version__,
        description=(
            "Authorization and policy enforcement for AI agents acting on money. "
            "No endpoint in this API invokes an LLM synchronously; asserted two "
            "independent ways in CI."
        ),
        lifespan=lifespan,
    )
    app.state.settings = settings

    # Order matters: the size cap runs before anything reads the body, and the trace ID
    # must wrap the cap so a 413 is still logged with a trace ID.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(TraceIDMiddleware)

    # The vite dev server runs on another port, so the console needs CORS in local
    # development. Scoped to localhost origins and to the console's read endpoints —
    # `/v1/authorize` is signed, so a browser origin cannot forge one either way.
    if settings.env == "local":
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
            allow_methods=["GET"],
            allow_headers=["*"],
        )

    app.include_router(health.router, tags=["ops"])
    app.include_router(authorize.router, tags=["authorize"])
    app.include_router(console.router)
    return app


app = create_app()
