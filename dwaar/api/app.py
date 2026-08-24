"""FastAPI application factory.

Note what this module does *not* import: no LLM client, no risk model, no `zoo`. That is
not incidental — `tests/test_hot_path_purity.py` walks the transitive import closure from
here and fails the build if an LLM ever becomes reachable from a request path.

The pool opened here uses ``DATABASE_URL_APP``: the non-owner role. The API has no
connection capable of UPDATE or DELETE on ``decision_records``, and that is what makes the
append-only claim a control rather than a convention.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from psycopg_pool import AsyncConnectionPool

from dwaar import __version__
from dwaar.api.middleware import BodySizeLimitMiddleware, TraceIDMiddleware
from dwaar.api.routes import health
from dwaar.config import Settings, get_settings
from dwaar.logging import configure_logging, get_logger

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

    log.info("startup", version=__version__, component="api")
    try:
        yield
    finally:
        await pool.close()
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

    app.include_router(health.router, tags=["ops"])
    return app


app = create_app()
