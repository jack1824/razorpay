"""Connection pools.

Two DSNs, never interchangeable:

- ``app_pool()``     — ``dwaar_app``. Non-owner. No UPDATE/DELETE on ``decision_records``.
                       Everything the API does.
- ``owner_conn()``   — ``dwaar_owner``. Migrations and tests only. Never the API.

They are separate functions rather than one parameterised call so that reaching for the
owner connection from request-handling code is a visible act, not a changed argument.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import psycopg
from psycopg_pool import AsyncConnectionPool

from dwaar.config import Settings, get_settings


def make_app_pool(
    settings: Settings | None = None, *, open_now: bool = False
) -> AsyncConnectionPool:
    settings = settings or get_settings()
    return AsyncConnectionPool(
        conninfo=settings.database_url_app,
        min_size=settings.pool_min_size,
        max_size=settings.pool_max_size,
        open=open_now,
    )


@asynccontextmanager
async def owner_conn(settings: Settings | None = None):
    """A single owner connection. Migrations and tests only."""
    settings = settings or get_settings()
    async with await psycopg.AsyncConnection.connect(settings.database_url_migrate) as conn:
        yield conn
