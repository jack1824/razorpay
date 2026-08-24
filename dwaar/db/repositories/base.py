"""Repository base helpers.

No ORM anywhere, in or out of the hot path. These are thin functions over psycopg cursors
holding hand-written SQL.

**The bytes/hex boundary lives here and nowhere else** (ADR 0001 item 10). Hashes, keys and
signatures are ``BYTEA`` in PostgreSQL and lowercase hex at every JSON surface — the API,
the verifier, the fixtures. If that conversion leaks into route handlers or the crypto
layer, the two representations start diverging and a signature that verifies in one place
fails in another.
"""

from __future__ import annotations

from typing import Any

from psycopg import AsyncConnection
from psycopg.rows import dict_row

HASH_BYTES = 32
SIG_BYTES = 64
KEY_BYTES = 32


def to_hex(raw: bytes | memoryview | None) -> str | None:
    """BYTEA → lowercase hex, for any JSON boundary."""
    if raw is None:
        return None
    return bytes(raw).hex()


def from_hex(
    value: str | bytes | memoryview | None, *, expect_len: int | None = None
) -> bytes | None:
    """Hex (or raw bytes) → BYTEA, validating length at the boundary.

    Length is checked here rather than relying on the table CHECK, so a malformed value is
    rejected with a useful message instead of a constraint violation from three frames down.
    """
    if value is None:
        return None
    raw = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
    if expect_len is not None and len(raw) != expect_len:
        raise ValueError(f"expected {expect_len} bytes, got {len(raw)}")
    return raw


async def fetch_one(conn: AsyncConnection, sql: str, params: tuple = ()) -> dict[str, Any] | None:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, params)
        return await cur.fetchone()


async def fetch_all(conn: AsyncConnection, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, params)
        return await cur.fetchall()


async def execute(conn: AsyncConnection, sql: str, params: tuple = ()) -> int:
    async with conn.cursor() as cur:
        await cur.execute(sql, params)
        return cur.rowcount
