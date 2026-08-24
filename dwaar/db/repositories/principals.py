"""Principals repository. The principal is the root of authority."""

from __future__ import annotations

from typing import Any

from psycopg import AsyncConnection

from dwaar.db.repositories.base import KEY_BYTES, fetch_all, fetch_one, from_hex

_COLUMNS = "principal_id, merchant_id, public_key, created_at"


async def create(
    conn: AsyncConnection,
    *,
    principal_id: str,
    merchant_id: str,
    public_key: str | bytes,
) -> dict[str, Any]:
    return await fetch_one(
        conn,
        f"INSERT INTO principals (principal_id, merchant_id, public_key) "
        f"VALUES (%s, %s, %s) RETURNING {_COLUMNS}",
        (principal_id, merchant_id, from_hex(public_key, expect_len=KEY_BYTES)),
    )


async def get(conn: AsyncConnection, principal_id: str) -> dict[str, Any] | None:
    return await fetch_one(
        conn, f"SELECT {_COLUMNS} FROM principals WHERE principal_id = %s", (principal_id,)
    )


async def list_for_merchant(conn: AsyncConnection, merchant_id: str) -> list[dict[str, Any]]:
    return await fetch_all(
        conn,
        f"SELECT {_COLUMNS} FROM principals WHERE merchant_id = %s ORDER BY created_at",
        (merchant_id,),
    )
