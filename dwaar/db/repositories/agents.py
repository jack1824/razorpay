"""Agents repository. Merchant-scoped identity registry."""

from __future__ import annotations

from typing import Any

from psycopg import AsyncConnection

from dwaar.db.repositories.base import KEY_BYTES, execute, fetch_all, fetch_one, from_hex

_COLUMNS = (
    "agent_id, display_name, public_key, registered_by, status, "
    "key_rotated_at, previous_public_key, created_at"
)


async def create(
    conn: AsyncConnection,
    *,
    agent_id: str,
    display_name: str,
    public_key: str | bytes,
    registered_by: str,
    status: str = "active",
) -> dict[str, Any]:
    return await fetch_one(
        conn,
        f"INSERT INTO agents (agent_id, display_name, public_key, registered_by, status) "
        f"VALUES (%s, %s, %s, %s, %s) RETURNING {_COLUMNS}",
        (
            agent_id,
            display_name,
            from_hex(public_key, expect_len=KEY_BYTES),
            registered_by,
            status,
        ),
    )


async def get(conn: AsyncConnection, agent_id: str) -> dict[str, Any] | None:
    return await fetch_one(
        conn, f"SELECT {_COLUMNS} FROM agents WHERE agent_id = %s", (agent_id,)
    )


async def list_for_merchant(conn: AsyncConnection, merchant_id: str) -> list[dict[str, Any]]:
    return await fetch_all(
        conn,
        f"SELECT {_COLUMNS} FROM agents WHERE registered_by = %s ORDER BY created_at",
        (merchant_id,),
    )


async def set_status(conn: AsyncConnection, agent_id: str, status: str) -> bool:
    """Suspend or revoke. Threat 1 recovery: auto-suspend after N signature failures."""
    if status not in {"active", "suspended", "revoked"}:
        raise ValueError(f"invalid status: {status}")
    return await execute(
        conn, "UPDATE agents SET status = %s WHERE agent_id = %s", (status, agent_id)
    ) == 1


async def rotate_key(
    conn: AsyncConnection, agent_id: str, new_public_key: str | bytes
) -> dict[str, Any] | None:
    """Rotate with an overlap window: the old key moves to previous_public_key.

    Verification accepts either key while ``key_rotated_at`` is inside the overlap window,
    so a rotation does not reject requests already in flight. Threat 3.
    """
    return await fetch_one(
        conn,
        f"UPDATE agents SET previous_public_key = public_key, public_key = %s, "
        f"key_rotated_at = now() WHERE agent_id = %s RETURNING {_COLUMNS}",
        (from_hex(new_public_key, expect_len=KEY_BYTES), agent_id),
    )
