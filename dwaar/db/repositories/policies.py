"""Policies repository. Compiled offline by an LLM, tested, human-approved, signed.

Nothing in this module is reachable from a request path. Compilation is a build-time
activity; the hot path reads the last approved version and evaluates it deterministically.

``approve()`` is the human gate. The schema refuses to approve a policy whose generated
tests have not passed (``policies_approved_implies_tested``), so the gate cannot be
skipped by an app that forgets to check.
"""

from __future__ import annotations

from typing import Any

from psycopg import AsyncConnection

from dwaar.db.repositories.base import SIG_BYTES, execute, fetch_all, fetch_one, from_hex

_COLUMNS = (
    "policy_id, merchant_id, version, source_nl, compiled_rules, generated_tests, "
    "tests_passed, approved_by, signature, created_at"
)


async def create(
    conn: AsyncConnection,
    *,
    policy_id: str,
    merchant_id: str,
    version: int,
    source_nl: str,
    compiled_rules: dict[str, Any] | list[Any],
    generated_tests: dict[str, Any] | list[Any],
    tests_passed: bool = False,
) -> dict[str, Any]:
    import json

    return await fetch_one(
        conn,
        f"INSERT INTO policies "
        f"(policy_id, merchant_id, version, source_nl, compiled_rules, generated_tests, "
        f" tests_passed) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING {_COLUMNS}",
        (
            policy_id,
            merchant_id,
            version,
            source_nl,
            json.dumps(compiled_rules, sort_keys=True),
            json.dumps(generated_tests, sort_keys=True),
            tests_passed,
        ),
    )


async def get(conn: AsyncConnection, policy_id: str) -> dict[str, Any] | None:
    return await fetch_one(
        conn, f"SELECT {_COLUMNS} FROM policies WHERE policy_id = %s", (policy_id,)
    )


async def get_live(conn: AsyncConnection, merchant_id: str) -> dict[str, Any] | None:
    """The highest approved version. NULL ``approved_by`` means not live, so it is excluded.

    This is what the hot path reads. If it returns None the merchant has no approved
    policy and, per `FAIL_MATRIX.md`, authority questions still resolve — the mandate and
    the ledger do not depend on a policy existing.
    """
    return await fetch_one(
        conn,
        f"SELECT {_COLUMNS} FROM policies "
        f"WHERE merchant_id = %s AND approved_by IS NOT NULL "
        f"ORDER BY version DESC LIMIT 1",
        (merchant_id,),
    )


async def list_versions(conn: AsyncConnection, merchant_id: str) -> list[dict[str, Any]]:
    return await fetch_all(
        conn,
        f"SELECT {_COLUMNS} FROM policies WHERE merchant_id = %s ORDER BY version DESC",
        (merchant_id,),
    )


async def mark_tests_passed(conn: AsyncConnection, policy_id: str, passed: bool) -> bool:
    return await execute(
        conn, "UPDATE policies SET tests_passed = %s WHERE policy_id = %s", (passed, policy_id)
    ) == 1


async def approve(
    conn: AsyncConnection,
    policy_id: str,
    *,
    approved_by: str,
    signature: str | bytes | None = None,
) -> bool:
    """The human gate. Fails on the DB CHECK if the generated tests have not passed."""
    if not approved_by.strip():
        raise ValueError("approved_by must name a person; the gate is the point")
    return await execute(
        conn,
        "UPDATE policies SET approved_by = %s, signature = %s WHERE policy_id = %s",
        (approved_by, from_hex(signature, expect_len=SIG_BYTES), policy_id),
    ) == 1
