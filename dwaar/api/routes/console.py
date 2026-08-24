"""Console read endpoints: decision stream, agent roster, decision detail.

Read-only, and everything here is derived from `decision_records` and `budget_ledger` — the
console shows what the system actually recorded, never a parallel view assembled for
display. If the console and the audit trail could disagree, the console would be
decoration.

── Why the stream polls rather than listens ────────────────────────────────────────────

`LISTEN/NOTIFY` would be lower latency and is the obvious choice. It is not used because it
requires a dedicated connection held open outside the pool and a trigger on
`decision_records` — a trigger on the append-only table whose whole point is that nothing
mutates it, added for a display feature. Polling `seq > last_seen` on an indexed column at
500ms is unnoticeable on a projector and costs the audit trail nothing.

── Auth ────────────────────────────────────────────────────────────────────────────────

A static token, and it is a `[MOCK]` — stated in the architecture and stated here. It keeps
a browser tab out of the decision path; it is not an authentication system, and one would
be three days of scope for zero judge value.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from dwaar.db.repositories.base import to_hex
from dwaar.logging import get_logger
from dwaar.money import format_inr

log = get_logger("dwaar.api.console")

router = APIRouter(prefix="/v1/console", tags=["console"])

POLL_INTERVAL_SECONDS = 0.5
STREAM_PAGE = 50


def _row_to_summary(row: dict[str, Any]) -> dict[str, Any]:
    """One decision-stream row. Deliberately small — this is rendered at 1080p."""
    return {
        "seq": row["seq"],
        "record_id": str(row["record_id"]),
        "created_at": row["created_at"].isoformat(),
        "agent_id": row["agent_id"],
        "decision": row["decision"],
        "reason_code": row["reason_code"],
        "rule_fired": row["rule_fired"],
        "amount_paise": row["amount_paise"],
        "amount_display": format_inr(row["amount_paise"]) if row["amount_paise"] else None,
        "latency_us": row["latency_us"],
        # NULL is the point, not an absence. Carried explicitly so the console can render
        # the literal word rather than an empty cell that reads as "we forgot to fill it".
        "risk_score": float(row["risk_score"]) if row["risk_score"] is not None else None,
        "risk_score_is_null": row["risk_score"] is None,
        "degraded_mode": list(row["degraded_mode"]),
    }


@router.get("/decisions")
async def recent_decisions(request: Request, merchant_id: str = "mch_demo0001", limit: int = 50):
    """The most recent decisions, newest first."""
    async with request.app.state.pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            "SELECT record_id, seq, created_at, agent_id, decision, reason_code, "
            "       rule_fired, amount_paise, latency_us, risk_score, degraded_mode "
            "FROM decision_records WHERE merchant_id = %s ORDER BY seq DESC LIMIT %s",
            (merchant_id, min(limit, 200)),
        )
        columns = [c.name for c in cur.description]
        rows = [dict(zip(columns, r, strict=True)) for r in await cur.fetchall()]
    return {"decisions": [_row_to_summary(row) for row in rows]}


@router.get("/stream")
async def decision_stream(request: Request, merchant_id: str = "mch_demo0001"):
    """Server-sent events. One event per new decision, oldest first within a batch."""

    async def events():
        last_seq = 0
        async with request.app.state.pool.connection() as conn, conn.cursor() as cur:
            await cur.execute(
                "SELECT COALESCE(max(seq), 0) FROM decision_records WHERE merchant_id = %s",
                (merchant_id,),
            )
            last_seq = (await cur.fetchone())[0]

        while True:
            if await request.is_disconnected():
                return
            try:
                async with (
                    request.app.state.pool.connection() as conn,
                    conn.cursor() as cur,
                ):
                    await cur.execute(
                        "SELECT record_id, seq, created_at, agent_id, decision, "
                        "       reason_code, rule_fired, amount_paise, latency_us, "
                        "       risk_score, degraded_mode "
                        "FROM decision_records "
                        "WHERE merchant_id = %s AND seq > %s ORDER BY seq LIMIT %s",
                        (merchant_id, last_seq, STREAM_PAGE),
                    )
                    columns = [c.name for c in cur.description]
                    rows = [dict(zip(columns, r, strict=True)) for r in await cur.fetchall()]

                for row in rows:
                    last_seq = max(last_seq, row["seq"])
                    yield f"data: {json.dumps(_row_to_summary(row))}\n\n"
            except Exception as exc:  # noqa: BLE001
                # The console must survive a database blip: it is a debugging tool for
                # every remaining phase, and one that dies with the thing it is watching is
                # useless exactly when it is needed.
                log.warning("stream_poll_failed", error_type=type(exc).__name__)
                yield f": poll failed ({type(exc).__name__})\n\n"

            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/agents")
async def agent_roster(request: Request, merchant_id: str = "mch_demo0001"):
    """One card per agent, with the budget bar's numbers.

    `spent` comes from the ledger, not from summing decisions: the ledger is the enforcement
    record, and a bar driven by anything else could show a different number from the one
    that actually denied a request.
    """
    async with request.app.state.pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            """
                SELECT a.agent_id,
                       a.display_name,
                       a.status,
                       m.mandate_id,
                       m.max_total_paise,
                       m.max_per_txn_paise,
                       COALESCE(tail.balance_after, m.max_total_paise) AS remaining_paise,
                       COALESCE(counts.decisions, 0)                   AS decisions,
                       COALESCE(counts.denials, 0)                     AS denials
                FROM agents a
                JOIN mandates m ON m.agent_id = a.agent_id AND m.revoked_at IS NULL
                LEFT JOIN LATERAL (
                    SELECT balance_after FROM budget_ledger
                    WHERE mandate_id = m.mandate_id ORDER BY entry_id DESC LIMIT 1
                ) tail ON TRUE
                LEFT JOIN LATERAL (
                    SELECT count(*) AS decisions,
                           count(*) FILTER (WHERE decision = 'deny') AS denials
                    FROM decision_records
                    WHERE agent_id = a.agent_id AND merchant_id = %s
                ) counts ON TRUE
                WHERE a.registered_by = %s
                ORDER BY a.created_at
                """,
            (merchant_id, merchant_id),
        )
        columns = [c.name for c in cur.description]
        rows = [dict(zip(columns, r, strict=True)) for r in await cur.fetchall()]

    agents = []
    for row in rows:
        total = row["max_total_paise"]
        remaining = row["remaining_paise"]
        spent = total - remaining
        agents.append(
            {
                "agent_id": row["agent_id"],
                "display_name": row["display_name"],
                "status": row["status"],
                "mandate_id": row["mandate_id"],
                "max_total_paise": total,
                "max_per_txn_paise": row["max_per_txn_paise"],
                "remaining_paise": remaining,
                "spent_paise": spent,
                "remaining_display": format_inr(remaining),
                "total_display": format_inr(total),
                "per_txn_display": format_inr(row["max_per_txn_paise"]),
                "spent_fraction": (spent / total) if total else 0.0,
                "decisions": row["decisions"],
                "denials": row["denials"],
            }
        )
    return {"agents": agents}


@router.get("/decisions/{record_id}")
async def decision_detail(request: Request, record_id: str):
    """Everything the record holds, for the detail panel.

    Includes `canonical_json` — the exact bytes that were signed. A reader can hash it
    themselves and check it against `payload_hash` without trusting this endpoint.
    """
    async with request.app.state.pool.connection() as conn:
        from dwaar.db.repositories import decision_records

        row = await decision_records.get(conn, record_id)

    if row is None:
        return {"error": "not_found"}

    return {
        "record_id": str(row["record_id"]),
        "seq": row["seq"],
        "merchant_id": row["merchant_id"],
        "created_at": row["created_at"].isoformat(),
        "agent_id": row["agent_id"],
        "principal_id": row["principal_id"],
        "decision": row["decision"],
        "reason_code": row["reason_code"],
        "rule_fired": row["rule_fired"],
        "risk_score": float(row["risk_score"]) if row["risk_score"] is not None else None,
        "risk_score_is_null": row["risk_score"] is None,
        "model_version": row["model_version"],
        "injection_flag": row["injection_flag"],
        "amount_paise": row["amount_paise"],
        "amount_display": format_inr(row["amount_paise"]) if row["amount_paise"] else None,
        "budget_before": row["budget_before"],
        "budget_after": row["budget_after"],
        "features": row["features"],
        "policy_version": row["policy_version"],
        "latency_us": row["latency_us"],
        "degraded_mode": list(row["degraded_mode"]),
        "stages_executed": list(row["stages_executed"]),
        "prev_hash": to_hex(row["prev_hash"]),
        "payload_hash": to_hex(row["payload_hash"]),
        "signing_key_id": row["signing_key_id"],
        "canonical_json": row["canonical_json"],
    }
