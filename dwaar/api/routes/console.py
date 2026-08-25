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


# ── the three panels that landed on day 30 ──────────────────────────────────────────


#: How long a verification result may be served before it is recomputed.
#:
#: Verifying 13,255 records takes about five seconds — every one is re-canonicalised and its
#: signature checked, which is the point and is not something to make faster by checking
#: less. Five seconds is fine for `make verify` and unusable for a panel that polls.
#:
#: So the result is cached and the panel shows its AGE. Three seconds is chosen from demo
#: beat 6: the tamper happens, the presenter says a sentence, and the panel goes red while
#: they are still on it. A longer TTL would make the beat wait on the console; a shorter one
#: would have the API re-verifying the whole chain continuously.
VERIFY_TTL_SECONDS = 3.0


@router.get("/verify")
async def chain_verification(request: Request, merchant_id: str = "mch_demo0001"):
    """Demo beat 6's panel: a big green PASS, or CHAIN BROKEN AT SEQ N.

    ── This is a CONVENIENCE, and the docstring says so where a reader will see it ─────

    `dwaar/verify_cli.py` is the artifact that answers "why should I believe your audit
    log": a separate process, a read-only connection, no cooperation from the running
    service. This endpoint runs the same function inside the API, which by definition asks
    you to trust the thing being verified.

    So the panel renders the command beside the result. The verdict on screen is for the
    room; `make verify` is for the reader who does not take our word for it.

    Run in a thread because the verifier is synchronous psycopg by design — it opens its own
    read-only connection rather than borrowing the app's pool, and borrowing the pool would
    make it depend on the application's connection settings.
    """
    import asyncio
    import time

    from dwaar.verify_cli import verify

    app = request.app
    cache = getattr(app.state, "verify_cache", None)
    if cache is None:
        cache = app.state.verify_cache = {}

    # `perf_counter`, not the clock seam: this measures an AGE, and a wall clock that steps
    # backwards would serve a stale verification forever. See dwaar/clock.py on why
    # durations deliberately stay monotonic.
    now = time.perf_counter()
    entry = cache.get(merchant_id)
    if entry is not None and now - entry[0] < VERIFY_TTL_SECONDS:
        findings, verified_ago = entry[1], now - entry[0]
    else:
        dsn = app.state.settings.database_url_app
        findings = await asyncio.to_thread(verify, dsn, merchant=merchant_id)
        cache[merchant_id] = (time.perf_counter(), findings)
        verified_ago = 0.0

    # The seq the panel puts on screen. The verifier writes an identifier two ways —
    # `seq=N (merchant)` for chain failures and `decision_records N:` for column failures —
    # so both are read rather than the first one that happened to be implemented.
    broken_at = None
    for failure in findings.failures:
        for token in failure.replace(":", " ").split():
            if token.startswith("seq="):
                broken_at = int(token.removeprefix("seq="))
                break
            if token.isdigit() and "decision_records" in failure:
                broken_at = int(token)
                break
        if broken_at is not None:
            break

    return {
        "ok": findings.ok,
        "merchant_id": merchant_id,
        "checked": findings.checked,
        "records": findings.checked.get("decision_records.chain", 0),
        "failures": findings.failures,
        "broken_at_seq": broken_at,
        # Reported, never treated as a break: a Postgres outage produces denials that cannot
        # be chained, and absence must not read as a tamper. See FAIL_MATRIX.md.
        "gaps": findings.gaps.get(merchant_id, []),
        # Records written before an invariant was enforced. Counted rather than hidden.
        "legacy": findings.legacy,
        # The age of this result, in seconds. Shown on the panel so nobody reads a cached
        # PASS as a live one — the same reason the SIMULATED badge exists.
        "verified_ago_s": round(verified_ago, 1),
        "command": "make verify",
    }


@router.get("/mcp")
async def mcp_calls(request: Request, merchant_id: str = "mch_demo0001", limit: int = 25):
    """Demo beat 7's panel: tool called, scope required, scopes delegated, decision.

    Every column comes from the CHAIN. `tool` is a signed field of the record (migration
    0017) and the delegated scopes come from the mandate the record names by hash — so this
    panel is a view of what was recorded, not a parallel account assembled for display.

    That distinction cost a migration. The alternative was an in-process ring buffer of
    recent tool calls, which would have been an hour's work and would have made the console
    a second source of truth about what happened. `rule_fired` and the scope map are enough
    to render the required scope without storing it, because the map is versioned with the
    deploy and a record naming a tool resolves through it deterministically.
    """
    from dwaar.mcp import scopes as scopemod

    async with request.app.state.pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            "SELECT d.record_id, d.seq, d.created_at, d.agent_id, d.tool, d.decision, "
            "       d.reason_code, d.rule_fired, d.amount_paise, d.risk_score, "
            "       m.scopes AS delegated "
            "FROM decision_records d "
            "LEFT JOIN mandates m ON m.mandate_hash = d.mandate_hash "
            "WHERE d.merchant_id = %s AND d.tool IS NOT NULL "
            "ORDER BY d.seq DESC LIMIT %s",
            (merchant_id, min(limit, 100)),
        )
        columns = [c.name for c in cur.description]
        rows = [dict(zip(columns, r, strict=True)) for r in await cur.fetchall()]

    calls = []
    for row in rows:
        rule = scopemod.rule_for(row["tool"])
        calls.append(
            {
                "seq": row["seq"],
                "record_id": str(row["record_id"]),
                "created_at": row["created_at"].isoformat(),
                "agent_id": row["agent_id"],
                "tool": row["tool"],
                # None means the tool is unlisted, which is DENIED — not unknown-and-allowed.
                "required_scope": rule.scope if rule else None,
                "money_direction": rule.money_direction if rule else None,
                "delegated": list(row["delegated"]) if row["delegated"] is not None else [],
                # NULL scopes and [] behave identically at the gate and differ in the record.
                "delegated_is_null": row["delegated"] is None,
                "decision": row["decision"],
                "reason_code": row["reason_code"],
                "rule_fired": row["rule_fired"],
                "amount_paise": row["amount_paise"],
                "amount_display": (
                    format_inr(row["amount_paise"]) if row["amount_paise"] else None
                ),
                # The headline artifact on a scope denial: no model was consulted, because
                # the mandate settled it on its own terms.
                "risk_score_is_null": row["risk_score"] is None,
            }
        )
    return {"calls": calls, "known_tools": sorted(scopemod.load())}


@router.get("/explanations/{record_id}")
async def explanation(request: Request, record_id: str):
    """The explainer's text for one record, if it has arrived.

    `null` is a normal answer, not an error: the explainer is asynchronous and may be
    behind, or dead. The console renders the absence rather than an error state, which is
    what "killing it changes nothing" has to look like on screen.
    """
    async with request.app.state.pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            "SELECT body, model, cached, generated_at FROM explanations WHERE record_id = %s",
            (record_id,),
        )
        row = await cur.fetchone()
    if row is None:
        return {"explanation": None, "reason": "not generated yet"}
    body, model, cached, generated_at = row
    return {
        "explanation": body,
        # NULL means no model was called — cache hit or deterministic fallback. Kept
        # distinct so the console can say which, rather than implying every sentence came
        # from a model.
        "model": model,
        "cached": cached,
        "generated_at": generated_at.isoformat(),
    }
