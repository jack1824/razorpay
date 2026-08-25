"""`python -m dwaar.explain.worker` — the container demo beat 5 kills.

Reads `dwaar:explain`, generates text, writes `explanations`. Connects with
``DATABASE_URL_EXPLAINER``, whose role holds SELECT on `decision_records` and INSERT here
and nothing else, so what this process is ALLOWED to do is a property of the database rather
than of this file.

── Failure posture: the loosest in the system, deliberately ────────────────────────────

Every other component in `FAIL_MATRIX.md` either fails closed or degrades. This one just
stops. No decision changes, no record is missing, no budget is affected — the explanations
simply stop appearing and the console renders their absence. `/health` reports it as `down`
with severity NOMINAL, which is `dwaar/components.py`'s one genuinely interesting entry:
an operator should know, and the gateway is not impaired.

That is the whole content of demo beat 5's first half, and it should be visibly boring.

── Consumer groups, and why a crash mid-message is not a lost explanation ──────────────

A consumer group with explicit acknowledgement. A message is acknowledged only after the
explanation is committed, so killing the container mid-generation leaves the message pending
and a restart picks it up. Nothing about that is load-bearing for a decision; it exists so
that "kill it and restart it" during the demo comes back to a complete panel rather than a
gap someone has to explain.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from typing import Any

import psycopg
from psycopg.rows import dict_row
from redis.asyncio import Redis

from dwaar.explain.cache import band_for, cache_key
from dwaar.explain.render import fallback_text, prompt_for
from dwaar.logging import configure_logging, get_logger
from dwaar.outbox import STREAM

log = get_logger("dwaar.explain.worker")

GROUP = "explainers"
BLOCK_MS = 2_000
BATCH = 16

DEFAULT_DSN = "postgresql://dwaar_explainer:explainer_pw@localhost:5432/dwaar"

#: Columns the explainer may read. It has SELECT on the whole table; naming them here keeps
#: the prompt's inputs auditable in one place rather than "whatever the row had".
COLUMNS = (
    "record_id, merchant_id, seq, decision, reason_code, rule_fired, risk_score, "
    "amount_paise, bounded_amount_paise, tool, degraded_mode"
)


class Explainer:
    def __init__(self, *, dsn: str, redis_url: str, use_model: bool = True) -> None:
        self.dsn = dsn
        self.redis_url = redis_url
        self.use_model = use_model
        self._stopping = asyncio.Event()
        #: Process-local, in front of the database's own UNIQUE. A burst of thirty denials
        #: with one reason is one model call, and the thirty rows share its text.
        self._memo: dict[str, tuple[str, str | None]] = {}

    def stop(self) -> None:
        self._stopping.set()

    async def run(self) -> int:
        redis = Redis.from_url(self.redis_url)
        try:
            await redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        except Exception as exc:  # noqa: BLE001 — BUSYGROUP means it already exists
            if "BUSYGROUP" not in str(exc):
                log.error("explain_group_failed", error_type=type(exc).__name__)

        conn = await psycopg.AsyncConnection.connect(self.dsn, row_factory=dict_row)
        log.info("explainer_started", stream=STREAM, group=GROUP, model=self.use_model)
        written = 0
        try:
            while not self._stopping.is_set():
                try:
                    batches = await redis.xreadgroup(
                        GROUP, "worker-1", {STREAM: ">"}, count=BATCH, block=BLOCK_MS
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning("explain_read_failed", error_type=type(exc).__name__)
                    await asyncio.sleep(1.0)
                    continue

                for _stream, messages in batches or []:
                    for message_id, fields in messages:
                        record_id = _decode(fields, "record_id")
                        try:
                            if await self.explain(conn, record_id):
                                written += 1
                            await redis.xack(STREAM, GROUP, message_id)
                        except Exception as exc:  # noqa: BLE001
                            # NOT acknowledged: the message stays pending and a restart
                            # retries it. Nothing downstream depends on it either way.
                            log.warning(
                                "explain_failed",
                                record_id=record_id,
                                error_type=type(exc).__name__,
                            )
        finally:
            await conn.close()
            await redis.aclose()
            log.info("explainer_stopped", written=written)
        return written

    async def explain(self, conn, record_id: str) -> bool:
        """Read the record, produce text, insert. Returns False when already explained."""
        async with conn.cursor() as cur:
            await cur.execute(
                f"SELECT {COLUMNS} FROM decision_records WHERE record_id = %s",  # noqa: S608
                (record_id,),
            )
            row = await cur.fetchone()
        if row is None:
            # The record does not exist. Not an error worth retrying: the only way to get
            # here is a stream that outlived its database.
            log.warning("explain_record_missing", record_id=record_id)
            return False

        key = cache_key(
            rule_fired=row["rule_fired"],
            decision=row["decision"],
            risk_band=band_for(row["risk_score"]),
        )
        body, model = await self.text_for(key, row)

        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO explanations "
                "(record_id, merchant_id, seq, cache_key, body, model, cached) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT ON CONSTRAINT explanations_record_unique DO NOTHING "
                "RETURNING explanation_id",
                (record_id, row["merchant_id"], row["seq"], key, body, model, model is None),
            )
            inserted = await cur.fetchone()
        await conn.commit()
        return inserted is not None

    async def text_for(self, key: str, row: dict[str, Any]) -> tuple[str, str | None]:
        """`(body, model)`. `model is None` means no call was made — cache or fallback."""
        if key in self._memo:
            return self._memo[key][0], None
        if not self.use_model:
            return fallback_text(row), None
        try:
            # Imported HERE and nowhere near a request path. `tests/test_hot_path_purity.py`
            # walks the closure from `dwaar.api.app` and fails the build if this module
            # becomes reachable from it.
            from dwaar.llm import client as llm  # noqa: PLC0415

            text = await llm.complete(prompt_for(row))
            body, model = text.strip(), llm.DEFAULT_MODEL
        except Exception as exc:  # noqa: BLE001
            # The floor, not a degradation. A merchant still gets a sentence.
            log.warning("explain_model_unavailable", error_type=type(exc).__name__)
            return fallback_text(row), None
        self._memo[key] = (body, model)
        return body, model


def _decode(fields: dict, name: str) -> str:
    value = fields.get(name.encode()) or fields.get(name)
    return value.decode() if isinstance(value, bytes) else str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dwaar-explainer", description=__doc__.splitlines()[0])
    parser.add_argument("--dsn", default=os.environ.get("DATABASE_URL_EXPLAINER", DEFAULT_DSN))
    parser.add_argument("--redis-url", default=os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    parser.add_argument(
        "--no-model",
        action="store_true",
        help="use the deterministic fallback only — no network, no key needed",
    )
    args = parser.parse_args(argv)

    configure_logging(os.environ.get("LOG_LEVEL", "INFO"))
    worker = Explainer(dsn=args.dsn, redis_url=args.redis_url, use_model=not args.no_model)

    async def run() -> int:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, worker.stop)
        return await worker.run()

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
