"""The outbox: the gateway announcing that a record exists. Not an explainer.

── Why this is not in `dwaar/explain/` ─────────────────────────────────────────────────

It was, for about ten minutes, and `tests/test_hot_path_purity.py` failed the build:
`dwaar.explain` is on the blocklist, so importing it from `dwaar/api/routes/authorize.py`
made an LLM package reachable from the request path.

The right response was not to loosen the blocklist. `dwaar.explain` is listed bluntly on
purpose — the guard's value is that nobody can add an LLM import to that package later and
have it quietly become reachable from an API route. Relaxing it to `dwaar.llm` alone would
have traded a structural guarantee for a naming convenience.

So the boundary moved instead, and it moved to the line that was actually there:

    the GATEWAY publishes a fact          "record R exists in chain M at seq N"
    a CONSUMER interprets it              "here is what that means, in English"

Publishing a record identifier is a gateway concern with no model in it. Explaining is a
consumer concern with a model in it. `dwaar/explain/` imports this module; nothing imports
`dwaar/explain/`.

The check found the architecture drifting an hour after the drift, which is the second time
a structural test has caught something it was not written for. See DEFENSE.md entry 6.

── AFTER the commit, and best effort ───────────────────────────────────────────────────

Both halves matter and for different reasons.

**After the commit** because the record must be durable before anything can be asked to
explain it. A message published inside the transaction would be visible to the explainer
before the row it names, and the explainer would then either fail to find it or — worse —
find it and have the transaction roll back underneath.

**Best effort** because this is the last thing that happens to a request that has already
been answered. The agent has its decision, the ledger has moved, the chain has the record.
An exception here would turn a completed authorization into a 500, which is the opposite of
what an off-path component is for. So every failure is logged and swallowed, and the
explanation is simply absent — which the console renders as absent.

A Redis stream rather than a list because it is bounded (`MAXLEN ~`) and readers do not
consume destructively: two explainers, or one restarted mid-backlog, do not lose messages
between them.
"""

from __future__ import annotations

from typing import Any

from dwaar.logging import get_logger

log = get_logger("dwaar.outbox")

STREAM = "dwaar:explain"

#: Approximate cap. The explainer is the only reader and it is allowed to fall behind; what
#: it must not do is grow without bound on a laptop during a demo. `~` lets Redis trim on
#: node boundaries, which is cheaper and close enough for a queue nothing depends on.
MAX_STREAM_LENGTH = 10_000


async def publish(redis, *, record_id: str, merchant_id: str, seq: int) -> bool:
    """Announce a written record. Returns False when it could not be published.

    Deliberately carries only the record's IDENTITY. The explainer holds a database role of
    its own and reads the row itself, so nothing here can hand it a decision that differs
    from the one in the chain — the same reason `decision_records` stores `canonical_json`
    rather than rebuilding it on read.
    """
    if redis is None:
        return False
    try:
        await redis.xadd(
            STREAM,
            {"record_id": str(record_id), "merchant_id": merchant_id, "seq": str(seq)},
            maxlen=MAX_STREAM_LENGTH,
            approximate=True,
        )
        return True
    except Exception as exc:  # noqa: BLE001 — the request is already answered
        log.warning("explain_publish_failed", error_type=type(exc).__name__)
        return False


def outcome_fields(outcome: Any) -> dict[str, Any] | None:
    """Pull the three identifiers out of a `PipelineOutcome`, or None if it has no record.

    A replayed outcome has one and is deliberately NOT republished by the caller: a retried
    request is one decision delivered twice, and explaining it twice would put a second row
    against a record the table's UNIQUE constraint already refuses.
    """
    if getattr(outcome, "record_id", None) is None or getattr(outcome, "seq", None) is None:
        return None
    return {"record_id": outcome.record_id, "seq": outcome.seq}


# ── liveness ────────────────────────────────────────────────────────────────────────
#
# `/health` has to distinguish "the explainer is running" from "nothing has read this
# stream in a while", and it has to do it without importing anything from `dwaar/explain/`.
# Redis already knows: a consumer group records how long each consumer has been idle.
#
# The signal is therefore "a consumer read from this group recently", which is a fact rather
# than a heartbeat someone has to remember to send. A heartbeat table would be a second
# thing that can be stale in its own right.

#: A worker blocks for two seconds per read, so an alive one is idle for at most that plus
#: however long one explanation takes — a Gemini call is 500-2000ms. Ten seconds is
#: comfortably above the working case and comfortably below demo beat 5's twelve-second
#: window, which is the constraint that actually sets it: the console has to go amber while
#: the presenter is still talking about it.
LIVENESS_IDLE_MS = 10_000


async def explainer_status(redis) -> dict[str, Any]:
    """`{up, reason, backlog}` for `/health`. Never raises.

    `up=False` with `backlog=0` is a stream nobody has ever read; `up=False` with a backlog
    is the interesting one — that is `docker kill dwaar-llm-explainer`, and the backlog is
    the count of decisions that went on being made while the explainer was dead.
    """
    if redis is None:
        return {"up": False, "reason": "not configured", "backlog": 0}
    try:
        groups = await redis.xinfo_groups(STREAM)
    except Exception as exc:  # noqa: BLE001 — health never raises
        # No stream yet is not an error: nothing has been published, so nothing is late.
        name = type(exc).__name__
        reason = "no decisions published yet" if "ResponseError" in name else name
        return {"up": False, "reason": reason, "backlog": 0}

    backlog = 0
    for group in groups:
        backlog += int(_field(group, "pending", 0)) + int(_field(group, "lag", 0) or 0)

    try:
        consumers = await redis.xinfo_consumers(STREAM, "explainers")
    except Exception:  # noqa: BLE001
        return {"up": False, "reason": "no consumer group", "backlog": backlog}

    live = [c for c in consumers if int(_field(c, "idle", LIVENESS_IDLE_MS + 1)) < LIVENESS_IDLE_MS]
    if live:
        return {"up": True, "reason": None, "backlog": backlog}
    return {
        "up": False,
        "reason": (
            f"no consumer has read for {LIVENESS_IDLE_MS // 1000}s"
            if consumers
            else "no consumer has ever connected"
        ),
        "backlog": backlog,
    }


def _field(mapping: dict, name: str, default):
    """Redis returns bytes keys under some clients and str under others."""
    if name in mapping:
        return mapping[name]
    return mapping.get(name.encode(), default)
