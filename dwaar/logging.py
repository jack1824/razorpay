"""Structured JSON logging with per-request trace IDs.

Two decisions worth stating, both from threat 14 (data leakage via logs):

**The field policy is an allowlist, not a denylist.** A denylist fails silently the first
time someone logs a field nobody thought of — and in a payments system the field nobody
thought of is the one that matters. Anything not in ``ALLOWED_FIELDS`` is replaced with
``<redacted>``; the key survives so the redaction is visible in the log rather than the
field vanishing.

**Free text is never loggable at all.** ``free_text`` is attacker-controlled by definition
(trust boundary 1) and is the injection surface. It is not on the allowlist and cannot be
added to it — the redactor drops it by key regardless of nesting depth.

The trace ID is a ContextVar rather than a parameter, so every log line in a request
carries it without any call site having to thread it through.
"""

from __future__ import annotations

import logging
import sys
import uuid
from contextvars import ContextVar
from typing import Any

import structlog

_trace_id: ContextVar[str | None] = ContextVar("dwaar_trace_id", default=None)

# Fields that may appear in a log line with their values intact.
#
# Rule for adding one: it must be an identifier, a decision, a measurement, or a coarse
# reason code. Never a monetary amount attributable to a natural person, never key
# material, never agent-supplied text.
ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        # structlog / stdlib plumbing
        "event", "level", "logger", "timestamp", "exc_info", "exception", "stack",
        # request identity
        "trace_id", "method", "path", "status_code", "duration_ms", "client_host",
        # domain identifiers — opaque, not personal
        "agent_id", "principal_id", "mandate_id", "merchant_id", "policy_id",
        "decision_id", "record_id", "entry_id", "seq", "signing_key_id",
        # decisions and measurements
        "decision", "reason_code", "rule_fired", "risk_score", "injection_flag",
        "latency_us", "degraded_mode", "policy_version", "chain_seq",
        # Behavioural feature VALUES — velocity, burst index, and similar aggregates.
        # Allowed because they are already in the signed decision record and are what
        # makes a decision explainable after the fact. Nested keys are still filtered:
        # ALWAYS_REDACT applies at every depth, so a secret cannot ride in inside this.
        "features",
        # operational
        "migration", "version", "applied", "component", "role", "count", "attempt",
        "table", "duration_s", "ok", "error_type",
    }
)

# Dropped by key at any depth, whatever the allowlist says. These are the surfaces where a
# leak is not a privacy problem but an attack surface or a credential.
ALWAYS_REDACT: frozenset[str] = frozenset(
    {
        "free_text", "order_note", "note", "password", "secret", "token",
        "authorization", "signature", "private_key", "secret_key", "dsn",
        "database_url", "database_url_app", "database_url_migrate",
        "database_url_superuser", "redis_url",
    }
)

_REDACTED = "<redacted>"
_MAX_DEPTH = 6


def new_trace_id() -> str:
    return uuid.uuid4().hex


def set_trace_id(trace_id: str | None) -> str:
    tid = trace_id or new_trace_id()
    _trace_id.set(tid)
    return tid


def get_trace_id() -> str | None:
    return _trace_id.get()


def _redact_value(value: Any, depth: int = 0) -> Any:
    """Walk nested structures so a disallowed key cannot hide inside a dict."""
    if depth >= _MAX_DEPTH:
        return _REDACTED
    if isinstance(value, dict):
        return {
            k: (_REDACTED if _is_redacted_key(k) else _redact_value(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(v, depth + 1) for v in value]
    return value


def _is_redacted_key(key: str) -> bool:
    return key.lower() in ALWAYS_REDACT


def allowlist_processor(_logger: Any, _name: str, event_dict: dict) -> dict:
    """Replace the value of any key not on the allowlist. Keys are kept, values are not.

    Keeping the key makes redaction auditable — you can see in the log that a field was
    present and suppressed, which a denylist that silently passes it through cannot show
    you.
    """
    out: dict[str, Any] = {}
    for key, value in event_dict.items():
        if _is_redacted_key(key):
            out[key] = _REDACTED
        elif key in ALLOWED_FIELDS:
            out[key] = _redact_value(value)
        else:
            out[key] = _REDACTED
    return out


def trace_id_processor(_logger: Any, _name: str, event_dict: dict) -> dict:
    tid = _trace_id.get()
    if tid is not None:
        event_dict["trace_id"] = tid
    return event_dict


def configure_logging(level: str = "INFO") -> None:
    """Idempotent. Safe to call from app startup and from a test fixture."""
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
        force=True,
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            trace_id_processor,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            allowlist_processor,
            structlog.processors.JSONRenderer(sort_keys=True),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str = "dwaar") -> Any:
    return structlog.get_logger(name)
