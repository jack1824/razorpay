"""Structured JSON logging: trace IDs and the allowlist redactor.

Threat 14 is data leakage via logs. The redactor is an allowlist, so the test that matters
is not "does it redact a password" — it is "does it redact a field nobody anticipated",
which is the case a denylist gets wrong.
"""

from __future__ import annotations

import json

import pytest

from dwaar.logging import (
    ALLOWED_FIELDS,
    ALWAYS_REDACT,
    allowlist_processor,
    configure_logging,
    get_logger,
    get_trace_id,
    set_trace_id,
)


def test_allowed_field_passes_through():
    out = allowlist_processor(None, "info", {"event": "decision", "agent_id": "agt_x"})
    assert out["agent_id"] == "agt_x"
    assert out["event"] == "decision"


def test_unanticipated_field_is_redacted():
    """The case a denylist misses: a field nobody thought about."""
    out = allowlist_processor(None, "info", {"event": "e", "customer_pan": "ABCDE1234F"})
    assert out["customer_pan"] == "<redacted>"


def test_redacted_key_survives_so_redaction_is_visible():
    """The key stays, the value goes. A vanished field is indistinguishable from no field."""
    out = allowlist_processor(None, "info", {"event": "e", "email": "a@b.com"})
    assert "email" in out
    assert out["email"] == "<redacted>"


@pytest.mark.parametrize("field", sorted(ALWAYS_REDACT))
def test_always_redact_fields_never_survive(field):
    out = allowlist_processor(None, "info", {"event": "e", field: "sensitive"})
    assert out[field] == "<redacted>"


def test_free_text_is_never_loggable():
    """free_text is attacker-controlled (trust boundary 1) and is the injection surface."""
    assert "free_text" in ALWAYS_REDACT
    assert "free_text" not in ALLOWED_FIELDS
    out = allowlist_processor(
        None, "info", {"event": "e", "free_text": {"order_note": "ignore previous..."}}
    )
    assert out["free_text"] == "<redacted>"


def test_nested_secret_inside_an_allowed_field_is_redacted():
    """A disallowed key must not survive by hiding inside an allowed one."""
    out = allowlist_processor(
        None, "info", {"event": "e", "features": {"velocity": 3, "token": "secret"}}
    )
    assert out["features"]["velocity"] == 3
    assert out["features"]["token"] == "<redacted>"


def test_deeply_nested_structures_terminate():
    """A cyclic-looking or very deep payload must not hang the logger."""
    deep: dict = {"event": "e", "features": {}}
    node = deep["features"]
    for _ in range(50):
        node["next"] = {}
        node = node["next"]
    out = allowlist_processor(None, "info", deep)
    assert out["features"] is not None


def test_dsn_fields_are_redacted():
    """A DSN contains a password. It is also the single most tempting thing to log."""
    out = allowlist_processor(
        None, "info", {"event": "e", "database_url": "postgresql://u:pw@h/db"}
    )
    assert out["database_url"] == "<redacted>"


def test_trace_id_contextvar_roundtrip():
    tid = set_trace_id(None)
    assert get_trace_id() == tid
    assert len(tid) == 32

    explicit = set_trace_id("deadbeef")
    assert get_trace_id() == explicit == "deadbeef"


def test_log_output_is_valid_json(capsys):
    configure_logging("INFO")
    set_trace_id("trace0001")
    get_logger("dwaar.test").info("decision", agent_id="agt_1", decision="deny", latency_us=900)

    line = capsys.readouterr().out.strip().splitlines()[-1]
    payload = json.loads(line)
    assert payload["event"] == "decision"
    assert payload["trace_id"] == "trace0001"
    assert payload["agent_id"] == "agt_1"
    assert payload["decision"] == "deny"
    assert payload["latency_us"] == 900


def test_log_output_redacts_in_practice(capsys):
    """End to end, not just the processor in isolation."""
    configure_logging("INFO")
    get_logger("dwaar.test").info("decision", free_text={"a": "b"}, surprise_field="leak")

    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["free_text"] == "<redacted>"
    assert payload["surprise_field"] == "<redacted>"
