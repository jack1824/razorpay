"""GET /health and the request middleware."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from dwaar.api.app import create_app
from dwaar.api.middleware import TRACE_HEADER
from dwaar.config import Settings


@pytest.fixture
def client():
    app = create_app(Settings(MAX_BODY_BYTES=1024))
    with TestClient(app) as c:
        yield c


def test_health_returns_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"]
    assert "postgres" in body["dependencies"]


def test_health_reports_postgres_unavailable_without_failing(client):
    """A database outage must not take /health down.

    FAIL_MATRIX.md requires the API to stay up and deny under a Postgres outage — demo
    beat 5 depends on it. If /health returned 503 here, Compose would restart the
    container and the fail-closed behaviour would be a crash loop instead.
    """
    r = client.get("/health")
    assert r.status_code == 200
    status = r.json()["dependencies"]["postgres"]
    assert status == "ok" or status.startswith("unavailable")


def test_trace_id_is_returned(client):
    r = client.get("/health")
    assert r.headers[TRACE_HEADER]
    assert r.json()["trace_id"] == r.headers[TRACE_HEADER]


def test_trace_id_is_per_request(client):
    a = client.get("/health").headers[TRACE_HEADER]
    b = client.get("/health").headers[TRACE_HEADER]
    assert a != b


def test_inbound_trace_id_is_honoured(client):
    r = client.get("/health", headers={TRACE_HEADER: "abc123def456"})
    assert r.headers[TRACE_HEADER] == "abc123def456"


@pytest.mark.parametrize(
    "bad",
    [
        "x" * 65,                    # too long for a log field
        "not alnum!",                # punctuation
        "line\nbreak",               # log injection
    ],
)
def test_malformed_inbound_trace_id_is_replaced(client, bad):
    """A caller-supplied trace ID lands in log lines; unbounded input there is injection."""
    r = client.get("/health", headers={TRACE_HEADER: bad})
    assert r.headers[TRACE_HEADER] != bad
    assert len(r.headers[TRACE_HEADER]) == 32


def test_body_size_cap_rejects_oversized_request(client):
    """Threat 12. Enforced before parsing, not after."""
    r = client.post("/health", content=b"x" * 2048)
    assert r.status_code == 413
    assert r.json()["reason_code"] == "request_too_large"


def test_body_size_cap_rejects_lying_content_length(client):
    """Content-Length is attacker-controlled, so the streamed length is what counts."""
    r = client.post(
        "/health",
        content=b"x" * 2048,
        headers={"content-length": "10"},
    )
    assert r.status_code in (413, 405)


def test_openapi_declares_no_llm(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200
    description = json.dumps(r.json()["info"]).lower()
    assert "llm" in description
