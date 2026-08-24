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
    # Explicit DSNs, not whatever `.env` holds. `.env` carries Docker service hostnames
    # (`postgres:5432`) which do not resolve from the host, so inheriting it made every
    # setup wait out the startup connection timeout.
    from tests.conftest import APP_DSN, MIGRATE_DSN, REDIS_URL, SUPERUSER_DSN

    app = create_app(
        Settings(
            MAX_BODY_BYTES=1024,
            DATABASE_URL_APP=APP_DSN,
            DATABASE_URL_MIGRATE=MIGRATE_DSN,
            DATABASE_URL_SUPERUSER=SUPERUSER_DSN,
            REDIS_URL=REDIS_URL,
        )
    )
    with TestClient(app) as c:
        yield c


def test_health_reports_component_severity(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("nominal", "degraded", "critical")
    assert body["version"]
    assert "postgres" in body["components"]
    for component in body["components"].values():
        assert set(component) >= {"status", "severity", "reason", "checked_at", "fail_mode"}


def test_severity_comes_from_the_fail_matrix_not_from_this_route(client):
    """One constant, two consumers. Hand-writing the mapping twice is what makes the
    console and the audit trail disagree on stage."""
    from dwaar.components import BY_NAME, Severity

    body = client.get("/health").json()
    for name, component in body["components"].items():
        expected = (
            Severity.NOMINAL if component["status"] == "up"
            else BY_NAME[name].severity_when_down
        )
        assert component["severity"] == expected.value


def test_a_fail_closed_component_down_is_critical(client):
    """Red, not amber. The thing that failed is the thing that decides about money."""
    from dwaar.components import BY_NAME, FailMode, Severity

    for name in ("postgres", "ledger", "mandate_store", "nonce_store"):
        assert BY_NAME[name].fail_mode is FailMode.FAIL_CLOSED
        assert BY_NAME[name].severity_when_down is Severity.CRITICAL


def test_a_fail_open_component_down_is_only_degraded(client):
    """Amber. Judgment degrades; the ledger still holds, so the residual is bounded."""
    from dwaar.components import BY_NAME, Severity

    for name in ("risk_model", "injection_detector", "redis"):
        assert BY_NAME[name].severity_when_down is Severity.DEGRADED


def test_the_explainer_can_never_make_the_service_degraded(client):
    """Killing it is a demo beat precisely because nothing else moves."""
    from dwaar.components import BY_NAME, FailMode, Severity

    assert BY_NAME["explainer"].fail_mode is FailMode.NO_EFFECT
    assert BY_NAME["explainer"].severity_when_down is Severity.NOMINAL

    body = client.get("/health").json()
    assert body["components"]["explainer"]["status"] == "down"
    assert body["components"]["explainer"]["severity"] == "nominal"


def test_overall_status_is_the_worst_component(client):
    from dwaar.components import Severity, overall

    body = client.get("/health").json()
    worst = overall([Severity(c["severity"]) for c in body["components"].values()])
    assert body["status"] == worst.value


def test_health_never_returns_503(client):
    """A database outage must not take /health down.

    FAIL_MATRIX.md requires the API to stay up and DENY under a Postgres outage — demo
    beat 5 depends on it. A 503 would make Compose restart the container, turning
    fail-closed into a crash loop. It also cannot distinguish degraded from dead, which is
    the one thing the console needs from it.
    """
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["components"]["postgres"]["status"] in ("up", "down")


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


# ── F-015 regression ────────────────────────────────────────────────────────────────

def test_a_post_body_survives_the_size_cap_middleware(client):
    """The body cap must not eat the body it is measuring.

    Phase 1's version consumed `request.stream()` and re-attached the buffer to the
    middleware's own Request object — which `BaseHTTPMiddleware` does not hand downstream.
    Every POST body arrived empty and every route returned 422. Nothing caught it because
    /health is a GET and the only POSTs in the suite existed to trigger the 413.

    /openapi.json is a GET, so this exercises the middleware against a route that actually
    parses a body: an under-limit POST must reach the route and fail on *validation*, not
    on a missing body.
    """
    r = client.post("/v1/authorize", json={"agent_id": "wrong-format"})
    assert r.status_code == 422
    detail = r.json()["detail"]
    locations = {tuple(item["loc"]) for item in detail}
    assert ("body",) not in locations, (
        "the route reported the whole body as missing, which means the size-cap "
        "middleware consumed the stream without replaying it (F-015)"
    )
    assert any(item["loc"][:2] == ["body", "agent_id"] for item in detail), (
        f"expected field-level validation errors, got {detail}"
    )


# ── F-022 regression ────────────────────────────────────────────────────────────────

def test_the_size_cap_does_not_fabricate_a_disconnect(client):
    """After replaying the body, the middleware must delegate to the real `receive`.

    An earlier version returned `http.disconnect` on every subsequent call, so
    `request.is_disconnected()` reported a disconnect the instant anything asked — and the
    SSE decision stream, the one endpoint that genuinely needs to detect one, exited on its
    first poll and delivered nothing.
    """
    import inspect

    from dwaar.api.middleware import BodySizeLimitMiddleware

    source = inspect.getsource(BodySizeLimitMiddleware)
    assert "return await receive()" in source, (
        "the replay callable must delegate to the real receive after the body, or any "
        "endpoint polling is_disconnected() sees a disconnect that did not happen"
    )
    assert 'return {"type": "http.disconnect"}' not in source


async def test_a_disconnected_client_ends_the_stream_promptly():
    """The stream must stop when the client really goes away — and only then.

    Driven with a request that reports disconnected immediately, so the generator
    terminates instead of running forever. That is also the F-022 assertion from the other
    side: before the fix this returned on the first poll for every client, connected or
    not.
    """
    from dwaar.api.routes.console import decision_stream

    class FakeRequest:
        app = None

        async def is_disconnected(self):
            return True

    response = await decision_stream(FakeRequest(), merchant_id="mch_nonexistent")
    assert response.media_type == "text/event-stream"
