"""Request middleware: trace ID, access log, body size cap.

The body cap is here rather than in a route validator because it must apply before any
parsing — threat 12 is a resource exhaustion threat, and a 64KB limit enforced after
`await request.json()` has already read the body is not a limit.
"""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from dwaar.logging import get_logger, set_trace_id

log = get_logger("dwaar.api")

TRACE_HEADER = "X-Dwaar-Trace-Id"


class TraceIDMiddleware(BaseHTTPMiddleware):
    """Bind a trace ID for the request and echo it back on the response.

    An inbound ``X-Dwaar-Trace-Id`` is honoured so a caller can correlate across the MCP
    proxy, but it is length-capped: it lands in log lines, and an unbounded caller-supplied
    string in a log line is a log-injection surface.
    """

    async def dispatch(self, request: Request, call_next):
        inbound = request.headers.get(TRACE_HEADER)
        if inbound is not None and (len(inbound) > 64 or not inbound.isalnum()):
            inbound = None
        trace_id = set_trace_id(inbound)
        request.state.trace_id = trace_id

        started = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception:
            duration_ms = round((time.perf_counter() - started) * 1000, 3)
            log.exception(
                "request_failed",
                method=request.method,
                path=request.url.path,
                duration_ms=duration_ms,
            )
            raise

        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        response.headers[TRACE_HEADER] = trace_id
        log.info(
            "request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized bodies before anything parses them (threat 12).

    Checks the declared Content-Length first, then enforces the real limit while streaming,
    because Content-Length is attacker-controlled and chunked requests do not send one.
    """

    def __init__(self, app, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    return self._too_large()
            except ValueError:
                return self._too_large()

        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > self.max_bytes:
                return self._too_large()

        # The stream is consumed; hand the buffered body to the downstream app.
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive  # noqa: SLF001 — the supported Starlette pattern
        return await call_next(request)

    def _too_large(self) -> JSONResponse:
        log.warning("body_too_large")
        return JSONResponse({"reason_code": "request_too_large"}, status_code=413)
