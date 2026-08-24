"""Request middleware: trace ID, access log, body size cap.

The body cap is **pure ASGI**, not `BaseHTTPMiddleware`, and that is not a style preference.

`BaseHTTPMiddleware` hands the downstream app a *different* `Request` object built from the
scope. Consuming `request.stream()` in the middleware and re-attaching the buffer via
`request._receive` therefore mutates an object the route never sees: the stream is drained,
nothing replaces it, and every POST body arrives empty. The route then returns
`422 {"loc": ["body"], "msg": "Field required"}` for a request that had a perfectly good
body.

Phase 1 shipped that version. Nothing caught it because `/health` is the only endpoint and
it is a GET — the tests POSTed to it purely to trigger the size cap and got a 405 either
way. It surfaced the moment `/v1/authorize` existed. See FAILURES.md F-015.

Pure ASGI lets the buffered body be replayed through a `receive` callable the downstream
app actually uses.
"""

from __future__ import annotations

import json
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from dwaar.logging import get_logger, set_trace_id
from dwaar.metrics import rejected_total

log = get_logger("dwaar.api")

TRACE_HEADER = "X-Dwaar-Trace-Id"


class TraceIDMiddleware(BaseHTTPMiddleware):
    """Bind a trace ID for the request and echo it back on the response.

    An inbound ``X-Dwaar-Trace-Id`` is honoured so a caller can correlate across the MCP
    proxy, but it is length- and charset-capped: it lands in log lines, and an unbounded
    caller-supplied string in a log line is a log-injection surface.
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


class BodySizeLimitMiddleware:
    """Reject oversized bodies before anything parses them (threat 12).

    Two checks, because either alone is insufficient:

    - the declared ``Content-Length``, which is cheap but attacker-controlled;
    - the bytes actually received, which is authoritative and is what a chunked request
      or a lying header requires.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or ())
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send)
                return

        # Buffer, enforcing the real limit as we go. Buffering is the point of a size cap:
        # we are bounding memory, so reading it all is the bound being applied.
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body += message.get("body", b"")
            if len(body) > self.max_bytes:
                await self._reject(send)
                return
            more_body = message.get("more_body", False)

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay, send)

    async def _reject(self, send: Send) -> None:
        log.warning("body_too_large", reason_code="request_too_large")
        rejected_total.labels(reason="request_too_large").inc()
        payload = json.dumps({"reason_code": "request_too_large"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})
