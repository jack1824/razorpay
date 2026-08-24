"""Request middleware: trace ID, access log, body size cap.

**Both middlewares are pure ASGI, not `BaseHTTPMiddleware`.** That is not a style
preference — `BaseHTTPMiddleware` broke this application twice, in two different ways:

**F-015, the body cap.** It hands the downstream app a *different* `Request` built from the
scope. Consuming `request.stream()` and re-attaching the buffer via `request._receive`
mutates an object the route never sees, so the stream is drained, nothing replaces it, and
every POST body arrives empty. The route then returns
`422 {"loc": ["body"], "msg": "Field required"}` for a request that had a perfectly good
body. Nothing caught it for two phases because the only endpoint was a GET.

**F-021, the trace ID.** `call_next` raises `RuntimeError: No response returned` when a
long-lived `StreamingResponse` is still open — which is every SSE connection the console
opens. The decision stream returned a 500 on connect.

Two defects, one cause. Per the standing rule, the fix is the layer rather than either
instance: nothing in this application uses `BaseHTTPMiddleware`, and a test asserts that.

Pure ASGI also lets the buffered body be replayed through a `receive` callable the
downstream app actually uses, which is what makes the size cap work at all.
"""

from __future__ import annotations

import json
import time

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from dwaar.logging import get_logger, set_trace_id
from dwaar.metrics import rejected_total

log = get_logger("dwaar.api")

TRACE_HEADER = "X-Dwaar-Trace-Id"


class TraceIDMiddleware:
    """Bind a trace ID for the request and echo it back on the response.

    An inbound ``X-Dwaar-Trace-Id`` is honoured so a caller can correlate across the MCP
    proxy, but it is length- and charset-capped: it lands in log lines, and an unbounded
    caller-supplied string in a log line is a log-injection surface.

    Pure ASGI. It wraps `send` rather than awaiting a completed response, so a streaming
    response stays streaming — the access line is written when the response STARTS, not
    when it finishes, because an SSE connection may stay open for the length of a demo.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or ())
        raw = headers.get(TRACE_HEADER.lower().encode())
        inbound = raw.decode("latin-1") if raw else None
        if inbound is not None and (len(inbound) > 64 or not inbound.isalnum()):
            inbound = None
        trace_id = set_trace_id(inbound)

        # Starlette's `request.state` reads from `scope["state"]`, so routes see this.
        scope.setdefault("state", {})["trace_id"] = trace_id

        started = time.perf_counter()
        method = scope.get("method", "")
        path = scope.get("path", "")

        async def send_with_trace(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                message["headers"] = [
                    *message["headers"],
                    (TRACE_HEADER.encode(), trace_id.encode()),
                ]
                log.info(
                    "request",
                    method=method,
                    path=path,
                    status_code=message["status"],
                    duration_ms=round((time.perf_counter() - started) * 1000, 3),
                )
            await send(message)

        try:
            await self.app(scope, receive, send_with_trace)
        except Exception:
            log.exception(
                "request_failed",
                method=method,
                path=path,
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
            )
            raise


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
            """Hand over the buffered body once, then get out of the way.

            Delegating to the real `receive` afterwards is load-bearing, not tidiness. An
            earlier version returned `{"type": "http.disconnect"}` on every call after the
            body — which meant `request.is_disconnected()` reported a disconnect the
            instant anything asked, and the SSE decision stream exited on its first poll.
            The endpoint that most needs to detect a real disconnect was the one this made
            unable to. See FAILURES.md F-022.

            After the body, this middleware has nothing left to say about the request, so
            it must be transparent rather than answering on the client's behalf.
            """
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

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
