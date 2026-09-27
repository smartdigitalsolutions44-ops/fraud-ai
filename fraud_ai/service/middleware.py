"""The outermost ASGI layer, written as pure ASGI (no response buffering).

For every request, it:

* assigns a **correlation id**. An incoming ``X-Correlation-ID`` is reused only if it
  matches a safe pattern; otherwise a fresh uuid is generated. The id is echoed back and
  put into error bodies.
* enforces the **request size limit**. A ``Content-Length`` over the limit is refused
  before the body is read, and a streamed or chunked body is counted and cut off at the
  limit. Both return 413.
* adds **security headers** to every response:
  ``nosniff``, ``no-store``, ``DENY``, ``no-referrer``,
  ``default-src 'none'; frame-ancestors 'none'`` and ``same-origin`` resource policy.
  HSTS is added only when enabled, because it must only be sent over TLS.
* resolves the **server-observed client address**. Forwarding headers count only from
  trusted proxies (see :mod:`fraud_ai.service.network`).
* records **metrics** by route template.
* turns any unhandled exception into a sanitised 500. The traceback is not returned; only
  the exception type is logged, with the correlation id.
"""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Sequence
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from fraud_ai.service.errors import error_body, log
from fraud_ai.service.metrics import ServiceMetrics
from fraud_ai.service.network import Network, client_address, headers_of

CORRELATION_HEADER = "x-correlation-id"
_SAFE_CORRELATION = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"cache-control", b"no-store"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"interest-cohort=()"),
)
HSTS = (b"strict-transport-security", b"max-age=31536000; includeSubDomains")


class BodyTooLargeError(Exception):
    pass


class ServiceMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body: int,
        metrics: ServiceMetrics,
        trusted_proxies: Sequence[Network] = (),
        hsts: bool = False,
    ) -> None:
        self.app = app
        self.max_body = max_body
        self.metrics = metrics
        self.trusted = list(trusted_proxies)
        self.extra = SECURITY_HEADERS + ((HSTS,) if hsts else ())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = headers_of(scope.get("headers", []))
        incoming = headers.get(CORRELATION_HEADER, "")
        cid = incoming if _SAFE_CORRELATION.match(incoming) else uuid.uuid4().hex
        state = scope.setdefault("state", {})
        state["correlation_id"] = cid
        peer = scope.get("client")
        state["client_address"] = client_address(peer[0] if peer else None, headers, self.trusted)
        started = time.perf_counter()
        status_holder: dict[str, int] = {}
        response_started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                status_holder["status"] = int(message["status"])
                raw = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() not in {b"server", CORRELATION_HEADER.encode()}
                ]
                raw.extend(self.extra)
                raw.append((CORRELATION_HEADER.encode(), cid.encode()))
                message = {**message, "headers": raw}
            await send(message)

        async def error(status: int, code: str, message: str) -> None:
            body = error_body(code, message, cid)
            await send_wrapper(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                    ],
                }
            )
            await send_wrapper({"type": "http.response.body", "body": body})

        declared = headers.get("content-length")
        try:
            too_large = declared is not None and int(declared) > self.max_body
        except ValueError:
            await error(400, "BAD_REQUEST", "invalid Content-Length")
            self._observe(scope, 400, started)
            return
        if too_large:
            await error(413, "REQUEST_TOO_LARGE", f"request body exceeds {self.max_body} bytes")
            self._observe(scope, 413, started)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body:
                    raise BodyTooLargeError
            return message

        try:
            await self.app(scope, limited_receive, send_wrapper)
        except BodyTooLargeError:
            if not response_started:
                await error(413, "REQUEST_TOO_LARGE", f"request body exceeds {self.max_body} bytes")
        except Exception as exc:
            log.error("unhandled service error type=%s correlation_id=%s", type(exc).__name__, cid)
            if not response_started:
                await error(500, "INTERNAL_ERROR", "internal error")
        self._observe(scope, status_holder.get("status", 500), started)

    def _observe(self, scope: Scope, status: int, started: float) -> None:
        route = _route_template(scope)
        method = str(scope.get("method", "GET"))
        self.metrics.requests.labels(route, method, str(status)).inc()
        self.metrics.latency.labels(route, method).observe(time.perf_counter() - started)


def _route_template(scope: Scope) -> str:
    route: Any = scope.get("route")
    path = getattr(route, "path", None)
    return str(path) if path else "unmatched"
