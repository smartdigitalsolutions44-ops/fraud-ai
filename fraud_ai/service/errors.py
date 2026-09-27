"""Structured, sanitised API errors.

Every error body has the same shape::

    {"error": {"code": "INVALID_EVENT", "message": "...", "correlation_id": "..."}}

What an error never contains:

* stack traces or exception reprs;
* SQL, database or driver details;
* file paths;
* secrets;
* request *values*. Validation errors name the offending field, never its content.

Unexpected exceptions become a generic ``INTERNAL_ERROR``. Only the exception *type* is
logged, with the correlation id, so an operator can match a report to a log line.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from fraud_ai.utils.logging import get_logger

log = get_logger("fraud_ai.service")

_HTTP_CODES = {
    400: "BAD_REQUEST",
    401: "UNAUTHENTICATED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    406: "NOT_ACCEPTABLE",
    409: "CONFLICT",
    410: "GONE",
    413: "REQUEST_TOO_LARGE",
    415: "UNSUPPORTED_MEDIA_TYPE",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMITED",
    500: "INTERNAL_ERROR",
    503: "UNAVAILABLE",
    504: "TIMEOUT",
}
_SAFE_HTTP_MESSAGES = {
    404: "no such resource",
    405: "method not allowed",
}


class ApiError(Exception):
    """An error the API returns as-is. ``message`` must already be safe to show."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}
        self.extra = extra or {}


def correlation_id_of(scope_or_request: Any) -> str | None:
    scope = getattr(scope_or_request, "scope", scope_or_request)
    state = scope.get("state") or {}
    value = state.get("correlation_id")
    return value if isinstance(value, str) else None


def error_body(code: str, message: str, correlation_id: str | None, **extra: Any) -> bytes:
    error: dict[str, Any] = {"code": code, "message": message, "correlation_id": correlation_id}
    error.update(extra)
    return json.dumps({"error": error}, sort_keys=True).encode()


def error_response(
    request: Request | None,
    status: int,
    code: str,
    message: str,
    *,
    headers: dict[str, str] | None = None,
    **extra: Any,
) -> JSONResponse:
    cid = correlation_id_of(request) if request is not None else None
    content = json.loads(error_body(code, message, cid, **extra))
    return JSONResponse(content, status_code=status, headers=headers)


def _validation_message(exc: RequestValidationError) -> str:
    parts = []
    for err in exc.errors()[:10]:
        loc = ".".join(str(p) for p in err.get("loc", ()) if p != "body") or "body"
        parts.append(f"{loc}: {err.get('msg', 'invalid')}")
    return "; ".join(parts) or "invalid request"


def install_handlers(app: FastAPI) -> None:
    async def api_error(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, ApiError)
        return error_response(
            request, exc.status, exc.code, exc.message, headers=exc.headers, **exc.extra
        )

    async def validation_error(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, RequestValidationError)
        return error_response(request, 422, "VALIDATION_ERROR", _validation_message(exc))

    async def http_error(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, StarletteHTTPException)
        status = exc.status_code
        message = _SAFE_HTTP_MESSAGES.get(status, "request failed")
        return error_response(
            request,
            status,
            _HTTP_CODES.get(status, "ERROR"),
            message,
            headers=dict(exc.headers or {}),
        )

    app.add_exception_handler(ApiError, api_error)
    app.add_exception_handler(RequestValidationError, validation_error)
    app.add_exception_handler(StarletteHTTPException, http_error)
