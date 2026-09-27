"""The service container and the authentication/authorisation dependency.

Order of checks for an authenticated route:

1. **Key.** ``Authorization: Bearer <key_id>.<secret>`` is verified in constant time.
   Missing, malformed, unknown, wrong and revoked keys all get the same 401. Repeated
   failures from one address are throttled.
2. **Rate limit** per (key, route template). The limit is keyed by the API key, never by
   the client address.
3. **Signature**, when signing is configured. It is mandatory with
   ``SERVICE_REQUIRE_SIGNATURES``, and verified whenever the headers are present. The
   HMAC covers the timestamp and the exact raw body. An accepted signature is persisted
   and committed immediately, so a replay fails even if processing then errors.
4. **Scope.** The route's required scope must be granted to the key (403 otherwise).
"""

from __future__ import annotations

import concurrent.futures
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from fastapi import Request
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool

from fraud_ai.config.settings import Settings
from fraud_ai.database.engine import write_scope
from fraud_ai.realtime.service import FraudScoringService
from fraud_ai.security.hashing import Pseudonymiser
from fraud_ai.service.errors import ApiError
from fraud_ai.service.keys import VerifiedKey, signing_secret, verify_key
from fraud_ai.service.metrics import ServiceMetrics
from fraud_ai.service.rate_limit import RateLimiter
from fraud_ai.service.signatures import SignatureError, check_signature, remember
from fraud_ai.stepup.payment import PaymentAuthenticationProvider
from fraud_ai.stepup.webauthn import WebAuthnConfig

TIMESTAMP_HEADER = "x-fraud-timestamp"
SIGNATURE_HEADER = "x-fraud-signature"


@dataclass
class ServiceContainer:
    settings: Settings
    engine: Engine
    factory: sessionmaker[Session]
    scoring: FraudScoringService
    pseudonymiser: Pseudonymiser
    webauthn: WebAuthnConfig
    payment: PaymentAuthenticationProvider | None
    limiter: RateLimiter
    auth_failure_limiter: RateLimiter
    metrics: ServiceMetrics
    clock: Callable[[], datetime]
    llm_client: Callable[[], Any]
    scoring_pool: concurrent.futures.ThreadPoolExecutor
    llm_pool: concurrent.futures.ThreadPoolExecutor
    signing_master_key: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)

    def close(self) -> None:
        self.scoring_pool.shutdown(wait=False, cancel_futures=True)
        self.llm_pool.shutdown(wait=False, cancel_futures=True)


@dataclass(frozen=True)
class Caller:
    key: VerifiedKey
    body: bytes
    signed: bool

    @property
    def key_id(self) -> str:
        return self.key.key_id

    def has(self, scope: str) -> bool:
        return scope in self.key.scopes


def container_of(request: Request) -> ServiceContainer:
    container: ServiceContainer = request.app.state.container
    return container


def route_template(request: Request) -> str:
    route = request.scope.get("route")
    return str(getattr(route, "path", request.url.path))


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def _unauthenticated(c: ServiceContainer, request: Request, reason: str) -> ApiError:
    c.metrics.auth_failures.labels(reason).inc()
    address = request.scope.get("state", {}).get("client_address") or "unknown"
    decision = c.auth_failure_limiter.hit(f"authfail|{address}")
    if not decision.allowed:
        return ApiError(
            429,
            "RATE_LIMITED",
            "too many failed authentication attempts",
            headers={"Retry-After": str(decision.retry_after)},
        )
    return ApiError(
        401,
        "UNAUTHENTICATED",
        "missing or invalid API credentials",
        headers={"WWW-Authenticate": 'Bearer realm="fraud-ai"'},
    )


def _verify(c: ServiceContainer, presented: str | None) -> VerifiedKey | None:
    with c.factory() as session:
        return verify_key(session, presented)


def _check_signature(c: ServiceContainer, request: Request, key: VerifiedKey, body: bytes) -> bool:
    timestamp = request.headers.get(TIMESTAMP_HEADER)
    signature = request.headers.get(SIGNATURE_HEADER)
    if c.signing_master_key is None:
        if timestamp or signature:
            raise ApiError(
                400, "SIGNING_NOT_CONFIGURED", "request signing is not enabled on this service"
            )
        return False
    if not (timestamp or signature or c.settings.service_require_signatures):
        return False
    max_age = c.settings.signature_max_age
    try:
        signed_at = check_signature(
            signing_secret(c.signing_master_key, key.key_id),
            timestamp,
            signature,
            body,
            now=c.clock(),
            max_age=max_age,
        )
        assert signature is not None
        with write_scope(c.factory) as session:
            remember(
                session,
                f"key:{key.key_id}",
                signature,
                signed_at,
                max_age=max_age,
                now=c.clock(),
            )
    except SignatureError as exc:
        c.metrics.auth_failures.labels(exc.code.lower()).inc()
        raise ApiError(401, exc.code, str(exc)) from None
    return True


def require(scope: str) -> Callable[[Request], Awaitable[Caller]]:
    """A FastAPI dependency: authenticate, rate-limit, verify the signature, check scope."""

    async def dependency(request: Request) -> Caller:
        c = container_of(request)
        presented = _bearer(request)
        key = await run_in_threadpool(_verify, c, presented) if presented else None
        if key is None:
            raise _unauthenticated(c, request, "missing" if presented is None else "invalid")
        route = route_template(request)
        decision = c.limiter.hit(f"{key.key_id}|{request.method}|{route}")
        if not decision.allowed:
            c.metrics.rate_limited.labels(route).inc()
            raise ApiError(
                429,
                "RATE_LIMITED",
                "rate limit exceeded for this API key and route",
                headers={"Retry-After": str(decision.retry_after)},
            )
        body = await request.body()
        signed = await run_in_threadpool(_check_signature, c, request, key, body)
        if scope not in key.scopes:
            c.metrics.auth_failures.labels("scope").inc()
            raise ApiError(403, "INSUFFICIENT_SCOPE", f"this API key lacks the {scope} scope")
        return Caller(key, body, signed)

    dependency.__name__ = f"require_{scope.replace(':', '_')}"
    return dependency
