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
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from fastapi import Request
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool

from fraud_ai.config.settings import Settings
from fraud_ai.database.engine import write_scope
from fraud_ai.realtime.service import FraudScoringService
from fraud_ai.security.hashing import Pseudonymiser
from fraud_ai.service.errors import ApiError, log
from fraud_ai.service.keys import VerifiedKey, signing_secret, touch_key, verify_key
from fraud_ai.service.metrics import ServiceMetrics
from fraud_ai.service.rate_limit import RateLimiter
from fraud_ai.service.signatures import (
    RequestTarget,
    SignatureError,
    check_signature,
    remember,
    remember_shared,
)
from fraud_ai.state.base import SharedState, StateUnavailableError
from fraud_ai.state.memory import MemoryState
from fraud_ai.stepup.payment import PaymentAuthenticationProvider
from fraud_ai.stepup.webauthn import WebAuthnConfig

TIMESTAMP_HEADER = "x-fraud-timestamp"
KEY_VERSION_HEADER = "x-fraud-key-version"
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
    signing_keys: tuple[SigningKey, ...] = ()
    state: SharedState = field(default_factory=MemoryState)
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def signing_master_key(self) -> str | None:
        """The *current* master key (new signatures), if signing is configured."""
        return self.signing_keys[0].master if self.signing_keys else None

    def verification_keys(self, now: datetime) -> list[SigningKey]:
        """Keys a signature may be checked against right now: the current key, plus the
        previous key until its grace period ends."""
        return [k for k in self.signing_keys if k.not_after is None or now <= k.not_after]

    def close(self) -> None:
        self.scoring_pool.shutdown(wait=False, cancel_futures=True)
        self.llm_pool.shutdown(wait=False, cancel_futures=True)
        self.state.close()
        from fraud_ai.service.app import uninstrument

        uninstrument(self.metrics)


@dataclass(frozen=True)
class SigningKey:
    version: str
    master: str = field(repr=False)
    not_after: datetime | None = None  # None: the current key


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
    try:
        decision = c.auth_failure_limiter.hit(f"authfail|{address}")
    except StateUnavailableError:
        return _state_unavailable(c, "rate_limit")
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


TOUCH_INTERVAL = timedelta(seconds=60)
_TOUCH_LOCK = threading.Lock()


def _verify(c: ServiceContainer, presented: str | None) -> VerifiedKey | None:
    now = c.clock()
    with c.factory() as session:
        key = verify_key(session, presented, now=now)
    if key is not None:
        _maybe_touch(c, key.key_id, now)
    return key


def _maybe_touch(c: ServiceContainer, key_id: str, now: datetime) -> None:
    """Update ``last_used_at`` at most once per ``TOUCH_INTERVAL`` per key and process.
    A failure here never fails the request (it is bookkeeping, not authorisation)."""
    touched: dict[str, datetime] = c.extras.setdefault("key_touched", {})
    with _TOUCH_LOCK:
        last = touched.get(key_id)
        if last is not None and now - last < TOUCH_INTERVAL:
            return
        touched[key_id] = now
    try:
        with write_scope(c.factory) as session:
            touch_key(session, key_id, now)
    except SQLAlchemyError as exc:
        log.warning("could not record key use (%s)", type(exc).__name__)


def _check_signature(c: ServiceContainer, request: Request, key: VerifiedKey, body: bytes) -> bool:
    timestamp = request.headers.get(TIMESTAMP_HEADER)
    signature = request.headers.get(SIGNATURE_HEADER)
    wanted_version = request.headers.get(KEY_VERSION_HEADER)
    if not c.signing_keys:
        if c.settings.service_require_signatures:
            # Defence in depth: settings validation forbids this state, but if the key
            # ever fails to load, required signatures must fail closed, never be skipped.
            raise ApiError(
                503,
                "SIGNING_UNAVAILABLE",
                "request signing is required but no signing key is available",
            )
        if timestamp or signature:
            raise ApiError(
                400, "SIGNING_NOT_CONFIGURED", "request signing is not enabled on this service"
            )
        return False
    if not (timestamp or signature or c.settings.service_require_signatures):
        return False
    max_age = c.settings.signature_max_age
    min_version = c.settings.effective_signature_min_version
    target = RequestTarget(request.method, request.url.path, request.url.query)
    now = c.clock()
    candidates = c.verification_keys(now)
    if wanted_version is not None:
        candidates = [k for k in candidates if k.version == wanted_version]
    try:
        signed_at = None
        version = None
        for candidate in candidates:
            try:
                signed_at = check_signature(
                    signing_secret(candidate.master, key.key_id),
                    timestamp,
                    signature,
                    body,
                    now=now,
                    max_age=max_age,
                    target=target,
                    min_version=min_version,
                )
            except SignatureError as exc:
                if exc.code != "INVALID_SIGNATURE":
                    raise  # missing / malformed timestamp / expired: same for every key
                continue
            version = candidate.version
            break
        if signed_at is None or signature is None:
            raise SignatureError("INVALID_SIGNATURE", "signature does not match")
        if c.state.distributed:
            remember_shared(
                c.state, f"key:{key.key_id}", signature, signed_at, max_age=max_age, now=now
            )
        else:
            with write_scope(c.factory) as session:
                remember(
                    session, f"key:{key.key_id}", signature, signed_at, max_age=max_age, now=now
                )
    except SignatureError as exc:
        c.metrics.auth_failures.labels(exc.code.lower()).inc()
        c.metrics.signature_failures.labels(exc.code).inc()
        raise ApiError(401, exc.code, str(exc)) from None
    except StateUnavailableError:
        raise _state_unavailable(c, "replay") from None
    c.metrics.signatures_verified.labels(version or "unknown").inc()
    return True


def _state_unavailable(c: ServiceContainer, what: str) -> ApiError:
    c.metrics.state_unavailable.labels(what).inc()
    return ApiError(
        503,
        "STATE_UNAVAILABLE",
        "a required coordination service is unavailable; the request was not processed",
        headers={"Retry-After": "1"},
    )


def _hit(c: ServiceContainer, limiter: RateLimiter, bucket: str, what: str) -> Any:
    try:
        return limiter.hit(bucket)
    except StateUnavailableError:
        raise _state_unavailable(c, what) from None


def require(scope: str) -> Callable[[Request], Awaitable[Caller]]:
    """A FastAPI dependency: authenticate, rate-limit, verify the signature, check scope."""

    async def dependency(request: Request) -> Caller:
        c = container_of(request)
        presented = _bearer(request)
        key = await run_in_threadpool(_verify, c, presented) if presented else None
        if key is None:
            raise _unauthenticated(c, request, "missing" if presented is None else "invalid")
        route = route_template(request)
        decision = _hit(c, c.limiter, f"{key.key_id}|{request.method}|{route}", "rate_limit")
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
