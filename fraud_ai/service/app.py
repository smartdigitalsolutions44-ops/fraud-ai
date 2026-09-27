"""The FastAPI application factory for the fraud service (Stage 9).

::

    merchant / application
      -> TLS termination (a reverse proxy in production; see DEPLOYMENT.md)
      -> ServiceMiddleware: correlation id, size limit, security headers, metrics
      -> /v1 routes: API key, rate limit, signature, scope
      -> FraudScoringService (Stage 8), unchanged
      -> risk assessment -> action request (STEP_UP, review, ...)
      -> step-up execution (WebAuthn / external payment auth) -> follow-up assessment

Defaults are closed:

* no CORS;
* no interactive docs and no OpenAPI endpoint unless ``SERVICE_EXPOSE_OPENAPI``;
* no trusted proxies;
* no payment provider;
* no LLM.

Scoring never needs the LLM.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Engine

from fraud_ai import __version__
from fraud_ai.config.settings import Settings, get_settings, parse_rate
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database import engine_from_settings, make_session_factory
from fraud_ai.realtime.service import FraudScoringService
from fraud_ai.security.keys import build_pseudonymiser
from fraud_ai.service.dependencies import ServiceContainer
from fraud_ai.service.errors import install_handlers
from fraud_ai.service.metrics import ServiceMetrics
from fraud_ai.service.middleware import ServiceMiddleware
from fraud_ai.service.rate_limit import InMemoryRateLimiter, RateLimiter
from fraud_ai.service.routes import router
from fraud_ai.service.schemas import API_VERSION
from fraud_ai.stepup.payment import FakePaymentAuthProvider, PaymentAuthenticationProvider
from fraud_ai.stepup.webauthn import WebAuthnConfig

DESCRIPTION = (
    "Machine-to-machine fraud decision service. Synthetic-data research system: not "
    "production-ready, not certified, not PCI-assessed. Responses carry decisions, reason "
    "codes and versions, never model internals or personal data."
)


class ServiceConfigurationError(FraudAIError):
    """The settings are not acceptable for serving (see ``Settings.service_problems``)."""


def default_llm_client(settings: Settings) -> Callable[[], Any]:
    """A factory for the configured local runtime, or ``None`` when none is configured.
    The LLM package is imported only when an investigation is requested."""

    def build() -> Any:
        if settings.local_llm_runtime is None:
            return None
        from fraud_ai.llm.runtime import make_client

        return make_client(
            settings.local_llm_runtime,
            model=settings.local_llm_model,
            endpoint=settings.local_llm_endpoint,
            timeout=settings.local_llm_timeout,
            binary=settings.local_llm_binary,
            model_path=str(settings.local_llm_model_path)
            if settings.local_llm_model_path
            else None,
        )

    return build


def default_payment_provider(settings: Settings) -> PaymentAuthenticationProvider | None:
    if settings.payment_auth_provider == "fake":
        assert settings.payment_auth_webhook_secret is not None  # enforced by settings
        return FakePaymentAuthProvider(settings.payment_auth_webhook_secret.get_secret_value())
    return None


def build_container(
    settings: Settings,
    *,
    engine: Engine | None = None,
    clock: Callable[[], datetime] | None = None,
    payment_provider: PaymentAuthenticationProvider | str | None = "default",
    llm_client: Callable[[], Any] | None = None,
    limiter: RateLimiter | None = None,
) -> ServiceContainer:
    problems = settings.service_problems()
    if problems:
        raise ServiceConfigurationError("; ".join(problems))
    engine = engine or engine_from_settings(settings)
    factory = make_session_factory(engine)
    pseudonymiser = build_pseudonymiser(settings)
    clock = clock or (lambda: datetime.now(UTC))
    count, period = parse_rate(settings.rate_limit)
    provider = (
        default_payment_provider(settings)
        if isinstance(payment_provider, str)
        else payment_provider
    )
    master = settings.service_signing_master_key
    return ServiceContainer(
        settings=settings,
        engine=engine,
        factory=factory,
        scoring=FraudScoringService(
            factory, pseudonymiser, store_raw_ip=settings.store_raw_ip, clock=clock
        ),
        pseudonymiser=pseudonymiser,
        webauthn=WebAuthnConfig(
            rp_id=settings.webauthn_rp_id,
            rp_name=settings.webauthn_rp_name,
            origin=settings.webauthn_origin,
            challenge_ttl=settings.webauthn_challenge_ttl,
            max_attempts=settings.step_up_max_attempts,
        ),
        payment=provider,
        limiter=limiter or InMemoryRateLimiter(count, period, settings.rate_limit_burst),
        # Throttles repeated *failed* authentication from one address (abuse control only).
        auth_failure_limiter=InMemoryRateLimiter(count, period, settings.rate_limit_burst),
        metrics=ServiceMetrics(),
        clock=clock,
        llm_client=llm_client or default_llm_client(settings),
        scoring_pool=concurrent.futures.ThreadPoolExecutor(
            max_workers=16, thread_name_prefix="fraud-score"
        ),
        llm_pool=concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="llm"),
        signing_master_key=master.get_secret_value() if master else None,
    )


@contextlib.asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    app.state.container.close()


def create_app(
    settings: Settings | None = None,
    *,
    container: ServiceContainer | None = None,
    **container_kwargs: Any,
) -> FastAPI:
    settings = settings or (container.settings if container else get_settings())
    container = container or build_container(settings, **container_kwargs)
    expose = settings.service_expose_openapi
    app = FastAPI(
        title="fraud-ai service",
        version=__version__,
        summary=f"API {API_VERSION}",
        description=DESCRIPTION,
        openapi_url="/v1/openapi.json" if expose else None,
        docs_url="/v1/docs" if expose else None,
        redoc_url=None,
        lifespan=_lifespan,
    )
    app.state.container = container
    install_handlers(app)
    app.include_router(router)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "Idempotency-Key",
                "X-Correlation-ID",
                "X-Fraud-Timestamp",
                "X-Fraud-Signature",
            ],
            allow_credentials=False,
            max_age=600,
        )
    app.add_middleware(
        ServiceMiddleware,
        max_body=settings.request_size_limit,
        metrics=container.metrics,
        trusted_proxies=settings.trusted_proxy_networks,
        hsts=settings.service_hsts,
    )

    return app


def openapi_document() -> dict[str, Any]:
    """The OpenAPI document, even when the endpoint is not exposed (for docs/CI)."""
    from fastapi.openapi.utils import get_openapi

    app = FastAPI(title="fraud-ai service", version=__version__)
    app.include_router(router)
    return get_openapi(
        title="fraud-ai service",
        version=__version__,
        summary=f"API {API_VERSION}",
        description=DESCRIPTION,
        routes=app.routes,
    )
