"""Fail-closed service start-up (Stage 10).

``fraud-ai service run`` starts uvicorn with :func:`serve_app` as its factory. Before a
single request is accepted, every worker process validates:

* the configuration profile (``Settings.service_problems``): https WebAuthn origin, no
  placeholder secrets, no unsafe CORS, signatures required and no reference LLM in
  production, the fake provider only where explicitly allowed;
* that required secrets are present (enforced by settings validation);
* database connectivity and the migration revision (must be the head);
* an active, hash-verified policy deployment;
* the primary model artefact: present and SHA-256-verified;
* Redis connectivity, when ``STATE_BACKEND=redis``;
* the signing key, when signatures are required;
* no per-process state with several workers in staging/production (rate limits and
  replay claims would not be shared).

Any problem raises :class:`~fraud_ai.service.app.ServiceConfigurationError`, uvicorn exits
non-zero and nothing is served. The LLM is not checked: scoring never needs it.

When the configuration fingerprint (a hash of the non-secret settings plus which secrets
are present and the signing-key versions) differs from the last recorded one, a
``service.configuration`` audit event is written.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from fastapi import FastAPI

from fraud_ai import audit
from fraud_ai.config.secrets import SECRET_NAMES
from fraud_ai.config.settings import Environment, Settings, get_settings
from fraud_ai.database.engine import write_scope
from fraud_ai.service.app import ServiceConfigurationError, build_container, create_app
from fraud_ai.service.dependencies import ServiceContainer
from fraud_ai.service.errors import log
from fraud_ai.service.health import readiness

WORKERS_ENV = "FRAUD_AI_SERVICE_WORKERS"
_OK = {"ok", "not_required"}


def startup_problems(c: ServiceContainer, *, workers: int = 1) -> list[str]:
    s = c.settings
    problems = list(s.service_problems())
    hosted = s.environment in {Environment.STAGING, Environment.PRODUCTION}
    if hosted and workers > 1 and not c.state.distributed:
        problems.append(
            "several workers need STATE_BACKEND=redis (rate limits and replay claims must "
            "be shared)"
        )
    for check, state in readiness(c).items():
        if state not in _OK:
            problems.append(f"readiness check {check}: {state}")
    return problems


def config_fingerprint(s: Settings) -> tuple[str, dict[str, Any]]:
    secret_fields = {n.lower() for n in SECRET_NAMES}
    visible: dict[str, Any] = {}
    for name, value in s.model_dump(mode="json").items():
        if name in secret_fields:
            visible[f"{name}_present"] = value is not None
        else:
            visible[name] = value
    visible["database"] = s.safe_database_url
    digest = hashlib.sha256(json.dumps(visible, sort_keys=True, default=str).encode()).hexdigest()
    return digest, visible


def record_configuration(c: ServiceContainer) -> bool:
    """Audit the configuration when it changed since the last recorded start."""
    digest, visible = config_fingerprint(c.settings)
    with write_scope(c.factory) as session:
        last = audit.list_events(session, action="service.configuration", limit=1)
        if last and last[0].details.get("fingerprint") == digest:
            return False
        keep = (
            "environment",
            "state_backend",
            "service_require_signatures",
            "service_signing_key_version",
            "payment_auth_provider",
            "trusted_proxies",
            "rate_limit",
            "service_cors_origins",
            "policy_require_promotion",
        )
        audit.record(
            session,
            "service.configuration",
            actor="service:startup",
            target_type="service",
            details={"fingerprint": digest, **{k: visible.get(k) for k in keep}},
        )
    return True


def warm_models(c: ServiceContainer) -> dict[str, float]:
    """Load (and verify) every model of the active deployment, shadows included, into this
    worker's cache before it serves, so no request pays the first-load cost. Each worker has
    its own cache: model objects are never shared between processes."""
    import time

    from fraud_ai.models.registry import resolve_model
    from fraud_ai.risk.registry import active_deployment

    timings: dict[str, float] = {}
    with c.factory() as session:
        deployment = active_deployment(session)
        if deployment is None:
            return timings
        c.scoring.cache.bind(deployment.deployment_id)
        refs = [slot.ref for slot in deployment.policy.slots().values()]
        for policy in deployment.shadow_policies:
            refs += [slot.ref for slot in policy.slots().values()]
        refs += list(deployment.shadow_models)
        for ref in dict.fromkeys(refs):
            started = time.perf_counter()
            c.scoring.cache.get(resolve_model(session, ref))
            timings[ref] = round(time.perf_counter() - started, 3)
    return timings


def serve_app() -> FastAPI:
    """The uvicorn factory used by ``fraud-ai service run`` (fail closed)."""
    from fraud_ai.utils.logging import configure_logging

    settings = get_settings()
    configure_logging(settings.log_level, settings.effective_log_format)
    container = build_container(settings)
    workers = int(os.environ.get(WORKERS_ENV, "1") or 1)
    problems = startup_problems(container, workers=workers)
    if problems:
        container.close()
        for problem in problems:
            log.error("startup refused: %s", problem)
        raise ServiceConfigurationError("; ".join(problems))
    try:
        timings = warm_models(container)
    except Exception as exc:
        container.close()
        raise ServiceConfigurationError(
            f"could not load the active model set ({type(exc).__name__})"
        ) from None
    log.info("model cache warmed: %s", json.dumps(timings, sort_keys=True))
    try:
        record_configuration(container)
    except Exception as exc:  # the audit write must not be skipped silently
        container.close()
        raise ServiceConfigurationError(
            f"could not record the configuration audit event ({type(exc).__name__})"
        ) from None
    log.info("service started (environment=%s)", settings.environment.value)
    return create_app(settings, container=container)
