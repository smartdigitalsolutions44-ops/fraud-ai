"""Liveness and readiness.

* ``/v1/health`` (liveness): the process answers. It touches no dependency, so a
  database outage does not get the container restarted in a loop.
* ``/v1/ready`` (readiness): the service can make **real** decisions. It checks:
  * the database answers and the schema is at the migration head;
  * an active policy deployment exists and its stored hash verifies;
  * the primary model's artefact loads and passes its SHA-256 check (via the model
    cache, so this is cheap after the first call).

  * the primary artefact **on disk** still matches: a cheap stat fingerprint (size and
    mtime of every file) is compared on each probe; any change, or every
    ``READINESS_REVERIFY_SECONDS``, triggers a full SHA-256 re-verification. A deleted or
    corrupted artefact makes the service not ready (the in-memory model already loaded
    stays the verified one);
  * the shared state (Redis) answers, when ``STATE_BACKEND=redis``;
  * a signing key is configured, when ``SERVICE_REQUIRE_SIGNATURES`` is on.

  The LLM is **not** a readiness dependency: scoring never uses it.

Check results are coarse (``ok``, ``failed``, ``missing``, ``not_required``). Internal
error details are not exposed.
"""

from __future__ import annotations

import time
from pathlib import Path

from sqlalchemy import text

from fraud_ai.database import migrations as mig
from fraud_ai.database.models import ModelVersion
from fraud_ai.models.registry import resolve_model
from fraud_ai.models.scoring import load_registered_model
from fraud_ai.models.signing import ModelSignatureError, ModelTrust
from fraud_ai.risk.registry import active_deployment
from fraud_ai.service.dependencies import ServiceContainer
from fraud_ai.service.errors import log
from fraud_ai.state.base import StateUnavailableError


def artifact_fingerprint(path: Path) -> tuple[tuple[str, int, int], ...]:
    if not path.is_dir():
        raise FileNotFoundError("model artefact directory is missing")
    return tuple(sorted((p.name, p.stat().st_size, p.stat().st_mtime_ns) for p in path.iterdir()))


def _verify_primary(c: ServiceContainer, record: ModelVersion) -> None:
    """Full SHA-256 verification when the artefact changed on disk or is due."""
    path = Path(record.model_path)
    try:
        fingerprint = artifact_fingerprint(path)
    except OSError:
        c.metrics.model_verification_failures.inc()
        c.extras.pop("primary_artifact", None)
        raise
    seen = c.extras.get("primary_artifact")
    now = time.monotonic()
    interval = c.settings.readiness_reverify_seconds
    key = (record.model_name, record.model_version, record.artifact_sha256)
    if seen and seen[0] == key and seen[1] == fingerprint and now - seen[2] < interval:
        return
    started = time.perf_counter()
    try:
        # Re-reads every file once; digest and (Stage 11) signature over those bytes.
        load_registered_model(record, trust=ModelTrust.from_settings(c.settings))
    except Exception:
        c.metrics.model_verification_failures.inc()
        c.extras.pop("primary_artifact", None)
        raise
    c.metrics.model_verification_seconds.observe(time.perf_counter() - started)
    c.extras["primary_artifact"] = (key, fingerprint, now)


def readiness(c: ServiceContainer) -> dict[str, str]:
    checks = {
        "database": "failed",
        "migrations": "failed",
        "active_policy": "failed",
        "primary_model": "failed",
        "shared_state": "not_required",
        "signing_key": "not_required",
        "llm": "not_required",
    }
    if c.state.distributed:
        try:
            c.metrics.observe_state("ping", c.state.ping(), True)
            checks["shared_state"] = "ok"
        except StateUnavailableError:
            checks["shared_state"] = "failed"
    if c.settings.service_require_signatures:
        checks["signing_key"] = "ok" if c.signing_keys else "missing"
    started = time.perf_counter()
    try:
        with c.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
        c.metrics.db_ping.observe(time.perf_counter() - started)
    except Exception as exc:
        log.warning("readiness: database check failed (%s)", type(exc).__name__)
        return checks
    try:
        status = mig.schema_status(c.engine, c.settings.resolved_database_url)
        checks["migrations"] = "ok" if status.up_to_date else "outdated"
    except Exception as exc:
        log.warning("readiness: migration check failed (%s)", type(exc).__name__)
    try:
        with c.factory() as session:
            deployment = active_deployment(session)
            if deployment is None:
                checks["active_policy"] = "missing"
                checks["primary_model"] = "missing"
                return checks
            checks["active_policy"] = "ok"
            record = resolve_model(session, deployment.policy.primary.ref)
            c.scoring.cache.bind(deployment.deployment_id)
            c.scoring.cache.get(record)
            _verify_primary(c, record)
            checks["primary_model"] = "ok"
    except ModelSignatureError as exc:
        # Safe to log in full: model names, key ids and file names only (no secrets).
        log.error("readiness: model signature check failed: %s", exc)
    except Exception as exc:
        log.warning("readiness: policy/model check failed (%s)", type(exc).__name__)
    return checks


def is_ready(checks: dict[str, str]) -> bool:
    return all(v in {"ok", "not_required"} for v in checks.values())
