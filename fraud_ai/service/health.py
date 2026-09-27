"""Liveness and readiness.

* ``/v1/health`` (liveness): the process answers. It touches no dependency, so a
  database outage does not get the container restarted in a loop.
* ``/v1/ready`` (readiness): the service can make **real** decisions. It checks:
  * the database answers and the schema is at the migration head;
  * an active policy deployment exists and its stored hash verifies;
  * the primary model's artefact loads and passes its SHA-256 check (via the model
    cache, so this is cheap after the first call).

  The LLM is **not** a readiness dependency: scoring never uses it.

Check results are coarse (``ok``, ``failed``, ``missing``, ``not_required``). Internal
error details are not exposed.
"""

from __future__ import annotations

from sqlalchemy import text

from fraud_ai.database import migrations as mig
from fraud_ai.models.registry import resolve_model
from fraud_ai.risk.registry import active_deployment
from fraud_ai.service.dependencies import ServiceContainer
from fraud_ai.service.errors import log


def readiness(c: ServiceContainer) -> dict[str, str]:
    checks = {
        "database": "failed",
        "migrations": "failed",
        "active_policy": "failed",
        "primary_model": "failed",
        "llm": "not_required",
    }
    try:
        with c.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
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
            checks["primary_model"] = "ok"
    except Exception as exc:
        log.warning("readiness: policy/model check failed (%s)", type(exc).__name__)
    return checks


def is_ready(checks: dict[str, str]) -> bool:
    return all(v in {"ok", "not_required"} for v in checks.values())
