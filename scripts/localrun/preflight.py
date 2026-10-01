"""Pre-launch checks against the configured database, run in a child interpreter that has the
mode's environment (``python scripts/sentinel.py preflight``). Prints one JSON object.

Reuses the service's own checks (no new rules): the database answers, the schema is at the
migration head, a policy is active, and the primary model *and* every shadow model load,
which verifies each artefact's digest and signature exactly as the service will.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def run() -> dict[str, Any]:
    from sqlalchemy import text

    from fraud_ai.config.settings import get_settings
    from fraud_ai.database import migrations as mig
    from fraud_ai.database.engine import engine_from_settings, make_session_factory
    from fraud_ai.models.registry import resolve_model
    from fraud_ai.models.scoring import load_registered_model
    from fraud_ai.risk.registry import active_deployment

    result: dict[str, Any] = {"database": None, "migrations": None, "policy": None, "models": {}}
    settings = get_settings()
    engine = engine_from_settings(settings)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        result["database"] = "ok"
    except Exception as exc:
        result["database"] = f"unreachable ({type(exc).__name__})"
        return result
    status = mig.schema_status(engine, settings.resolved_database_url)
    result["migrations"] = (
        "ok" if status.up_to_date else f"outdated ({status.current} != {status.head})"
    )
    factory = make_session_factory(engine)
    with factory() as session:
        deployment = active_deployment(session)
        if deployment is None:
            result["policy"] = "missing"
            return result
        result["policy"] = deployment.policy.policy_version
        refs = [deployment.policy.primary.ref, *deployment.shadow_models]
        for ref in refs:
            try:
                load_registered_model(resolve_model(session, ref))
                result["models"][ref] = "ok"
            except Exception as exc:
                result["models"][ref] = f"{type(exc).__name__}: {exc}"
    engine.dispose()
    return result


def main() -> None:
    try:
        print(json.dumps(run()))
    except Exception as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        sys.exit(1)
