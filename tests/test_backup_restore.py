"""Stage 10 backup / restore: seed (the PostgreSQL world plus Stage 9/10 records), dump,
destroy, restore, verify every table and the application invariants."""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

import pytest
from sqlalchemy.engine import make_url

from fraud_ai import audit
from fraud_ai.core.enums import ReviewResolution
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import ReviewItem, RiskAssessment
from fraud_ai.realtime.review import resolve
from fraud_ai.service.keys import create_key
from scripts.backup_restore_check import (
    create_database,
    drop_database,
    dump,
    fingerprint,
    invariants,
    restore,
)
from tests.conftest import POSTGRES_URL
from tests.test_service_backends import _seed_step_up

pytestmark = pytest.mark.postgres


def _schema(url: str) -> str:
    options = make_url(url).query.get("options", "")
    text = options if isinstance(options, str) else options[0]
    return text.split("search_path=", 1)[1] if "search_path=" in text else "public"


@pytest.mark.skipif(shutil.which("pg_dump") is None, reason="pg_dump not installed")
def test_backup_destroy_restore_verify(pg_world: tuple[str, Path], tmp_path: Path) -> None:
    url, _ = pg_world
    assert POSTGRES_URL
    schema = _schema(url)
    engine = create_db_engine(url)
    factory = make_session_factory(engine)
    seeded = _seed_step_up(factory, 2)  # assessments + users + events
    with session_scope(factory) as s:
        assessment = s.get(RiskAssessment, uuid.UUID(seeded[0][0]))
        assert assessment is not None
        item = ReviewItem(
            assessment_id=assessment.assessment_id,
            event_id=assessment.event_id,
            priority=2,
            reason_codes=["TEST"],
        )
        s.add(item)
        s.flush()
        resolve(s, item.review_id, ReviewResolution.LEGITIMATE, note="backup test")
        create_key(s, "backup-test", ["score:write"])
        audit.record(s, "service_key.created", actor="cli:test", target_type="service_key")
    engine.dispose()

    before = fingerprint(url, schema)
    for table in (
        "risk_assessments",
        "review_queue",
        "review_outcomes",
        "risk_policies",
        "model_versions",
        "policy_deployments",
        "service_api_keys",
        "audit_events",
        "events",
    ):
        assert before[table]["rows"] > 0, table
    dump_file = tmp_path / "backup.dump"
    dump(url, dump_file, schema)
    assert dump_file.stat().st_size > 0 and oct(dump_file.stat().st_mode)[-3:] == "600"

    admin = make_url(POSTGRES_URL).set(database="postgres").render_as_string(hide_password=False)
    scratch = "fraud_ai_restore_test"
    try:
        for attempt in range(2):  # restore, destroy the database, restore again
            target = create_database(admin, scratch)
            restore(dump_file, target)
            restored = (
                f"{target}?options=-csearch_path%3D{schema}" if schema != "public" else target
            )
            after = fingerprint(restored, schema)
            assert after == before, f"attempt {attempt}: tables differ"
            checks = invariants(restored)
            assert checks["active_policy"] == "risk-policy-1.0.0"
            assert checks["audit_chain_ok"] and checks["audit_events"] >= 1
            assert checks["models_resolved"]
            drop_database(admin, scratch)  # destroy
    finally:
        drop_database(admin, scratch)
