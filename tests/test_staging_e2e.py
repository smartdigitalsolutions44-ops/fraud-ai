"""Stage 10 staging end-to-end test: the service in the *staging* profile (PostgreSQL with
non-default credentials, Redis, required signatures, the fake provider explicitly allowed,
https WebAuthn origin) with two workers, driven by ``scripts/staging_e2e.py``.

Needs ``TEST_STAGING_POSTGRES_URL``: a database/role whose password is not a development
default (the staging profile refuses those). CI creates one; locally, for example:

    sudo -u postgres psql -c "CREATE ROLE fraud_ai_staging LOGIN CREATEDB PASSWORD '<random>'"
    sudo -u postgres createdb -O fraud_ai_staging fraud_ai_staging
"""

from __future__ import annotations

import json
import os
import secrets
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import EventRecord, RiskAssessment
from fraud_ai.service.keys import create_key, signing_secret
from scripts.staging_e2e import SignedClient, run
from tests.conftest import TEST_KEY
from tests.service_process import running_service

STAGING_URL = os.environ.get("TEST_STAGING_POSTGRES_URL")
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(not STAGING_URL, reason="TEST_STAGING_POSTGRES_URL not set"),
]
RP_ID = "staging.example.test"
ORIGIN = f"https://{RP_ID}"


@pytest.fixture(scope="module")
def staging_world(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[str, Path]]:
    from sqlalchemy import text

    from tests.realtime_world import build_pg_world

    assert STAGING_URL
    root = tmp_path_factory.mktemp("staging_world")
    url = build_pg_world(STAGING_URL, "stage10_staging", root)
    yield url, root
    engine = create_db_engine(STAGING_URL)
    with engine.begin() as conn:
        conn.execute(text('DROP SCHEMA IF EXISTS "stage10_staging" CASCADE'))
    engine.dispose()


def test_staging_end_to_end(
    staging_world: tuple[str, Path], redis_url: str, tmp_path: Path
) -> None:
    import redis

    url, root = staging_world
    client = redis.Redis.from_url(redis_url)
    client.flushdb()
    client.close()
    master = secrets.token_hex(32)
    webhook = secrets.token_hex(32)
    env = {
        "ENVIRONMENT": "staging",
        "DATABASE_URL": url,
        "PSEUDONYMISATION_KEY": TEST_KEY,
        "MODEL_DIRECTORY": str(root / "models"),
        "STATE_BACKEND": "redis",
        "REDIS_URL": redis_url,
        "SERVICE_SIGNING_MASTER_KEY": master,
        "SERVICE_REQUIRE_SIGNATURES": "true",
        "WEBAUTHN_RP_ID": RP_ID,
        "WEBAUTHN_ORIGIN": ORIGIN,
        "PAYMENT_AUTH_PROVIDER": "fake",
        "PAYMENT_AUTH_WEBHOOK_SECRET": webhook,
        "PAYMENT_AUTH_ALLOW_FAKE_IN_STAGING": "true",
        "LOCAL_LLM_RUNTIME": "reference",
        "SERVICE_REQUEST_TIMEOUT": "60",
        "RATE_LIMIT": "6000/minute",
        "RATE_LIMIT_BURST": "1000",
    }
    engine = create_db_engine(url)
    factory = make_session_factory(engine)
    with session_scope(factory) as s:
        credential = create_key(
            s,
            "staging-e2e",
            [
                "score:write",
                "score:replay",
                "signals:trusted",
                "assessment:read",
                "review:read",
                "review:write",
                "policy:read",
                "stepup:write",
                "webauthn:write",
                "investigation:write",
                "metrics:read",
            ],
        ).credential

    def lookup(assessment_id: str) -> tuple[str, str]:
        with factory() as s:
            row = s.get(RiskAssessment, uuid.UUID(assessment_id))
            assert row is not None
            record = s.get(EventRecord, row.event_id)
            assert record is not None and record.session_id
            return str(row.user_id), record.session_id

    events = [json.loads(line) for line in (root / "live.jsonl").read_text().splitlines()]
    try:
        with running_service(env, workers=2, log_dir=tmp_path) as svc:
            signer = SignedClient(
                svc.base_url, credential, signing_secret(master, credential.split(".")[0])
            )
            report: dict[str, Any] = run(
                signer,
                events,
                webhook_secret=webhook,
                rp_id=RP_ID,
                origin=ORIGIN,
                session_lookup=lookup,
            )
            log = svc.log()
    finally:
        engine.dispose()
    assert report["ok"]
    steps = {s["step"]: s for s in report["steps"]}
    assert steps["payment_step_up"]["followup"] == "ALLOW_WITH_MONITORING"
    assert steps["webauthn_step_up"]["followup"] == "ALLOW_WITH_MONITORING"
    assert steps["investigation"]["status"] == 200
    assert master not in log and webhook not in log and credential.split(".")[1] not in log
    assert '"level": "INFO"' in log  # staging logs are structured JSON by default
