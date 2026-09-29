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
from sqlalchemy import select

from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import EventRecord, ModelVersion, RiskAssessment
from fraud_ai.models.signing import sign_model
from fraud_ai.service.keys import create_key, signing_secret
from fraud_ai.trust import keys as tk
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
        "SIGNATURE_MIN_VERSION": "v2",
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
    # Stage 11: the staging profile requires signed models. Unsigned: start-up refused.
    pair = tk.generate()
    env["MODEL_SIGNING_PUBLIC_KEYS"] = tk.encode_public(pair.public)
    unsigned_logs = tmp_path / "unsigned"
    unsigned_logs.mkdir()
    with (
        pytest.raises(RuntimeError, match="exited early"),
        running_service(env, workers=1, log_dir=unsigned_logs, timeout=90),
    ):
        pass
    refusal = "".join(f.read_text() for f in unsigned_logs.glob("*.log"))
    assert "model signature check failed" in refusal and "unsigned" in refusal
    with session_scope(factory) as s:
        for model in s.scalars(select(ModelVersion)):
            sign_model(s, model, pair, actor="cli:staging-e2e")
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
    v2 = steps["signature_v2"]
    assert v2["valid"] == 200 and v2["replay"] == "REPLAYED_SIGNATURE"
    assert v2["method"] == v2["path"] == v2["body"] == "INVALID_SIGNATURE"
    assert tuple(v2["v1_downgrade"]) == (401, "SIGNATURE_VERSION_REJECTED")
    assert master not in log and webhook not in log and credential.split(".")[1] not in log
    assert '"level": "INFO"' in log  # staging logs are structured JSON by default
    _two_person_activation(env)


def _two_person_activation(service_env: dict[str, str]) -> None:
    """shadow -> evaluation -> candidate -> approval A -> approval B -> activation, through
    the real CLI in the staging profile; one operator cannot approve twice."""
    from click.testing import CliRunner

    from fraud_ai.cli.main import cli
    from fraud_ai.config.settings import get_settings
    from tests.realtime_world import P2

    base = {
        k: service_env[k]
        for k in ("ENVIRONMENT", "DATABASE_URL", "PSEUDONYMISATION_KEY", "MODEL_DIRECTORY",
                  "MODEL_SIGNING_PUBLIC_KEYS")
    }  # fmt: skip
    base["POLICY_APPROVALS_REQUIRED"] = "2"

    def run(operator: str | None, *args: str) -> Any:
        env = {**base, **({"OPERATOR_ID": operator} if operator else {})}
        get_settings.cache_clear()
        try:
            return CliRunner().invoke(cli, list(args), env=env)
        finally:
            get_settings.cache_clear()

    early = run("alice", "deployment", "activate", P2, "--yes")
    assert early.exit_code != 0 and "promoted candidate" in early.output
    for stage, extra in (("shadow", []), ("evaluation", []), ("candidate", ["--approve"])):
        r = run(
            "alice", "policy", "promote", P2, "--to", stage, "--note", f"staging {stage}", *extra
        )
        assert r.exit_code == 0, r.output
    first = run("alice", "policy", "approve", P2, "--note", "simulation reviewed")
    assert first.exit_code == 0 and "1/2" in first.output, first.output
    twice = run("alice", "policy", "approve", P2, "--note", "again")
    assert twice.exit_code != 0 and "already approved" in twice.output
    one = run("alice", "deployment", "activate", P2, "--yes")
    assert one.exit_code != 0 and "needs 2 approvals" in one.output
    anonymous = run(None, "policy", "approve", P2, "--note", "who am I")
    assert anonymous.exit_code != 0 and "OPERATOR_ID" in anonymous.output
    second = run("bob", "policy", "approve", P2, "--note", "second review")
    assert second.exit_code == 0 and "2/2" in second.output, second.output
    done = run("bob", "deployment", "activate", P2, "--yes")
    assert done.exit_code == 0 and "is active" in done.output, done.output
    log = run(None, "audit", "list")
    assert "operator:alice" in log.output and "operator:bob" in log.output
    assert "chain OK" in run(None, "audit", "verify").output
