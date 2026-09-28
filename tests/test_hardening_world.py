"""Stage 10 on the Stage 8 world: promotion (shadow → evaluation → candidate → active),
activation safeguards, fail-closed start-up validation and the new CLI commands."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from click.testing import CliRunner, Result
from sqlalchemy import select, text

from fraud_ai import audit
from fraud_ai.cli.main import cli
from fraud_ai.config.settings import Environment, reset_settings_cache
from fraud_ai.database.engine import session_scope
from fraud_ai.database.models import AuditEvent, PolicyDeployment
from fraud_ai.risk.promotion import current_stage, promote
from fraud_ai.risk.registry import PolicyError, activate
from fraud_ai.service.app import ServiceConfigurationError
from fraud_ai.service.startup import (
    WORKERS_ENV,
    config_fingerprint,
    record_configuration,
    serve_app,
    startup_problems,
)
from tests.realtime_world import GB, LR, P1, P2, World, open_world
from tests.service_helpers import MASTER_KEY, make_harness

Runner = Callable[..., Result]


@pytest.fixture
def w(realtime_world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(realtime_world_dir, tmp_path)


@pytest.fixture
def run(w: World, monkeypatch: pytest.MonkeyPatch) -> Runner:
    monkeypatch.setenv("DATABASE_URL", w.url)
    monkeypatch.setenv("MODEL_DIRECTORY", str(w.root / "models"))

    def _run(*args: str, input: str | None = None) -> Result:
        reset_settings_cache()
        return CliRunner().invoke(cli, list(args), input=input, catch_exceptions=False)

    return _run


def test_promotion_flow_and_activation_gate(w: World) -> None:
    with session_scope(w.factory) as s:
        with pytest.raises(PolicyError, match="must be at stage 'shadow'"):
            promote(s, P2, "evaluation", actor="t", evidence={"simulation": {"x": 1}})
        with pytest.raises(PolicyError, match="already active"):
            promote(s, P1, "shadow", actor="t")
        with pytest.raises(PolicyError, match="not a promoted candidate"):
            activate(s, P2, require_promotion=True)
        promote(s, P2, "shadow", actor="t")  # P2 is a shadow policy of the world deployment
        with pytest.raises(PolicyError, match="already at stage"):
            promote(s, P2, "shadow", actor="t")
        with pytest.raises(PolicyError, match="simulation summary"):
            promote(s, P2, "evaluation", actor="t")
        promote(s, P2, "evaluation", actor="t", evidence={"simulation": {"events": 10}})
        with pytest.raises(PolicyError, match="explicit approval"):
            promote(s, P2, "candidate", actor="t", note="looks fine")
        with pytest.raises(PolicyError, match="note"):
            promote(s, P2, "candidate", actor="t", approved=True)
        promote(s, P2, "candidate", actor="t", approved=True, note="synthetic review ok")
        assert current_stage(s, P2) == "candidate"
        row = activate(s, P2, require_promotion=True, activated_by="cli:tester")
        assert row.activated_by == "cli:tester" and row.policy_version == P2
        with pytest.raises(PolicyError, match="stage"):
            promote(s, P2, "foo", actor="t")
    with w.session() as s:
        actions = [e.action for e in s.scalars(select(AuditEvent).order_by(AuditEvent.sequence))]
        assert actions == ["policy.promoted"] * 3
        assert audit.verify_chain(s).ok


def test_rejected_policies_cannot_be_promoted(w: World) -> None:
    with session_scope(w.factory) as s:
        promote(s, P2, "rejected", actor="t", note="worse on review")
        with pytest.raises(PolicyError, match="rejected"):
            promote(s, P2, "shadow", actor="t")


def test_activation_refuses_mismatched_feature_versions(w: World) -> None:
    w.sql(
        "UPDATE model_versions SET feature_version = 'features-9.9.9' WHERE model_name = :n",
        n="logistic-regression",
    )
    with session_scope(w.factory) as s, pytest.raises(PolicyError):
        activate(s, P1, shadow_models=[LR])
    w.sql(
        "UPDATE model_versions SET artifact_sha256 = :d WHERE model_name = 'gradient-boosting'",
        d="0" * 64,
    )
    with session_scope(w.factory) as s, pytest.raises(PolicyError, match=r"digest|verification"):
        activate(s, P1)
    assert GB


def test_promotion_and_activation_cli(run: Runner, w: World) -> None:
    shadow = run("policy", "promote", P2, "--to", "shadow")
    assert shadow.exit_code == 0 and "stage shadow" in shadow.output
    evaluation = run("policy", "promote", P2, "--to", "evaluation")
    assert evaluation.exit_code == 0, evaluation.output
    assert "evidence" in evaluation.output
    refused = run("policy", "promote", P2, "--to", "candidate", "--note", "ok")
    assert refused.exit_code != 0 and "approval" in refused.output
    assert (
        run("policy", "promote", P2, "--to", "candidate", "--approve", "--note", "ok").exit_code
        == 0
    )
    assert "candidate" in run("policy", "history", P2).output
    assert "no promotion history" in run("policy", "history", P1).output
    activated = run("deployment", "activate", P2, "--yes")
    assert activated.exit_code == 0, activated.output
    with w.session() as s:
        row = s.scalar(select(PolicyDeployment).order_by(PolicyDeployment.sequence.desc()))
        assert row is not None and row.activated_by and row.activated_by.startswith("cli:")
    listing = run("audit", "list", "--action", "policy.activated").output
    assert P2 in listing
    assert "audit chain OK" in run("audit", "verify").output


def test_activation_gate_is_on_in_staging(run: Runner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICY_REQUIRE_PROMOTION", "true")
    result = run("deployment", "activate", P2, "--yes")
    assert result.exit_code != 0 and "not a promoted candidate" in result.output


def test_key_rotation_cli(run: Runner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SERVICE_SIGNING_MASTER_KEY", MASTER_KEY)
    created = run(
        "service-key",
        "create",
        "--name",
        "checkout",
        "--scope",
        "score:write",
        "--expires-in-days",
        "30",
    )
    assert created.exit_code == 0 and "expires" in created.output
    key_id = next(
        line.split()[2] for line in created.output.splitlines() if line.startswith("key id")
    )
    secret = next(
        line.split()[1] for line in created.output.splitlines() if line.startswith("credential")
    )
    rotated = run("service-key", "rotate", key_id, "--grace-hours", "2", "--show-signing-secret")
    assert rotated.exit_code == 0, rotated.output
    assert "stays valid until" in rotated.output and "signing" in rotated.output
    assert secret.split(".")[1] not in rotated.output  # the old secret is never shown again
    listing = run("service-key", "list").output
    assert "rotated from " + key_id in listing and "last used" in listing
    again = run("service-key", "rotate", key_id)
    assert again.exit_code == 0  # still active during the grace period
    signing = run("service-key", "signing-secret", key_id)
    assert signing.exit_code == 0 and "version     1" in signing.output
    assert run("service-key", "signing-secret", "nope").exit_code != 0
    assert run("service-key", "signing-secret", key_id, "--previous").exit_code != 0
    actions = run("audit", "list").output
    assert "service_key.created" in actions and "service_key.rotated" in actions
    revoked = run("service-key", "revoke", key_id)
    assert revoked.exit_code == 0
    assert run("service-key", "rotate", key_id).exit_code != 0


def test_review_resolution_is_audited(run: Runner, w: World) -> None:
    h = make_harness(w.url, engine=w.engine)
    try:
        cred = h.key()
        body, _ = h.drive(cred, w.events, "MANUAL_REVIEW")
        review = h.get("/v1/reviews", cred).json()["items"][0]
        r = h.post(f"/v1/reviews/{review['review_id']}/resolve", cred, {"resolution": "fraud"})
        assert r.status_code == 200
    finally:
        h.container.close()
    listing = run("audit", "list", "--action", "review.resolved").output
    assert review["review_id"] in listing and "api_key:" in listing and body


def test_config_check(run: Runner, monkeypatch: pytest.MonkeyPatch) -> None:
    ok = run("config", "check")
    assert ok.exit_code == 0 and "profile         test" in ok.output
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:fraud_ai_dev@db/x")
    bad = run("config", "check")
    assert bad.exit_code == 1
    assert "https WEBAUTHN_ORIGIN" in bad.output and "placeholder password" in bad.output


# ------------------------------------------------------------------ start-up validation
def test_startup_passes_on_the_world_and_records_configuration(w: World) -> None:
    h = make_harness(w.url, engine=w.engine)
    try:
        assert startup_problems(h.container) == []
        assert record_configuration(h.container) is True
        assert record_configuration(h.container) is False  # unchanged configuration
        digest, visible = config_fingerprint(h.settings)
        assert len(digest) == 64 and visible["pseudonymisation_key_present"] is True
        assert MASTER_KEY not in str(visible)
    finally:
        h.container.close()


def test_startup_fails_closed(w: World, sqlite_url: str) -> None:
    empty = make_harness(sqlite_url)
    try:
        problems = startup_problems(empty.container)
        assert "readiness check active_policy: missing" in problems
    finally:
        empty.container.close()
        empty.container.engine.dispose()
    h = make_harness(w.url, engine=w.engine)
    h.container.settings = h.settings.model_copy(update={"environment": Environment.STAGING})
    try:
        problems = startup_problems(h.container, workers=4)
        assert any("STATE_BACKEND=redis" in p for p in problems)
    finally:
        h.container.close()
    w.sql(
        "UPDATE model_versions SET artifact_sha256 = :d WHERE model_name = 'gradient-boosting'",
        d="f" * 64,
    )
    broken = make_harness(w.url, engine=w.engine)
    try:
        assert "readiness check primary_model: failed" in startup_problems(broken.container)
    finally:
        broken.container.close()


def test_serve_app_factory(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", w.url)
    monkeypatch.setenv(WORKERS_ENV, "1")
    reset_settings_cache()
    app = serve_app()
    app.state.container.close()
    with w.session() as s:
        assert s.scalar(select(AuditEvent.action)) == "service.configuration"
    w.sql("DELETE FROM policy_deployments")
    reset_settings_cache()
    with pytest.raises(ServiceConfigurationError, match="active_policy"):
        serve_app()


def test_readiness_detects_artifact_deletion_and_corruption(w: World) -> None:
    h = make_harness(w.url, engine=w.engine)
    try:
        assert h.get("/v1/ready", None).status_code == 200
        with w.session() as s:
            path = Path(
                str(
                    s.scalar(
                        text(
                            "SELECT model_path FROM model_versions "
                            "WHERE model_name = 'gradient-boosting'"
                        )
                    )
                )
            )
        target = next(p for p in sorted(path.iterdir()) if p.suffix != ".json")
        original = target.read_bytes()
        target.write_bytes(original + b"tampered")
        corrupted = h.get("/v1/ready", None)
        assert corrupted.status_code == 503
        assert corrupted.json()["checks"]["primary_model"] == "failed"
        target.write_bytes(original)
        assert h.get("/v1/ready", None).status_code == 200
        backup = path.with_name(path.name + ".bak")
        path.rename(backup)
        assert h.get("/v1/ready", None).json()["checks"]["primary_model"] == "failed"
        # Scoring still never allows on a broken artefact: the in-memory model is the
        # verified one, and a fresh process would fall back to review (Stage 8 matrix).
        backup.rename(path)
        metrics = h.container.metrics.render().decode()
        assert "fraud_model_verification_failures_total 2.0" in metrics
    finally:
        h.container.close()
