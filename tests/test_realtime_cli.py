"""Stage 8 CLI (realtime, policy, deployment, review, monitoring, seed --live-days) and
the hot path on SQLite and PostgreSQL."""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result
from sqlalchemy import Engine, func, select

from fraud_ai.cli.main import cli
from fraud_ai.config.settings import reset_settings_cache
from fraud_ai.core.enums import Decision
from fraud_ai.data.seed import seed_with_live_holdout
from fraud_ai.database.engine import make_session_factory, session_scope
from fraud_ai.database.models import ModelCalibration, RiskAssessment
from fraud_ai.models.registry import resolve_model
from fraud_ai.models.training import run_training
from fraud_ai.realtime.service import FraudScoringService
from fraud_ai.risk.policy import Band, CalibrationSpec, ModelSlot, RiskPolicyDefinition
from fraud_ai.risk.registry import activate, create_policy
from fraud_ai.rules.ruleset import RULES_VERSION, get_rule_set
from tests.conftest import fast_training_config
from tests.realtime_world import P1, P2, PSEUDO, REF, World, open_world


@pytest.fixture
def world_dir(realtime_world_dir: Path) -> Path:
    return realtime_world_dir


@pytest.fixture
def w(world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(world_dir, tmp_path)


@pytest.fixture
def run(w: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DATABASE_URL", w.url)
    monkeypatch.setenv("MODEL_DIRECTORY", str(w.root / "models"))
    monkeypatch.setenv("EVALUATION_DIRECTORY", str(tmp_path / "evaluation"))
    monkeypatch.setenv("PSEUDONYMISATION_KEY", PSEUDO_KEY)

    def _run(*args: str, input: str | None = None) -> Result:
        reset_settings_cache()
        return CliRunner().invoke(cli, list(args), input=input, catch_exceptions=False)

    return _run


from tests.conftest import TEST_KEY as PSEUDO_KEY  # noqa: E402


def _live_file(w: World, n: int) -> Path:
    path = w.root / "prefix.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in w.events[:n]))
    return path


def test_cli_replay_score_and_reassess(run, w: World) -> None:  # type: ignore[no-untyped-def]
    replay = run("realtime", "replay", str(_live_file(w, 120)), "--verbose",
                 "--output", str(w.root / "replay.json"))  # fmt: skip
    assert replay.exit_code == 0, replay.output
    assert "replayed 120 events" in replay.output and "model cache" in replay.output
    assert "decided" in replay.output
    report = json.loads((w.root / "replay.json").read_text())
    decided = [o for o in report["outcomes"] if o["status"] == "decided"]
    assert decided and all(o["event_ref"].startswith("rt-") for o in report["outcomes"])
    again = run("realtime", "replay", str(_live_file(w, 120)))
    assert "'duplicate': 120" in again.output
    # Live scoring: arrival time comes from the clock, so a recorded one is refused.
    live = run("realtime", "score", str(_live_file(w, 3)), "--json")
    outcomes = json.loads(live.output)
    assert all(o["status"] == "rejected" and o["decision"] == "MANUAL_REVIEW" for o in outcomes)
    raw = {k: v for k, v in w.events[0].items() if k != "arrival_time"}
    single = run("realtime", "score", "-", input=json.dumps(raw))
    assert "duplicate" in single.output
    with w.session() as s:
        row = s.scalar(select(RiskAssessment))
        assert row is not None
    reassess = run("realtime", "reassess", str(row.event_id))
    assert reassess.exit_code == 0 and "assessment version 2" in reassess.output
    assert run("realtime", "reassess", str(uuid.uuid4())).exit_code != 0
    empty = w.root / "empty.jsonl"
    empty.write_text("")
    assert run("realtime", "score", str(empty)).exit_code != 0
    broken = w.root / "broken.jsonl"
    broken.write_text('{"a": 1}\nnot json\n')
    assert "line 2" in run("realtime", "score", str(broken)).output
    array = w.root / "array.json"
    array.write_text(json.dumps([raw]))
    assert "duplicate" in run("realtime", "score", str(array)).output


def test_cli_policy_commands(run, w: World) -> None:  # type: ignore[no-untyped-def]
    listed = run("policy", "list")
    assert (
        P1 in listed.output and "ACTIVE" in listed.output and "synthetic-derived" in listed.output
    )
    shown = run("policy", "show", P1)
    assert "bands (calibrated primary score)" in shown.output and "fallbacks:" in shown.output
    as_json = json.loads(run("policy", "show", P1, "--json").output)
    assert as_json["definition"]["policy_version"] == P1 and len(as_json["sha256"]) == 64
    assert run("policy", "show", "risk-policy-9.9.9").exit_code != 0
    sim = run("policy", "simulate", P1, "--step-up-stop-rate", "0.3")
    assert sim.exit_code == 0 and "SYNTHETIC" in sim.output and "written" in sim.output
    cmp = run("policy", "compare", P1, P2, "--iterations", "30")
    assert cmp.exit_code == 0 and "identical test events" in cmp.output
    assert "never a reason to activate" in cmp.output
    assert run("policy", "simulate", "risk-policy-9.9.9").exit_code != 0
    assert run("policy", "compare", P1, "risk-policy-9.9.9").exit_code != 0
    proposed = run("policy", "propose", "risk-policy-2.0.0", "--primary", "gradient-boosting-1.0.0",
                   "--secondary", "logistic-regression-1.0.0")  # fmt: skip
    assert proposed.exit_code == 0, proposed.output
    assert "INACTIVE" in proposed.output and "sha256" in proposed.output
    again = run("policy", "propose", "risk-policy-2.0.0", "--primary", "gradient-boosting-1.0.0")
    assert again.exit_code != 0 and "immutable" in again.output
    bad = run("policy", "propose", "risk-policy-2.0.1", "--primary", "gradient-boosting-1.0.0",
              "--secondary", "gradient-boosting-1.0.0")  # fmt: skip
    assert bad.exit_code != 0


def test_cli_deployment_commands(run, w: World) -> None:  # type: ignore[no-untyped-def]
    shown = run("deployment", "show", "--history")
    assert f"policy          {P1}" in shown.output and "shadow models" in shown.output
    aborted = run("deployment", "activate", P2, input="n\n")
    assert aborted.exit_code != 0
    assert f"policy          {P1}" in run("deployment", "show").output  # nothing changed
    ok = run("deployment", "activate", P2, "--yes", "--note", "cli test")
    assert ok.exit_code == 0 and "deployment #2" in ok.output
    assert "cli test" in run("deployment", "show").output
    assert run("deployment", "activate", "risk-policy-9.9.9", "--yes").exit_code != 0
    status = run("system-status")
    assert f"risk policy     {P2} (deployment #2)" in status.output
    w.sql("UPDATE policy_deployments SET note = 'x', shadow_models = '[\"z\"]' WHERE sequence = 2")
    tampered = run("deployment", "show")
    assert tampered.exit_code != 0 and "not trustworthy" in tampered.output
    assert "UNTRUSTED" in run("system-status").output


def test_cli_review_and_monitoring(run, w: World, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from fraud_ai.realtime import service as service_module

    assert "review queue is empty" in run("review", "list").output
    svc = w.service()
    with monkeypatch.context() as m:
        m.setattr(
            service_module, "point_in_time_snapshot",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")),
        )  # fmt: skip
        w.replay_until(svc, decisions=2)
    listed = run("review", "list")
    review_id = listed.output.split()[0]
    shown = run("review", "show", review_id)
    assert "MANUAL_REVIEW" in shown.output and "feature_extraction_failed" in shown.output
    assert "fraud-ai investigate" in shown.output
    assert run("review", "show", str(uuid.uuid4())).exit_code != 0
    bad = run("review", "resolve", review_id, "--outcome", "fraud", "--note", "mail a@b.com")
    assert bad.exit_code != 0 and "personal data" in bad.output
    assert run("review", "resolve", review_id, "--outcome", "fraud").exit_code == 0
    assert run("review", "resolve", review_id, "--outcome", "legitimate").exit_code != 0
    assert "resolved" in run("review", "list", "--status", "all").output
    summary = run("monitoring", "summary")
    assert summary.exit_code == 0 and "assessments 2" in summary.output
    assert (
        "failure feature_extraction_failed" in summary.output and "latency (ms)" in summary.output
    )
    as_json = json.loads(run("monitoring", "summary", "--json", "--since-hours", "1").output)
    assert as_json["summary"]["assessments"] == 2 and "drift" in as_json
    assert "drift" not in json.loads(run("monitoring", "summary", "--json", "--no-drift").output)
    shadow = run("monitoring", "shadow")
    assert shadow.exit_code == 0 and "assessments with shadow results" in shadow.output


def test_cli_seed_live_holdout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'seed.db'}")
    monkeypatch.setenv("PSEUDONYMISATION_KEY", PSEUDO_KEY)

    def _run(*args: str) -> Result:
        reset_settings_cache()
        return CliRunner().invoke(cli, list(args), catch_exceptions=False)

    _run("db", "init")
    assert _run("seed", "--live-days", "3").exit_code != 0  # needs --live-output
    out = tmp_path / "live.jsonl"
    seeded = _run("seed", "--users", "12", "--days", "30", "--reference-time", "2026-05-01",
                  "--live-days", "3", "--live-output", str(out))  # fmt: skip
    assert seeded.exit_code == 0 and "SYNTHETIC events" in seeded.output
    lines = [json.loads(line) for line in out.read_text().splitlines()]
    assert lines and all("arrival_time" in e for e in lines)
    assert [e["arrival_time"] for e in lines] == sorted(e["arrival_time"] for e in lines)
    assert (
        _run("seed", "--users", "12", "--live-days", "3", "--live-output", str(out)).exit_code != 0
    )


def test_live_holdout_validation(tmp_path: Path, migrated_template: Path) -> None:
    import shutil

    from fraud_ai.data.seed import SeedError
    from fraud_ai.database.engine import create_db_engine

    shutil.copy(migrated_template, tmp_path / "h.db")
    engine = create_db_engine(f"sqlite:///{tmp_path / 'h.db'}")
    with make_session_factory(engine)() as s:
        with pytest.raises(SeedError, match="live_days"):
            seed_with_live_holdout(s, PSEUDO, n_users=12, seed=1, reference_time=REF,
                                   activity_days=30, live_days=40)  # fmt: skip
        with pytest.raises(SeedError, match="late_fraction"):
            seed_with_live_holdout(s, PSEUDO, n_users=12, seed=1, reference_time=REF,
                                   activity_days=30, live_days=3, late_fraction=2)  # fmt: skip
    engine.dispose()


# ------------------------------------------------------------------ SQLite + PostgreSQL
def _hand_policy(session: Any) -> RiskPolicyDefinition:
    record = resolve_model(session, "logistic-regression-1.0.0")
    calibration = ModelCalibration(
        model_version_id=record.model_version_id,
        method="sigmoid",
        fitted_on="validation",
        dataset_fingerprint=record.dataset_fingerprint,
        parameters={"a": 1.0, "b": 0.0},
    )
    session.add(calibration)
    session.flush()
    assert record.artifact_sha256 is not None
    return RiskPolicyDefinition(
        policy_version="risk-policy-0.1.0",
        primary=ModelSlot(
            ref="logistic-regression-1.0.0",
            artifact_sha256=record.artifact_sha256,
            threshold=0.5,
            calibration=CalibrationSpec(
                calibration_id=str(calibration.calibration_id),
                method="sigmoid",
                parameters={"a": 1.0, "b": 0.0},
            ),
        ),
        bands=(
            Band(lower=0.0, risk_level="very_low", decision=Decision.ALLOW),
            Band(lower=0.5, risk_level="elevated", decision=Decision.STEP_UP_AUTHENTICATION),
            Band(lower=0.8, risk_level="high", decision=Decision.MANUAL_REVIEW),
        ),
        rules_version=RULES_VERSION,
        rules_fingerprint=get_rule_set().fingerprint(),
        synthetic_derived=False,
    )


def test_hot_path_on_each_backend(any_engine: Engine, tmp_path: Path) -> None:
    factory = make_session_factory(any_engine)
    with session_scope(factory) as s:
        holdout = seed_with_live_holdout(
            s, PSEUDO, n_users=40, seed=5, reference_time=datetime(2026, 6, 1, tzinfo=UTC),
            activity_days=90, live_days=5, fraud_multiplier=2.0,
        )  # fmt: skip
        run_training(s, ["logistic"], fast_training_config(), tmp_path / "models")
    with session_scope(factory) as s:
        create_policy(s, _hand_policy(s), description="hand-written test policy")
        activate(s, "risk-policy-0.1.0")
    svc = FraudScoringService(factory, PSEUDO, replay=True)
    decided = []
    events = holdout.events
    for i, e in enumerate(events):
        outcome = svc.score_event(e)
        if outcome.status == "decided":
            decided.append((i, outcome))
            if len(decided) == 3:
                break
    assert len(decided) == 3 and all(o.persisted for _, o in decided)
    # Concurrent redelivery of the next decision point (true concurrency on PostgreSQL).
    target = next(
        e for e in events[decided[-1][0] + 1 :] if e["event_type"] == "TRANSACTION_CREATED"
    )
    for e in events[decided[-1][0] + 1 : events.index(target)]:
        svc.score_event(e)
    barrier = threading.Barrier(5)
    results: list[Any] = []

    def worker() -> None:
        barrier.wait()
        results.append(svc.score_event(target))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len({o.assessment_id for o in results}) == 1
    assert [o.status for o in results].count("decided") == 1
    with factory() as s:
        assert (
            s.scalar(
                select(func.count())
                .select_from(RiskAssessment)
                .where(RiskAssessment.event_id == uuid.UUID(target["event_id"]))
            )
            == 1
        )
        row = s.scalar(select(RiskAssessment).where(
            RiskAssessment.event_id == uuid.UUID(target["event_id"])))  # fmt: skip
        assert row is not None and isinstance(row.model_scores, dict)
        assert row.reason_codes and row.latency_ms["total"] > 0
