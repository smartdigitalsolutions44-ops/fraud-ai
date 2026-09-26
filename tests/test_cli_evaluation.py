"""Stage 4 CLI: fraud-ai evaluate confidence|walk-forward|calibration|scenarios|errors|costs|
compare|drift-baseline|report."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner, Result
from sqlalchemy import select

from fraud_ai.cli.main import cli
from fraud_ai.config.settings import get_settings, reset_settings_cache
from fraud_ai.database import engine_from_settings, make_session_factory
from fraud_ai.database.engine import create_db_engine, session_scope
from fraud_ai.database.models import ModelCalibration
from fraud_ai.models.training import run_training
from tests.conftest import fast_training_config

GB = "gradient-boosting-1.0.0"
FAST = ("--bootstrap", "50")


@pytest.fixture(scope="module")
def trained_world(seeded_model_world: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("cli_evaluation")
    shutil.copy(seeded_model_world, root / "world.db")
    engine = create_db_engine(f"sqlite:///{root / 'world.db'}")
    with session_scope(make_session_factory(engine)) as s:
        run_training(s, ["logistic", "gradient-boosting"], fast_training_config(), root / "models")
    engine.dispose()
    return root


@pytest.fixture
def run(trained_world: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    shutil.copy(trained_world / "world.db", tmp_path / "w.db")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'w.db'}")
    monkeypatch.setenv("MODEL_DIRECTORY", str(trained_world / "models"))
    monkeypatch.setenv("EVALUATION_DIRECTORY", str(tmp_path / "evaluation"))

    def _run(*args: str) -> Result:
        reset_settings_cache()
        return CliRunner().invoke(cli, list(args), catch_exceptions=False)

    return _run


def _load(tmp_path: Path, model: str, name: str) -> dict:  # type: ignore[type-arg]
    return json.loads((tmp_path / "evaluation" / model / f"{name}.json").read_text())


def test_evaluate_help_lists_every_subcommand(run) -> None:  # type: ignore[no-untyped-def]
    out = run("evaluate", "--help").output
    for sub in (
        "confidence",
        "walk-forward",
        "calibration",
        "scenarios",
        "errors",
        "costs",
        "compare",
        "drift-baseline",
        "report",
        "reproduce",
    ):
        assert sub in out


def test_confidence_and_errors(run, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    result = run("evaluate", "confidence", GB, *FAST, "--seed", "3", "--level", "0.9")
    assert result.exit_code == 0, result.output
    assert "90% bootstrap CI" in result.output and "pr_auc" in result.output
    report = _load(tmp_path, GB, "confidence")
    assert report["seed"] == 3 and report["iterations"] == 50 and report["level"] == 0.9
    assert set(report["test"]["metrics"]) == {
        "pr_auc",
        "roc_auc",
        "precision",
        "recall",
        "f1",
        "fpr",
        "fnr",
    }
    errors = run("evaluate", "errors", GB, "--limit", "3", "--threshold", "0.2")
    assert errors.exit_code == 0, errors.output
    assert "false positives:" in errors.output and "false negatives:" in errors.output
    data = _load(tmp_path, GB, "errors")
    assert data["threshold"] == 0.2 and len(data["false_positives"]["examples"]) <= 3
    assert run("evaluate", "confidence", "nope-1.0.0").exit_code != 0


def test_calibration_persists_unless_told_not_to(run, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    dry = run("evaluate", "calibration", GB, "--no-persist")
    assert dry.exit_code == 0, dry.output
    assert "isotonic" in dry.output and "persisted" not in dry.output

    def stored() -> list[str]:
        engine = engine_from_settings(get_settings())
        with make_session_factory(engine)() as s:
            methods = sorted(s.scalars(select(ModelCalibration.method)))
        engine.dispose()
        return methods

    assert stored() == []
    for _ in range(2):  # idempotent
        result = run("evaluate", "calibration", GB)
        assert result.exit_code == 0, result.output and "persisted" in result.output
    assert stored() == ["isotonic", "sigmoid"]
    report = _load(tmp_path, GB, "calibration")
    assert report["methods"]["sigmoid"]["fitted_on"] == "validation"
    buckets = report["methods"]["uncalibrated"]["test"]["reliability"]
    assert len(buckets) == 10


def test_scenarios_costs_and_drift(run, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    scen = run("evaluate", "scenarios", GB)
    assert scen.exit_code == 0, scen.output
    assert "stealthy_account_takeover" in scen.output and "operational cohorts" in scen.output
    costs = run(
        "evaluate",
        "costs",
        GB,
        "--fraud-loss",
        "250",
        "--friction",
        "20",
        "--bands",
        "0.2,0.8",
        "--loss-mode",
        "amount",
    )
    assert costs.exit_code == 0, costs.output
    assert "NOT applied" in costs.output and "band high_risk" in costs.output
    data = _load(tmp_path, GB, "costs")
    assert data["manual_review"]["config"]["false_positive_friction"] == 20
    assert data["manual_review"]["config"]["fraud_loss_mode"] == "amount"
    assert _load(tmp_path, GB, "thresholds")["bands"]["boundaries"] == [0.2, 0.8]
    bad = run("evaluate", "costs", GB, "--bands", "0.9,0.1")
    assert bad.exit_code != 0
    assert run("evaluate", "costs", GB, "--bands", "oops").exit_code != 0
    drift = run("evaluate", "drift-baseline", "--model", GB)
    assert drift.exit_code == 0, drift.output
    assert "PSI" in drift.output and "vpn_detected" in drift.output
    assert "limitations" in _load(tmp_path, GB, "drift_baseline")


def test_walk_forward(run, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    result = run(
        "evaluate",
        "walk-forward",
        "logistic-regression-1.0.0",
        "--period-days",
        "15",
        "--initial-periods",
        "3",
        "--max-folds",
        "3",
        *FAST,
    )
    assert result.exit_code == 0, result.output
    assert "PR-AUC across folds" in result.output
    report = _load(tmp_path, "logistic-regression-1.0.0", "walk_forward")
    assert len(report["folds"]) == 3 and report["config"]["period_days"] == 15


def test_compare_and_report(run, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    result = run("evaluate", "compare", *FAST)  # defaults to the models on one dataset
    assert result.exit_code == 0, result.output
    assert "McNemar" in result.output and "appears useful" in result.output
    assert "agreement groups" in result.output
    compare_files = list((tmp_path / "evaluation" / "comparisons").glob("*/compare.json"))
    assert len(compare_files) == 1
    assert run("evaluate", "compare", GB).exit_code != 0  # needs two models
    report = run("evaluate", "report", GB, *FAST, "--output-dir", str(tmp_path / "out"))
    assert report.exit_code == 0, report.output
    names = {p.stem for p in (tmp_path / "out" / GB).glob("*.json")}
    assert names == {
        "summary",
        "confidence",
        "thresholds",
        "calibration",
        "scenarios",
        "errors",
        "costs",
        "walk_forward",
        "drift_baseline",
    }


def test_compare_without_models(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, migrated_template: Path
) -> None:
    shutil.copy(migrated_template, tmp_path / "empty.db")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'empty.db'}")
    reset_settings_cache()
    result = CliRunner().invoke(cli, ["evaluate", "compare"])
    assert result.exit_code != 0 and "no models registered" in result.output
