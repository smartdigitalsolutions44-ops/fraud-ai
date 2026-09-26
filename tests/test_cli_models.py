"""Stage 3 CLI: train, models list/show/activate, evaluate, compare-models, score."""

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
from fraud_ai.database.models import EventRecord, Transaction


@pytest.fixture
def run(seeded_model_world: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    shutil.copy(seeded_model_world, tmp_path / "w.db")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'w.db'}")
    monkeypatch.setenv("MODEL_DIRECTORY", str(tmp_path / "models"))

    def _run(*args: str) -> Result:
        reset_settings_cache()
        return CliRunner().invoke(cli, list(args), catch_exceptions=False)

    return _run


def _latest_event(model: type) -> str:  # type: ignore[type-arg]
    engine = engine_from_settings(get_settings())
    with make_session_factory(engine)() as s:
        value = s.scalars(select(model.event_id).order_by(model.occurred_at.desc()).limit(1)).one()
    engine.dispose()
    return str(value)


def test_train_evaluate_compare_score_flow(run, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    assert "no models registered" in run("models", "list").output
    report = tmp_path / "report.json"
    trained = run("train", "all", "--maturity-days", "14", "--report", str(report))
    assert trained.exit_code == 0, trained.output
    out = trained.output
    assert "logistic-regression-1.0.0" in out and "gradient-boosting-1.0.0" in out
    assert "SYNTHETIC" in out and "train" in out and "validation" in out
    data = json.loads(report.read_text())
    assert len(data["models"]) == 3 and data["dataset"]["splits"]["test"]["rows"] > 0
    assert (tmp_path / "models" / "random-forest-1.0.0" / "estimator.joblib").exists()

    again = run("train", "logistic", "--maturity-days", "14")
    assert again.exit_code != 0 and "already registered" in again.output

    listed = run("models", "list").output
    assert all(
        f"{m}-1.0.0 " in listed
        for m in ("logistic-regression", "random-forest", "gradient-boosting")
    )
    assert "PR-AUC" in listed
    shown = run("models", "show", "random-forest-1.0.0")
    assert (
        shown.exit_code == 0 and "sha256" in shown.output and "threshold analysis" in shown.output
    )
    assert run("models", "show", "nope-1.0.0").exit_code != 0

    evaluated = run("evaluate", "logistic-regression-1.0.0")
    assert evaluated.exit_code == 0, evaluated.output
    assert "unchanged" in evaluated.output and "reproduced exactly" in evaluated.output

    table = run("compare-models")
    assert table.exit_code == 0 and "PR-AUC" in table.output and "FPR" in table.output
    rows = json.loads(run("compare-models", "--format", "json").output)
    assert {r["model"] for r in rows} == {
        "logistic-regression",
        "random-forest",
        "gradient-boosting",
    }
    assert run("compare-models", "--dataset", "zzzz").exit_code != 0

    event_id = _latest_event(Transaction)
    scored = run("score", event_id, "--model", "gradient-boosting-1.0.0")
    assert (
        scored.exit_code == 0
        and "new prediction" in scored.output
        and "no decision" in scored.output
    )
    assert (
        "existing prediction" in run("score", event_id, "--model", "gradient-boosting-1.0.0").output
    )
    conflict = run("score", event_id, "--model", "gradient-boosting-1.0.0", "--threshold", "0.9")
    assert conflict.exit_code != 0 and "never replaced" in conflict.output
    login = _latest_event(EventRecord)
    assert run("score", login, "--model", "nope-1.0.0").exit_code != 0

    activated = run("models", "activate", "gradient-boosting-1.0.0")
    assert activated.exit_code == 0 and "active" in run("models", "list").output
    assert run("models", "activate", "gradient-boosting-9.9.9").exit_code != 0


def test_train_single_models_with_date_split_and_options(run) -> None:  # type: ignore[no-untyped-def]
    ok = run(
        "train",
        "logistic",
        "--maturity-days",
        "14",
        "--train-end",
        "2026-04-20",
        "--validation-end",
        "2026-05-10",
        "--imbalance",
        "oversample",
        "--seed",
        "7",
        "--version",
        "2.0.0",
        "--threshold",
        "0.3",
    )
    assert ok.exit_code == 0, ok.output
    assert "logistic-regression-2.0.0" in ok.output
    bad = run("train", "random-forest", "--train-end", "2026-04-20")
    assert bad.exit_code != 0 and "both" in bad.output
    empty = run("train", "gradient-boosting", "--start", "2026-06-01", "--end", "2026-05-01")
    assert empty.exit_code != 0
