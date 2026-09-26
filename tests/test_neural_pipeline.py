"""Stage 5 neural models in the real pipeline: training on the baselines' split, registry,
scoring and prediction persistence, the Stage 4 evaluation framework (confidence,
calibration, scenarios, walk-forward), anomaly evaluation, complementarity, experiments,
the CLI, and SQLite/PostgreSQL."""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pytest
from click.testing import CliRunner, Result
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from fraud_ai.cli.main import cli
from fraud_ai.config.settings import reset_settings_cache
from fraud_ai.data.seed import seed_synthetic_data
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import EventRecord, ModelPrediction, Transaction
from fraud_ai.evaluation import reports
from fraud_ai.evaluation.anomaly_report import anomaly_evaluation
from fraud_ai.evaluation.complementarity import complementarity
from fraud_ai.evaluation.context import EvaluationContext, EvaluationError, build_context
from fraud_ai.evaluation.reports import EvaluationSettings
from fraud_ai.evaluation.walk_forward import WalkForwardConfig, walk_forward
from fraud_ai.models.experiments import ExperimentGrid, run_experiments
from fraud_ai.models.neural import NeuralNetworkModel
from fraud_ai.models.registry import resolve_model
from fraud_ai.models.scoring import ScoringError, load_registered_model, score_event
from fraud_ai.models.training import prepare_data, reevaluate, run_training
from fraud_ai.security.hashing import Pseudonymiser
from tests.conftest import TEST_KEY, fast_training_config

GB, NN, AE = "gradient-boosting-1.0.0", "neural-network-1.0.0", "autoencoder-1.0.0"
FAST = EvaluationSettings(
    iterations=40,
    walk_forward=WalkForwardConfig(
        period_days=15, initial_train_periods=3, max_folds=2, bootstrap_iterations=20
    ),
)


@pytest.fixture(scope="module")
def world(seeded_model_world: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("neural_pipeline")
    shutil.copy(seeded_model_world, root / "world.db")
    engine = create_db_engine(f"sqlite:///{root / 'world.db'}")
    with session_scope(make_session_factory(engine)) as s:
        run_training(
            s, ["gradient-boosting", "neural-network"], fast_training_config(), root / "models"
        )
        run_training(s, ["autoencoder"], fast_training_config(threshold=0.95), root / "models")
    engine.dispose()
    return root


@pytest.fixture
def session(world: Path, tmp_path: Path) -> Iterator[Session]:
    shutil.copy(world / "world.db", tmp_path / "w.db")
    engine = create_db_engine(f"sqlite:///{tmp_path / 'w.db'}")
    with make_session_factory(engine)() as s:
        yield s
        s.rollback()
    engine.dispose()


@pytest.fixture(scope="module")
def ctx(world: Path) -> Iterator[EvaluationContext]:
    engine = create_db_engine(f"sqlite:///{world / 'world.db'}")
    with make_session_factory(engine)() as s:
        yield build_context(s, [GB, NN, AE], allow_anomaly=True)
    engine.dispose()


# ------------------------------------------------------------------ training + registry
def test_neural_model_is_registered_with_full_reproducibility(session: Session) -> None:
    record = resolve_model(session, NN)
    gb = resolve_model(session, GB)
    assert record.algorithm == "torch.FeedForward"
    assert record.dataset_fingerprint == gb.dataset_fingerprint  # same dataset as baselines
    assert (record.train_rows, record.validation_rows, record.test_rows) == (
        gb.train_rows,
        gb.validation_rows,
        gb.test_rows,
    )
    manifest = record.training_manifest or {}
    assert manifest["kind"] == "neural-network"
    model = manifest["model"]
    assert model["hyperparameters"]["hidden_sizes"] == [32, 16]
    assert model["parameter_count"] > 0 and model["optimizer"] == "AdamW"
    assert model["training"]["selection_metric"] == "validation PR-AUC"
    assert model["environment"]["device"] == "cpu" and "torch" in manifest["environment"]
    assert manifest["dataset"]["splits"]["test"]["rows"] == record.test_rows
    assert record.hyperparameters["loss"] == "weighted_bce"
    directory = Path(record.model_path)
    for name in (
        "model.pt",
        "config.json",
        "preprocessing.json",
        "training_manifest.json",
        "metrics.json",
        "artifact_hashes.json",
        "history.json",
    ):
        assert (directory / name).exists(), name
    hashes = json.loads((directory / "artifact_hashes.json").read_text())
    assert "training_manifest.json" in hashes["files"]
    assert hashes["artifact_sha256"] == record.artifact_sha256
    ae = resolve_model(session, AE)
    assert "not a fraud probability" in (ae.algorithm or "")
    assert (ae.metrics or {})["score_kind"] == "anomaly_score"


def test_neural_model_reproduces_on_reevaluation(session: Session) -> None:
    result = reevaluate(session, resolve_model(session, NN))
    assert result.dataset_matches and result.reproduced


# ------------------------------------------------------------------ scoring
def test_score_event_with_the_neural_model(session: Session) -> None:
    record = resolve_model(session, NN)
    event_id = session.scalars(
        select(Transaction.event_id).order_by(Transaction.occurred_at.desc()).limit(1)
    ).one()
    first = score_event(session, event_id, record)
    assert 0.0 <= first.fraud_probability <= 1.0 and not first.existing
    again = score_event(session, event_id, record)
    assert again.existing and again.prediction.prediction_id == first.prediction.prediction_id
    stored = session.scalars(
        select(ModelPrediction).where(ModelPrediction.model_name == "neural-network")
    ).all()
    assert len(stored) == 1 and stored[0].feature_snapshot_id is not None
    loaded = load_registered_model(record)
    assert isinstance(loaded, NeuralNetworkModel)
    with pytest.raises(ScoringError, match="anomaly scores"):
        score_event(session, event_id, resolve_model(session, AE))


# ------------------------------------------------------------------ Stage 4 framework
def test_context_refuses_anomaly_models_unless_allowed(session: Session) -> None:
    with pytest.raises(EvaluationError, match="anomaly scores"):
        build_context(session, [GB, AE])


def test_stage4_reports_work_for_the_neural_model(ctx: EvaluationContext, tmp_path: Path) -> None:
    model = ctx.model(NN)
    confidence = reports.confidence(ctx, model, FAST)
    assert confidence["test"]["metrics"]["pr_auc"]["lower"] is not None
    calibration = reports.calibration(ctx, model, FAST)
    assert set(calibration["methods"]) == {"uncalibrated", "sigmoid", "isotonic"}
    assert calibration["methods"]["sigmoid"]["fitted_on"] == "validation"
    scenarios = reports.scenarios(ctx, model, FAST)
    assert any(
        s["segment"] == "stealthy_account_takeover" for s in scenarios["scenarios"]["segments"]
    )
    errors = reports.errors(ctx, model, FAST)
    assert "false_positives" in errors
    compared = reports.compare(
        EvaluationContext(ctx.prepared, [ctx.model(GB), model], ctx.scenarios, ctx.fraud_types),
        FAST,
    )
    assert compared["pairwise"][0]["a"] == GB and compared["pairwise"][0]["b"] == NN


def test_walk_forward_retrains_the_neural_model(ctx: EvaluationContext) -> None:
    result = walk_forward(ctx, ctx.model(NN), FAST.walk_forward)
    evaluated = [f for f in result["folds"] if "test_metrics" in f]
    assert evaluated
    for fold in evaluated:
        assert fold["model"]["kind"] == "neural-network"
        assert fold["training"]["best_epoch"] >= 1
        assert "+fold" in fold["model"]["retrained_as"]


# ------------------------------------------------------------------ anomaly + research
def test_anomaly_evaluation(ctx: EvaluationContext) -> None:
    report = anomaly_evaluation(ctx, ctx.model(AE), iterations=30)
    assert "NOT a fraud probability" in report["score_kind"]
    assert report["distributions"]["fraud"]["n"] == int(ctx.labels("test").sum())
    assert [f["threshold"] for f in report["flagging"]] == [0.90, 0.95, 0.99]
    shares = [f["flagged_share"] for f in report["flagging"]]
    assert shares == sorted(shares, reverse=True)
    assert report["legitimate_shift_by_month"]
    assert report["scenarios"]["threshold"] == 0.95


def test_complementarity(ctx: EvaluationContext) -> None:
    gb, nn, ae = ctx.model(GB), ctx.model(NN), ctx.model(AE)
    report = complementarity(ctx, gb, nn, anomaly=ae, iterations=30)
    groups = report["disagreement"]["groups"]
    assert sum(g["events"] for g in groups.values()) == len(ctx.labels("test"))
    assert sum(g["fraud"] for g in groups.values()) == int(ctx.labels("test").sum())
    misses = report["base_misses_and_false_alarms"]
    assert misses["caught_by_other"] <= misses["base_false_negatives"]
    assert set(report["combinations"]) == {
        "average_probability",
        "rank_average",
        "rank_average_with_anomaly",
    }
    assert "no combination is persisted" in report["note"]
    versus_anomaly = complementarity(ctx, gb, ae, iterations=20)
    assert "average_probability" not in versus_anomaly["combinations"]


def test_experiment_runner_uses_validation_only(session: Session) -> None:
    prepared = prepare_data(session, fast_training_config())
    grid = ExperimentGrid(
        hidden_sizes=((8,), (16, 8)),
        dropout=(0.1,),
        learning_rate=(1e-3,),
        weight_decay=(0.0,),
        base={"max_epochs": 4, "patience": 2},
    )
    seen: list[int] = []
    result = run_experiments(prepared, grid, progress=lambda i, n, r: seen.append(i))
    assert seen == [1, 2] and len(result["results"]) == 2
    text = json.dumps(result)
    assert "test_pr_auc" not in text and "test split is not used" in result["selection"]
    assert result["loss_experiment"]["focal"]["hyperparameters"]["loss"] == "focal"
    assert result["selected"] == result["results"][0]


# ------------------------------------------------------------------ CLI
@pytest.fixture
def run(world: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    shutil.copy(world / "world.db", tmp_path / "w.db")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'w.db'}")
    monkeypatch.setenv("MODEL_DIRECTORY", str(world / "models"))
    monkeypatch.setenv("EVALUATION_DIRECTORY", str(tmp_path / "evaluation"))

    def _run(*args: str) -> Result:
        reset_settings_cache()
        return CliRunner().invoke(cli, list(args), catch_exceptions=False)

    return _run


def test_cli_neural_inspection(run) -> None:  # type: ignore[no-untyped-def]
    history = run("neural", "training-history", NN)
    assert history.exit_code == 0, history.output
    assert "<- restored" in history.output and "validation PR-AUC" in history.output
    as_json = json.loads(run("neural", "training-history", NN, "--format", "json").output)
    assert as_json["summary"]["best_epoch"] >= 1
    inspect = run("neural", "inspect", NN)
    assert inspect.exit_code == 0, inspect.output
    assert "parameters" in inspect.output and "Linear" in inspect.output
    assert "not inherently interpretable" in inspect.output
    assert run("neural", "inspect", GB).exit_code != 0


def test_cli_train_neural_and_score(run, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("MODEL_DIRECTORY", str(tmp_path / "models"))
    trained = run(
        "train",
        "neural-network",
        "--maturity-days",
        "14",
        "--version",
        "2.0.0",
        "--hidden",
        "16,8",
        "--max-epochs",
        "3",
        "--patience",
        "2",
        "--dropout",
        "0.2",
        "--loss",
        "focal",
    )
    assert trained.exit_code == 0, trained.output
    assert "neural-network-2.0.0" in trained.output
    assert run("train", "neural-network", "--hidden", "0").exit_code != 0
    assert run("train", "neural-network", "--hidden", "a,b").exit_code != 0
    event = _latest_transaction(tmp_path / "w.db")
    scored = run("score", event, "--model", "neural-network-2.0.0")
    assert scored.exit_code == 0, scored.output
    refused = run("score", event, "--model", AE)
    assert refused.exit_code != 0 and "anomaly" in refused.output


def test_cli_anomaly_and_complementarity(run, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    evaluated = run("anomaly", "evaluate", "1.0.0", "--compare-with", GB, "--bootstrap", "50")
    assert evaluated.exit_code == 0, evaluated.output
    assert "NOT a fraud probability" in evaluated.output and "recall" in evaluated.output
    report = json.loads((tmp_path / "evaluation" / AE / "anomaly.json").read_text())
    assert "versus_fraud_model" in report
    assert run("anomaly", "evaluate", "9.9.9").exit_code != 0
    comp = run("evaluate", "complementarity", GB, NN, "--anomaly", "1.0.0", "--bootstrap", "50")
    assert comp.exit_code == 0, comp.output
    assert "adds signal" in comp.output and "both_high" in comp.output
    assert run("evaluate", "complementarity", GB, AE).exit_code != 0
    compare = run("evaluate", "compare", "--bootstrap", "50")  # anomaly model excluded
    assert compare.exit_code == 0, compare.output
    assert AE not in compare.output
    monkeypatch.setenv("MODEL_DIRECTORY", str(tmp_path / "models"))
    trained = run(
        "anomaly",
        "train-autoencoder",
        "--maturity-days",
        "14",
        "--version",
        "2.0.0",
        "--hidden",
        "16",
        "--bottleneck",
        "4",
        "--max-epochs",
        "3",
    )
    assert trained.exit_code == 0, trained.output
    assert "NOT a fraud probability" in trained.output


def test_cli_neural_experiments(run, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    result = run(
        "neural",
        "experiments",
        "--maturity-days",
        "14",
        "--quick",
        "--max-epochs",
        "3",
        "--patience",
        "2",
    )
    assert result.exit_code == 0, result.output
    assert "[ 2/2]" in result.output and "test split not used" in result.output
    files = list((tmp_path / "evaluation" / "neural_experiments").glob("*/experiments.json"))
    assert len(files) == 1


def _latest_transaction(db: Path) -> str:
    engine = create_db_engine(f"sqlite:///{db}")
    with make_session_factory(engine)() as s:
        value = s.scalars(
            select(Transaction.event_id).order_by(Transaction.occurred_at.desc()).limit(1)
        ).one()
    engine.dispose()
    return str(value)


# ------------------------------------------------------------------ SQLite + PostgreSQL
def test_neural_train_and_score_on_each_backend(any_engine: Engine, tmp_path: Path) -> None:
    factory = make_session_factory(any_engine)
    with session_scope(factory) as s:
        seed_synthetic_data(
            s,
            Pseudonymiser(TEST_KEY.encode()),
            n_users=40,
            seed=5,
            reference_time=datetime(2026, 6, 1, tzinfo=UTC),
            activity_days=90,
            fraud_multiplier=2.0,
        )
        run_training(s, ["neural-network"], fast_training_config(), tmp_path / "models")
    with session_scope(factory) as s:
        record = resolve_model(s, NN)
        event_id = s.scalars(select(Transaction.event_id).limit(1)).one()
        result = score_event(s, event_id, record)
        assert s.get(EventRecord, event_id) is not None
        assert np.isfinite(result.fraud_probability)
    with session_scope(factory) as s:
        ctx = build_context(s, [NN])
        report = reports.calibration(ctx, ctx.models[0], FAST)
        assert "sigmoid" in report["methods"]
