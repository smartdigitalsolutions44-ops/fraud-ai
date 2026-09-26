"""Stage 6 sequence models in the real pipeline: training on the baselines' split,
registry + reproducibility (sequence fingerprint and digest), scoring and prediction
persistence, Stage 4 evaluation (calibration, scenarios, walk-forward), complementarity,
the stealth report, anti-shortcut checks, the CLI, and SQLite/PostgreSQL."""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pytest
from click.testing import CliRunner, Result
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from fraud_ai.cli.main import cli
from fraud_ai.config.settings import reset_settings_cache
from fraud_ai.core.enums import EventSource, EventType
from fraud_ai.data.seed import seed_synthetic_data
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import EventRecord, ModelPrediction, Transaction, User
from fraud_ai.evaluation import reports
from fraud_ai.evaluation.complementarity import complementarity
from fraud_ai.evaluation.context import EvaluationContext, EvaluationError, build_context
from fraud_ai.evaluation.reports import EvaluationSettings
from fraud_ai.evaluation.shortcuts import univariate_separability
from fraud_ai.evaluation.stealth import stealth_report
from fraud_ai.evaluation.walk_forward import WalkForwardConfig, walk_forward
from fraud_ai.models.registry import resolve_model
from fraud_ai.models.scoring import load_registered_model, score_event
from fraud_ai.models.sequence_models import SequenceModel
from fraud_ai.models.training import prepare_data, reevaluate, run_training
from fraud_ai.security.hashing import Pseudonymiser
from fraud_ai.sequences.definition import SequenceDefinition
from fraud_ai.sequences.inputs import SequenceMatrix
from tests.conftest import TEST_KEY, fast_training_config

GB, GRU, TRF, HYB = (
    "gradient-boosting-1.0.0",
    "gru-1.0.0",
    "transformer-1.0.0",
    "hybrid-gru-1.0.0",
)
DEF = SequenceDefinition(max_events=16)
FAST = EvaluationSettings(
    iterations=40,
    walk_forward=WalkForwardConfig(
        period_days=15, initial_train_periods=3, max_folds=2, bootstrap_iterations=20
    ),
)


@pytest.fixture(scope="module")
def world(seeded_model_world: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("sequence_pipeline")
    shutil.copy(seeded_model_world, root / "world.db")
    engine = create_db_engine(f"sqlite:///{root / 'world.db'}")
    with session_scope(make_session_factory(engine)) as s:
        run_training(
            s,
            ["gradient-boosting", "gru", "transformer", "hybrid-gru"],
            fast_training_config(sequence=DEF),
            root / "models",
        )
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
        yield build_context(s, [GB, GRU, TRF, HYB])
    engine.dispose()


# ------------------------------------------------------------------ registry
def test_sequence_models_are_registered_with_sequence_provenance(session: Session) -> None:
    gb = resolve_model(session, GB)
    for ref, algorithm in (
        (GRU, "torch.GRU"),
        (TRF, "torch.CausalTransformer"),
        (HYB, "torch.Hybrid(GRU+static)"),
    ):
        record = resolve_model(session, ref)
        assert record.algorithm == algorithm
        assert record.dataset_fingerprint == gb.dataset_fingerprint  # same examples
        assert (record.train_rows, record.test_rows) == (gb.train_rows, gb.test_rows)
        manifest = record.training_manifest or {}
        dataset = manifest["dataset"]
        assert dataset["sequence"]["fingerprint"] == DEF.fingerprint()
        assert len(dataset["sequence_digest"]) == 64
        model = manifest["model"]
        assert model["sequence_fingerprint"] == DEF.fingerprint()
        assert model["embedding_vocabulary_version"] == DEF.version
        assert model["input_kind"] == "sequence" and model["parameter_count"] > 0
        assert (Path(record.model_path) / "artifact_hashes.json").exists()


def test_reevaluation_reproduces(session: Session) -> None:
    result = reevaluate(session, resolve_model(session, GRU))
    assert result.dataset_matches and result.reproduced


# ------------------------------------------------------------------ scoring
def test_score_event_builds_the_sequence_and_persists(session: Session) -> None:
    record = resolve_model(session, TRF)
    event_id = session.scalars(
        select(Transaction.event_id).order_by(Transaction.occurred_at.desc()).limit(1)
    ).one()
    first = score_event(session, event_id, record)
    assert 0 <= first.fraud_probability <= 1 and not first.existing
    assert score_event(session, event_id, record).existing
    stored = session.scalars(
        select(ModelPrediction).where(ModelPrediction.model_name == "transformer")
    ).all()
    assert len(stored) == 1
    loaded = load_registered_model(record)
    assert isinstance(loaded, SequenceModel) and loaded.definition == DEF


# ------------------------------------------------------------------ evaluation context
def test_context_rebuilds_and_verifies_sequences(ctx: EvaluationContext) -> None:
    assert isinstance(ctx.prepared.matrix, SequenceMatrix)
    assert ctx.prepared.matrix.sequences.definition == DEF
    for m in ctx.models:
        assert len(m.scores["test"]) == len(ctx.labels("test"))


def test_context_refuses_changed_history(session: Session) -> None:
    """Rewriting an old event changes the sequences, so evaluation must refuse."""
    event = session.scalars(
        select(EventRecord)
        .where(EventRecord.event_type == EventType.LOGIN_SUCCESS)
        .order_by(EventRecord.occurred_at)
        .limit(1)
    ).one()
    event.metadata_json = {**event.metadata_json, "mfa_used": True}
    session.flush()
    with pytest.raises(EvaluationError, match="sequences can no longer be reproduced"):
        build_context(session, [GRU])


def test_context_refuses_mixed_definitions(session: Session, tmp_path: Path) -> None:
    run_training(
        session,
        ["gru"],
        fast_training_config(version="2.0.0", sequence=SequenceDefinition(max_events=8)),
        tmp_path / "models",
    )
    with pytest.raises(EvaluationError, match="different sequence definitions"):
        build_context(session, [GRU, "gru-2.0.0"])


def test_stage4_reports_for_sequence_models(ctx: EvaluationContext) -> None:
    for ref in (GRU, HYB):
        model = ctx.model(ref)
        calibration = reports.calibration(ctx, model, FAST)
        assert calibration["methods"]["sigmoid"]["fitted_on"] == "validation"
        scenarios = reports.scenarios(ctx, model, FAST)
        assert scenarios["scenarios"]["segments"]
    result = walk_forward(ctx, ctx.model(GRU), FAST.walk_forward)
    evaluated = [f for f in result["folds"] if "test_metrics" in f]
    assert evaluated and all(f["model"]["kind"] == "gru" for f in evaluated)
    assert all(f["training"]["best_epoch"] >= 1 for f in evaluated)


def test_complementarity_overlap_and_stealth_report(ctx: EvaluationContext) -> None:
    gb, gru = ctx.model(GB), ctx.model(GRU)
    report = complementarity(ctx, gb, gru, iterations=30)
    overlap = report["fraud_detection_overlap"]
    total = sum(
        overlap[k]["count"]
        for k in (
            "caught_by_both",
            f"caught_only_by_{GB}",
            f"caught_only_by_{GRU}",
            "missed_by_both",
        )
    )
    assert total == overlap["fraud_events"] == int(ctx.labels("test").sum())
    stealth = stealth_report(ctx)
    assert set(stealth["recall_by_model"]) == {GB, GRU, TRF, HYB}
    for case in stealth["details"]:
        assert case["ref"].startswith("ex-") and set(case["probabilities"]) == {GB, GRU, TRF, HYB}
        behaviour = case["behaviour"]
        assert behaviour["history_events"] <= DEF.max_events
        assert {"device_changes", "failed_logins", "security_changes"} <= set(behaviour)
    text = json.dumps(stealth, default=str)
    for example in ctx.prepared.dataset.examples[:100]:
        assert str(example.event_id) not in text and str(example.vector.user_id) not in text


# ------------------------------------------------------------------ generator realism
def test_temporal_takeovers_have_no_single_feature_shortcut(session: Session) -> None:
    """The temporal scenario must not be separable by any one current-event feature."""
    prepared = prepare_data(session, fast_training_config())
    scenario = dict(session.execute(select(User.user_id, User.synthetic_scenario)).all())
    names = np.array([scenario.get(e.vector.user_id) for e in prepared.dataset.examples])
    y = prepared.y
    slow = (names == "slow_account_takeover") & (y == 1)
    assert slow.sum() >= 5
    rows = list(np.flatnonzero((y == 0) | slow))
    ranked = univariate_separability(prepared.matrix.take(rows), y[rows])
    assert ranked[0]["auc"] < 0.95, ranked[:3]


def test_generator_emits_every_temporal_variant() -> None:
    from fraud_ai.data.synthetic import SyntheticDataGenerator

    ds = SyntheticDataGenerator(
        seed=3, reference_time=datetime(2026, 7, 1, tzinfo=UTC), activity_days=120
    ).generate(400)
    assert ds.scenario_counts["slow_account_takeover"] >= 15
    assert ds.scenario_counts["legitimate_lookalike"] >= 10
    confirmed = [e for e in ds.events if e.event_type is EventType.FRAUD_CONFIRMED]
    assert confirmed and all(e.source is EventSource.SYNTHETIC for e in confirmed)
    # Temporal attacks spread over days: failed logins on >= 2 different days before a
    # successful login from the same device happen in the data.
    per_user: dict[object, list[datetime]] = {}
    for e in ds.events:
        if e.event_type is EventType.LOGIN_FAILURE and e.user_id is not None:
            per_user.setdefault(e.user_id, []).append(e.timestamp)
    assert any(len({t.date() for t in times}) >= 2 for times in per_user.values())


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


def _latest_transaction(db: Path) -> str:
    engine = create_db_engine(f"sqlite:///{db}")
    with make_session_factory(engine)() as s:
        value = s.scalars(
            select(Transaction.event_id).order_by(Transaction.occurred_at.desc()).limit(1)
        ).one()
    engine.dispose()
    return str(value)


def test_cli_sequence_build_and_inspect(run, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    event = _latest_transaction(tmp_path / "w.db")
    built = run("sequence", "build", event, "--max-events", "8")
    assert built.exit_code == 0, built.output
    payload = json.loads(built.output)
    assert payload["definition"]["max_events"] == 8 and payload["length"] <= 9
    assert payload["positions"][-1]["is_target"] == 1.0
    again = json.loads(run("sequence", "build", event, "--max-events", "8").output)
    assert again["sequence_digest"] == payload["sequence_digest"]
    out = tmp_path / "seq.json"
    assert run("sequence", "build", event, "--output", str(out)).exit_code == 0
    assert json.loads(out.read_text())["definition"]["max_events"] == 16
    inspected = run("sequence", "inspect", event)
    assert inspected.exit_code == 0 and "TRANSACTION_CREATED" in inspected.output
    assert "is_target" in inspected.output
    assert run("sequence", "build", "not-a-uuid").exit_code != 0
    assert run("sequence", "build", event, "--max-age-days", "400").exit_code != 0


def test_cli_train_and_score_sequence_models(run, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("MODEL_DIRECTORY", str(tmp_path / "models"))
    for command, name in (("gru", "gru"), ("transformer", "transformer"), ("hybrid", "hybrid-gru")):
        trained = run(
            "train",
            command,
            "--maturity-days",
            "14",
            "--version",
            "3.0.0",
            "--max-events",
            "8",
            "--hidden-size",
            "8",
            "--heads",
            "2",
            "--max-epochs",
            "2",
            "--patience",
            "1",
        )
        assert trained.exit_code == 0, trained.output
        assert f"{name}-3.0.0" in trained.output and "fingerprint" in trained.output
    assert run("train", "gru", "--max-age-days", "999").exit_code != 0
    event = _latest_transaction(tmp_path / "w.db")
    scored = run("score", event, "--model", "gru-3.0.0")
    assert scored.exit_code == 0, scored.output


def test_cli_sequence_compare_and_stealth(run, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    compared = run("sequence", "compare", "--bootstrap", "50")
    assert compared.exit_code == 0, compared.output
    assert "missed by every model" in compared.output and "gru-1.0.0" in compared.output
    assert len(list((tmp_path / "evaluation").glob("comparisons/*/sequence_compare.json"))) == 1
    stealth = run("sequence", "stealth-report")
    assert stealth.exit_code == 0, stealth.output
    assert "recall" in stealth.output and "caught only by sequence models" in stealth.output
    assert run("sequence", "compare", "--base", "nope-1.0.0").exit_code != 0
    report = run("evaluate", "report", GRU, "--bootstrap", "50")
    assert report.exit_code == 0, report.output


# ------------------------------------------------------------------ SQLite + PostgreSQL
def test_sequence_train_and_score_on_each_backend(any_engine: Engine, tmp_path: Path) -> None:
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
        run_training(
            s,
            ["gru"],
            fast_training_config(
                sequence=SequenceDefinition(max_events=8), maturity=timedelta(days=14)
            ),
            tmp_path / "models",
        )
    with session_scope(factory) as s:
        record = resolve_model(s, GRU)
        event_id = s.scalars(select(Transaction.event_id).limit(1)).one()
        assert np.isfinite(score_event(s, event_id, record).fraud_probability)
    with session_scope(factory) as s:
        ctx = build_context(s, [GRU])
        assert isinstance(ctx.prepared.matrix, SequenceMatrix)
