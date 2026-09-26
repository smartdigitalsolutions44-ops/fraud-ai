"""Scoring: snapshot -> preprocessor -> model -> prediction, with every refusal."""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session

from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import (
    EventRecord,
    FeatureSnapshot,
    ModelPrediction,
    ModelVersion,
    Transaction,
)
from fraud_ai.features.context import LOGIN_EVENT_TYPES
from fraud_ai.features.snapshot import snapshot_features
from fraud_ai.models.estimators import ArtifactIntegrityError
from fraud_ai.models.matrix import FeatureVersionMismatchError
from fraud_ai.models.preprocessing import PreprocessingError
from fraud_ai.models.registry import resolve_model
from fraud_ai.models.scoring import (
    PredictionConflictError,
    ScoringError,
    ScoringLeakageError,
    load_registered_model,
    score_event,
)
from fraud_ai.models.training import run_training
from tests.conftest import fast_training_config


@pytest.fixture(scope="module")
def scoring_world(seeded_model_world: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("scoring")
    shutil.copy(seeded_model_world, root / "world.db")
    engine = create_db_engine(f"sqlite:///{root / 'world.db'}")
    with session_scope(make_session_factory(engine)) as s:
        run_training(s, ["logistic"], fast_training_config(), root / "models")
    engine.dispose()
    return root


@pytest.fixture
def s(scoring_world: Path, tmp_path: Path) -> Iterator[Session]:
    shutil.copy(scoring_world / "world.db", tmp_path / "w.db")
    engine = create_db_engine(f"sqlite:///{tmp_path / 'w.db'}")
    with make_session_factory(engine)() as session:
        yield session
        session.rollback()
    engine.dispose()


def _txn_event(s: Session, offset: int = 0) -> EventRecord:
    event_id = s.scalars(
        select(Transaction.event_id)
        .order_by(Transaction.occurred_at.desc())
        .offset(offset)
        .limit(1)
    ).one()
    return s.get(EventRecord, event_id)  # type: ignore[return-value]


def test_score_event_persists_prediction_linked_to_snapshot(s: Session) -> None:
    model = resolve_model(s, "logistic-regression-1.0.0")
    event = _txn_event(s)
    result = score_event(s, event.event_id, model)
    p = result.prediction
    assert not result.existing and 0.0 <= p.fraud_probability <= 1.0
    assert p.model_name == "logistic-regression" and p.model_version == "1.0.0"
    assert p.feature_version == model.feature_version and p.threshold == model.default_threshold
    assert p.predicted_class == int(p.fraud_probability >= p.threshold)
    snap = s.get(FeatureSnapshot, p.feature_snapshot_id)
    assert snap is not None and snap.as_of_timestamp == event.occurred_at  # point in time
    assert p.feature_snapshot_reference == f"feature_snapshots/{snap.snapshot_id}"
    assert p.transaction_id is not None and p.user_id is not None


def test_rescoring_is_idempotent_and_never_silently_replaced(s: Session) -> None:
    model = resolve_model(s, "logistic-regression-1.0.0")
    event = _txn_event(s, 1)
    first = score_event(s, event.event_id, model)
    again = score_event(s, event.event_id, model)
    assert again.existing and again.prediction.prediction_id == first.prediction.prediction_id
    assert s.scalar(select(func.count()).select_from(ModelPrediction)) == 1
    with pytest.raises(PredictionConflictError, match="never replaced"):
        score_event(s, event.event_id, model, threshold=0.9)
    s.execute(update(ModelPrediction).values(fraud_probability=0.123456))
    s.expire_all()
    with pytest.raises(PredictionConflictError):
        score_event(s, event.event_id, model)


def test_snapshot_after_scoring_point_is_refused(s: Session) -> None:
    model = resolve_model(s, "logistic-regression-1.0.0")
    event = _txn_event(s, 2)
    later = snapshot_features(s, event.event_id, event.occurred_at + timedelta(days=3))
    with pytest.raises(ScoringLeakageError, match="after the scoring point"):
        score_event(s, event.event_id, model, snapshot=later)
    other = _txn_event(s, 3)
    wrong = snapshot_features(s, other.event_id)
    with pytest.raises(ScoringError, match="does not belong"):
        score_event(s, event.event_id, model, snapshot=wrong)


def test_model_refuses_event_kinds_it_was_not_trained_on(s: Session) -> None:
    model = resolve_model(s, "logistic-regression-1.0.0")
    login = s.scalars(
        select(EventRecord.event_id)
        .where(EventRecord.event_type.in_(LOGIN_EVENT_TYPES), EventRecord.user_id.is_not(None))
        .limit(1)
    ).one()
    with pytest.raises(ScoringError, match="trained on"):
        score_event(s, login, model)
    import uuid

    with pytest.raises(ScoringError, match="unknown event"):
        score_event(s, uuid.uuid4(), model)


def test_incompatible_models_are_refused(s: Session) -> None:
    model = resolve_model(s, "logistic-regression-1.0.0")
    for column, value, error in (
        ("preprocessing_version", "preprocessing-0.1.0", PreprocessingError),
        ("feature_catalogue_fingerprint", "0" * 64, FeatureVersionMismatchError),
        ("feature_version", "fraud-features-0.0.1", FeatureVersionMismatchError),
        ("artifact_sha256", "f" * 64, ArtifactIntegrityError),
        ("artifact_sha256", None, ScoringError),
    ):
        s.begin_nested()
        s.execute(
            update(ModelVersion)
            .where(ModelVersion.model_version_id == model.model_version_id)
            .values({column: value})
        )
        s.expire_all()
        with pytest.raises(error):
            load_registered_model(s.get(ModelVersion, model.model_version_id))  # type: ignore[arg-type]
        s.rollback()


def test_train_and_score_on_each_backend(any_engine: Engine, tmp_path: Path) -> None:
    """The full Stage 3 path on SQLite and PostgreSQL: seed, train, score, persist."""
    from fraud_ai.data.seed import seed_synthetic_data
    from fraud_ai.security.hashing import Pseudonymiser
    from tests.conftest import TEST_KEY

    factory = make_session_factory(any_engine)
    with session_scope(factory) as session:
        seed_synthetic_data(
            session,
            Pseudonymiser(TEST_KEY.encode()),
            n_users=45,
            seed=13,
            reference_time=datetime(2026, 7, 1, tzinfo=UTC),
            activity_days=90,
        )
    with session_scope(factory) as session:
        run = run_training(
            session, ["logistic", "gradient-boosting"], fast_training_config(), tmp_path / "models"
        )
        assert all(r.registered is not None for r in run.results)
    with session_scope(factory) as session:
        model = resolve_model(session, "gradient-boosting-1.0.0")
        event = _txn_event(session)
        result = score_event(session, event.event_id, model)
        assert result.prediction.feature_snapshot_id is not None
    with session_scope(factory) as session:
        stored = session.scalars(select(ModelPrediction)).one()
        assert stored.fraud_probability == result.fraud_probability
        again = score_event(
            session, event.event_id, resolve_model(session, "gradient-boosting-1.0.0")
        )
        assert again.existing
