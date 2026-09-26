import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from fraud_ai.core.enums import EventType
from fraud_ai.models.base import EvaluationResult, FraudModel
from fraud_ai.models.predictions import record_prediction
from fraud_ai.models.registry import (
    ModelRegistryError,
    activate_model_version,
    active_model_version,
    list_model_versions,
    register_model_version,
)
from tests.conftest import create_user, make_event

T = datetime(2026, 4, 1, tzinfo=UTC)


def _register(session: Session, version: str, **kw: object) -> None:
    register_model_version(
        session,
        model_name="baseline_lr",
        model_version=version,
        training_timestamp=T,
        training_dataset_version="synthetic-seed42",
        feature_version="fv1",
        model_path=f"models/lr-{version}.bin",
        metrics={"auc": 0.91, "precision_at_1pct": 0.4},
        algorithm="logistic_regression",
        **kw,
    )  # type: ignore[arg-type]


def test_register_and_activate(session: Session) -> None:
    _register(session, "1.0.0")
    _register(session, "1.1.0", notes="more data")
    assert active_model_version(session, "baseline_lr") is None
    activate_model_version(session, "baseline_lr", "1.0.0")
    activate_model_version(session, "baseline_lr", "1.1.0")
    active = active_model_version(session, "baseline_lr")
    assert active is not None and active.model_version == "1.1.0"
    assert [v.active for v in list_model_versions(session)] == [False, True]
    assert active.metrics["auc"] == 0.91 and active.notes == "more data"


def test_registry_errors(session: Session) -> None:
    _register(session, "1.0.0")
    with pytest.raises(ModelRegistryError, match="already registered"):
        _register(session, "1.0.0")
    with pytest.raises(ModelRegistryError, match="not registered"):
        activate_model_version(session, "baseline_lr", "9.9.9")


def test_record_prediction(session: Session, processor: object) -> None:
    uid = create_user(processor)  # type: ignore[arg-type]
    ev = make_event(EventType.LOGIN_SUCCESS, uid, {})
    processor.process(ev)  # type: ignore[attr-defined]
    _register(session, "1.0.0")
    p = record_prediction(
        session,
        event_id=ev.event_id,
        user_id=uid,
        model_name="baseline_lr",
        model_version="1.0.0",
        fraud_probability=0.78,
        threshold=0.5,
        feature_version="fv1",
        feature_snapshot_reference="snapshots/abc.json",
    )
    assert p.predicted_class == 1 and p.model.algorithm == "logistic_regression"
    from sqlalchemy.exc import IntegrityError

    with session.begin_nested(), pytest.raises(IntegrityError):  # one per event per version
        record_prediction(
            session,
            event_id=ev.event_id,
            model_name="baseline_lr",
            model_version="1.0.0",
            fraud_probability=0.2,
            threshold=0.5,
            feature_version="fv1",
        )
    _register(session, "1.0.1")
    low = record_prediction(
        session,
        event_id=ev.event_id,
        model_name="baseline_lr",
        model_version="1.0.1",
        fraud_probability=0.2,
        threshold=0.5,
        feature_version="fv1",
    )
    assert low.predicted_class == 0
    with pytest.raises(ModelRegistryError, match="feature_version"):
        record_prediction(
            session,
            event_id=ev.event_id,
            model_name="baseline_lr",
            model_version="1.0.0",
            fraud_probability=0.2,
            threshold=0.5,
            feature_version="fv2",
        )
    with pytest.raises(ModelRegistryError):
        record_prediction(
            session,
            event_id=ev.event_id,
            model_name="nope",
            model_version="1",
            fraud_probability=0.2,
            threshold=0.5,
            feature_version="fv1",
        )
    with pytest.raises(ValueError):
        record_prediction(
            session,
            event_id=uuid.uuid4(),
            model_name="baseline_lr",
            model_version="1.0.0",
            fraud_probability=1.2,
            threshold=0.5,
            feature_version="fv1",
        )


class _ConstantModel(FraudModel):
    """Minimal test double proving the Stage 3 contract is implementable."""

    model_name, version, feature_version = "const", "0", "fraud-features-1.0.0"

    def __init__(self, p: float = 0.6) -> None:
        self.p = p
        self.seed, self.imbalance, self.hyperparameters, self.train_seconds = 0, "none", {}, None

    @property
    def algorithm(self) -> str:
        return "constant"

    def train(self, matrix, labels, validation=None):  # type: ignore[no-untyped-def]
        self.p = sum(labels) / len(labels)

    def manifest(self):  # type: ignore[no-untyped-def]
        return {"kind": "const", "p": self.p}

    def explain(self, matrix=None, labels=None, top_k=12):  # type: ignore[no-untyped-def]
        return {"method": "none", "top_features": []}

    def predict_proba(self, matrix):  # type: ignore[no-untyped-def]
        import numpy as np

        return np.full(len(matrix), self.p)

    def evaluate(self, matrix, labels, threshold=0.5):  # type: ignore[no-untyped-def]
        from fraud_ai.models.metrics import evaluate_scores

        return EvaluationResult(
            evaluate_scores(labels, self.predict_proba(matrix), threshold), len(matrix), threshold
        )

    def save(self, directory: Path) -> str:
        directory.mkdir()
        (directory / "p.txt").write_text(str(self.p))
        return "digest"

    @classmethod
    def load(cls, directory: Path, expected_sha256: str) -> "_ConstantModel":
        assert expected_sha256 == "digest"
        return cls(float((directory / "p.txt").read_text()))


def test_fraud_model_interface(tmp_path: Path) -> None:
    from fraud_ai.models.matrix import ModelMatrix
    from tests.model_helpers import make_vectors

    vectors, _ = make_vectors(4)
    matrix = ModelMatrix.from_vectors(vectors)
    model = _ConstantModel()
    model.train(matrix, [0, 1, 1, 1])
    assert list(model.predict(matrix, threshold=0.7)) == [1, 1, 1, 1]
    assert model.evaluate(matrix, [1, 0, 1, 1]).metrics["recall"] == 1.0
    assert model.save(tmp_path / "m") == "digest"
    assert _ConstantModel.load(tmp_path / "m", "digest").p == 0.75
    assert model.model_id == "const-0" and model.algorithm == "constant"
    assert model.score_kind == "fraud_probability" and model.manifest()["kind"] == "const"
    assert model.explain()["top_features"] == []
    with pytest.raises(ValueError):
        model.predict(matrix, threshold=2)
    with pytest.raises(TypeError):
        FraudModel()  # type: ignore[abstract]
