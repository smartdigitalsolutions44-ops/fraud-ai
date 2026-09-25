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
    low = record_prediction(
        session,
        event_id=ev.event_id,
        model_name="baseline_lr",
        model_version="1.0.0",
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
    """Minimal test double proving the interface is implementable."""

    name, version, feature_version, feature_names = "const", "0", "fv1", ("a",)

    def __init__(self, p: float = 0.6) -> None:
        self.p = p

    def train(self, features, labels):  # type: ignore[no-untyped-def]
        self.p = sum(labels) / len(labels)

    def predict_proba(self, features):  # type: ignore[no-untyped-def]
        return [self.p for _ in features]

    def evaluate(self, features, labels, threshold=0.5):  # type: ignore[no-untyped-def]
        preds = self.predict(features, threshold)
        acc = sum(int(p == y) for p, y in zip(preds, labels, strict=True)) / len(labels)
        return EvaluationResult({"accuracy": acc}, len(labels), threshold)

    def save(self, path: Path) -> None:
        path.write_text(str(self.p))

    @classmethod
    def load(cls, path: Path) -> "_ConstantModel":
        return cls(float(path.read_text()))


def test_fraud_model_interface(tmp_path: Path) -> None:
    model = _ConstantModel()
    model.train([[0.0], [1.0], [1.0], [1.0]], [0, 1, 1, 1])
    assert model.predict([[0.0]], threshold=0.7) == [1]
    assert model.evaluate([[0.0], [1.0]], [1, 1]).metrics["accuracy"] == 1.0
    model.save(tmp_path / "m.txt")
    assert _ConstantModel.load(tmp_path / "m.txt").p == 0.75
    with pytest.raises(ValueError):
        model.predict([[0.0]], threshold=2)
    with pytest.raises(TypeError):
        FraudModel()  # type: ignore[abstract]
