"""Storage of model predictions so model versions can be compared over time."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from fraud_ai.database.models import ModelPrediction
from fraud_ai.models.registry import ModelRegistryError, get_model_version
from fraud_ai.utils.time import ensure_utc, utcnow


def record_prediction(
    session: Session,
    *,
    event_id: uuid.UUID,
    model_name: str,
    model_version: str,
    fraud_probability: float,
    threshold: float,
    feature_version: str,
    user_id: uuid.UUID | None = None,
    transaction_id: uuid.UUID | None = None,
    feature_snapshot_reference: str | None = None,
    prediction_timestamp: datetime | None = None,
) -> ModelPrediction:
    if not 0.0 <= fraud_probability <= 1.0:
        raise ValueError("fraud_probability must be within [0, 1]")
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be within [0, 1]")
    model = get_model_version(session, model_name, model_version)
    if model is None:
        raise ModelRegistryError(f"{model_name}:{model_version} is not registered")
    if model.feature_version != feature_version:
        raise ModelRegistryError(
            f"feature_version {feature_version!r} does not match model's {model.feature_version!r}"
        )
    row = ModelPrediction(
        event_id=event_id,
        transaction_id=transaction_id,
        user_id=user_id,
        model_name=model_name,
        model_version=model_version,
        prediction_timestamp=ensure_utc(prediction_timestamp or utcnow()),
        fraud_probability=fraud_probability,
        predicted_class=int(fraud_probability >= threshold),
        threshold=threshold,
        feature_version=feature_version,
        feature_snapshot_reference=feature_snapshot_reference,
    )
    session.add(row)
    session.flush()
    return row
