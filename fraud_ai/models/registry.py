"""Model-version registry backed by the ``model_versions`` table."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import ModelVersion
from fraud_ai.utils.logging import get_logger
from fraud_ai.utils.time import ensure_utc

log = get_logger(__name__)


class ModelRegistryError(FraudAIError):
    pass


def register_model_version(
    session: Session,
    *,
    model_name: str,
    model_version: str,
    training_timestamp: datetime,
    training_dataset_version: str,
    feature_version: str,
    model_path: str | Path,
    metrics: dict[str, Any] | None = None,
    algorithm: str | None = None,
    notes: str | None = None,
) -> ModelVersion:
    existing = get_model_version(session, model_name, model_version)
    if existing is not None:
        raise ModelRegistryError(f"{model_name}:{model_version} is already registered")
    row = ModelVersion(
        model_name=model_name,
        model_version=model_version,
        algorithm=algorithm,
        training_timestamp=ensure_utc(training_timestamp),
        training_dataset_version=training_dataset_version,
        feature_version=feature_version,
        metrics=dict(metrics or {}),
        model_path=str(model_path),
        active=False,
        notes=notes,
    )
    session.add(row)
    session.flush()
    log.info("registered model version %s:%s", model_name, model_version)
    return row


def get_model_version(session: Session, model_name: str, model_version: str) -> ModelVersion | None:
    return session.scalar(
        select(ModelVersion).where(
            ModelVersion.model_name == model_name, ModelVersion.model_version == model_version
        )
    )


def activate_model_version(session: Session, model_name: str, model_version: str) -> ModelVersion:
    """Make one version active, deactivating any other version of the same model."""
    target = get_model_version(session, model_name, model_version)
    if target is None:
        raise ModelRegistryError(f"{model_name}:{model_version} is not registered")
    session.execute(
        update(ModelVersion)
        .where(ModelVersion.model_name == model_name, ModelVersion.active.is_(True))
        .values(active=False)
        .execution_options(synchronize_session="fetch")
    )
    session.flush()
    target.active = True
    session.flush()
    log.info("activated model version %s:%s", model_name, model_version)
    return target


def active_model_version(session: Session, model_name: str) -> ModelVersion | None:
    return session.scalar(
        select(ModelVersion).where(
            ModelVersion.model_name == model_name, ModelVersion.active.is_(True)
        )
    )


def list_model_versions(session: Session) -> list[ModelVersion]:
    return list(
        session.scalars(
            select(ModelVersion).order_by(ModelVersion.model_name, ModelVersion.training_timestamp)
        )
    )
