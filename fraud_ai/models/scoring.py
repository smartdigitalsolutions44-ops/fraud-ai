"""Scoring: event -> point-in-time snapshot -> preprocessor -> model -> probability ->
prediction record.

* The vector is the persisted point-in-time snapshot *as of the event itself*; a snapshot
  computed for any later moment is refused (it could contain the future).
* The artefact is verified against the digest recorded at training time before loading.
* The model refuses feature versions, catalogue fingerprints, preprocessing versions and
  event kinds it was not trained for.
* One prediction per (event, model version): scoring again returns the stored prediction
  if it reproduces exactly, and raises :class:`PredictionConflictError` if it does not.
  A historical prediction is never silently recomputed or replaced.

The threshold only sets ``predicted_class`` for analysis. No decision is made here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import EventRecord, FeatureSnapshot, ModelPrediction, ModelVersion
from fraud_ai.features.context import load_contexts
from fraud_ai.features.definitions import get_feature_set
from fraud_ai.features.extractor import compute_vector
from fraud_ai.features.snapshot import find_snapshot, load_vector, persist_snapshot
from fraud_ai.features.vector import FraudFeatureVector
from fraud_ai.models.base import FRAUD_PROBABILITY, FraudModel
from fraud_ai.models.factory import is_anomaly_model, kind_for_name, load_model
from fraud_ai.models.matrix import FeatureVersionMismatchError, ModelMatrix
from fraud_ai.models.predictions import record_prediction
from fraud_ai.models.preprocessing import SUPPORTED_PREPROCESSING_VERSIONS, PreprocessingError
from fraud_ai.utils.time import ensure_utc

PROBABILITY_TOLERANCE = 1e-12


class ScoringError(FraudAIError):
    pass


class PredictionConflictError(ScoringError):
    """A rescore disagrees with the stored historical prediction."""


class ScoringLeakageError(ScoringError):
    """The vector offered for scoring was computed after the scoring point."""


@dataclass(frozen=True)
class ScoreResult:
    prediction: ModelPrediction
    vector: FraudFeatureVector
    snapshot_id: uuid.UUID
    existing: bool

    @property
    def fraud_probability(self) -> float:
        return self.prediction.fraud_probability


def load_registered_model(model: ModelVersion) -> FraudModel:
    """Load a registered model after verifying compatibility and artefact integrity."""
    if model.artifact_sha256 is None:
        raise ScoringError(f"{model.model_name}-{model.model_version} has no artefact digest")
    if model.preprocessing_version not in SUPPORTED_PREPROCESSING_VERSIONS:
        raise PreprocessingError(
            f"{model.model_name}-{model.model_version} needs preprocessing "
            f"{model.preprocessing_version!r}; supported: "
            f"{sorted(SUPPORTED_PREPROCESSING_VERSIONS)}"
        )
    try:
        fingerprint = get_feature_set(model.feature_version).fingerprint()
    except KeyError as exc:
        raise FeatureVersionMismatchError(str(exc)) from None
    if model.feature_catalogue_fingerprint != fingerprint:
        raise FeatureVersionMismatchError(
            f"{model.model_name}-{model.model_version} was trained on a different "
            f"{model.feature_version} catalogue"
        )
    return load_model(
        kind_for_name(model.model_name), Path(model.model_path), model.artifact_sha256
    )


def trained_kinds(model: ModelVersion) -> set[str]:
    manifest = model.training_manifest or {}
    return set(manifest.get("dataset", {}).get("kinds", []))


def point_in_time_snapshot(
    session: Session, event_id: uuid.UUID, feature_version: str
) -> tuple[FeatureSnapshot, FraudFeatureVector]:
    """The snapshot as of the event's own timestamp (created if absent)."""
    ctx = load_contexts(session, [event_id])[event_id]
    snapshot = find_snapshot(session, event_id, feature_version, ctx.event_time)
    if snapshot is None:
        snapshot = persist_snapshot(session, compute_vector(session, ctx, feature_version))
    return snapshot, load_vector(snapshot, ctx.event_time)


def check_snapshot_is_point_in_time(snapshot: FeatureSnapshot, event_time: datetime) -> None:
    if ensure_utc(snapshot.as_of_timestamp) != ensure_utc(event_time):
        raise ScoringLeakageError(
            f"snapshot {snapshot.snapshot_id} is as of {snapshot.as_of_timestamp}, not the "
            "event time: it may contain information from after the scoring point"
        )


def score_event(
    session: Session,
    event_id: uuid.UUID,
    model: ModelVersion,
    *,
    threshold: float | None = None,
    loaded: FraudModel | None = None,
    snapshot: FeatureSnapshot | None = None,
) -> ScoreResult:
    if is_anomaly_model(model.model_name):
        raise ScoringError(
            f"{model.model_name}-{model.model_version} produces anomaly scores, not fraud "
            "probabilities; it cannot be stored as a fraud prediction"
        )
    event = session.get(EventRecord, event_id)
    if event is None:
        raise ScoringError(f"unknown event {event_id}")
    if snapshot is None:
        snapshot, vector = point_in_time_snapshot(session, event_id, model.feature_version)
    else:
        if snapshot.event_id != event_id or snapshot.feature_version != model.feature_version:
            raise ScoringError("snapshot does not belong to this event / feature version")
        vector = load_vector(snapshot, ensure_utc(event.occurred_at))
    check_snapshot_is_point_in_time(snapshot, event.occurred_at)

    kinds = trained_kinds(model)
    if kinds and vector.event_kind.value not in kinds:
        raise ScoringError(
            f"{model.model_name}-{model.model_version} was trained on "
            f"{sorted(kinds)} events, not {vector.event_kind.value}"
        )
    loaded = loaded or load_registered_model(model)
    if loaded.score_kind != FRAUD_PROBABILITY:  # pragma: no cover - guarded by name above
        raise ScoringError("only fraud-probability models can be scored")
    matrix = ModelMatrix.from_vectors([vector], model.feature_version)
    if loaded.input_kind == "sequence":
        # The same point-in-time extraction as training: the user's events strictly before
        # this event, under the definition the model was trained with.
        from fraud_ai.sequences.extraction import build_sequence
        from fraud_ai.sequences.inputs import SequenceMatrix

        definition = getattr(loaded, "definition", None)
        if definition is None:  # pragma: no cover - a trained sequence model has one
            raise ScoringError("sequence model has no sequence definition")
        matrix = SequenceMatrix.attach(matrix, build_sequence(session, event_id, definition))
    probability = float(loaded.predict_proba(matrix)[0])
    threshold = model.default_threshold if threshold is None else threshold
    if threshold is None:
        raise ScoringError("no threshold given and none recorded with the model")

    prediction, existed = store_prediction(
        session, event_id, model, probability, threshold, snapshot, vector
    )
    return ScoreResult(prediction, vector, snapshot.snapshot_id, existing=existed)


def store_prediction(
    session: Session,
    event_id: uuid.UUID,
    model: ModelVersion,
    probability: float,
    threshold: float,
    snapshot: FeatureSnapshot,
    vector: FraudFeatureVector,
) -> tuple[ModelPrediction, bool]:
    """Persist one prediction per (event, model version).

    Returns ``(prediction, existed)``. A stored prediction that the new score reproduces is
    returned as is; one it contradicts raises :class:`PredictionConflictError`.
    """
    existing = session.scalar(
        select(ModelPrediction).where(
            ModelPrediction.event_id == event_id,
            ModelPrediction.model_name == model.model_name,
            ModelPrediction.model_version == model.model_version,
        )
    )
    if existing is not None:
        same = (
            abs(existing.fraud_probability - probability) <= PROBABILITY_TOLERANCE
            and existing.feature_snapshot_id in (None, snapshot.snapshot_id)
            and existing.threshold == threshold
        )
        if not same:
            raise PredictionConflictError(
                f"event {event_id} already scored by {model.model_name}-{model.model_version} "
                f"(p={existing.fraud_probability:.6f}, threshold={existing.threshold}); the "
                f"rescore gives p={probability:.6f}, threshold={threshold}. Historical "
                "predictions are never replaced."
            )
        return existing, True
    prediction = record_prediction(
        session,
        event_id=event_id,
        model_name=model.model_name,
        model_version=model.model_version,
        fraud_probability=probability,
        threshold=threshold,
        feature_version=model.feature_version,
        user_id=vector.user_id,
        transaction_id=vector.transaction_id,
        feature_snapshot_id=snapshot.snapshot_id,
        feature_snapshot_reference=f"feature_snapshots/{snapshot.snapshot_id}",
    )
    return prediction, False
