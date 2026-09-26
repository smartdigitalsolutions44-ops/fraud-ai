"""Batch extraction for training datasets.

``extract_training_features`` returns feature vectors only. Labels are resolved
separately (``fraud_ai.datasets``) so that no label information can ever be part of a
feature vector.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection, Iterator
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import EventType
from fraud_ai.database.models import EventRecord
from fraud_ai.features.context import LOGIN_EVENT_TYPES, SCORABLE_EVENT_TYPES, load_contexts
from fraud_ai.features.definitions import DEFAULT_FEATURE_VERSION, EventKind
from fraud_ai.features.extractor import compute_vector
from fraud_ai.features.vector import FraudFeatureVector
from fraud_ai.utils.time import ensure_utc

BATCH_SIZE = 500


def event_types_for(kinds: Collection[EventKind]) -> set[EventType]:
    types: set[EventType] = set()
    if EventKind.LOGIN in kinds:
        types |= LOGIN_EVENT_TYPES
    if EventKind.TRANSACTION in kinds:
        types.add(EventType.TRANSACTION_CREATED)
    return types


def scorable_event_ids(
    session: Session,
    start: datetime,
    end: datetime,
    kinds: Collection[EventKind] = (EventKind.LOGIN, EventKind.TRANSACTION),
) -> list[uuid.UUID]:
    """Scorable events with ``start <= occurred_at <= end``, in deterministic order."""
    types = event_types_for(kinds) & SCORABLE_EVENT_TYPES
    return list(
        session.scalars(
            select(EventRecord.event_id)
            .where(
                EventRecord.event_type.in_(types),
                EventRecord.occurred_at >= ensure_utc(start),
                EventRecord.occurred_at <= ensure_utc(end),
            )
            .order_by(EventRecord.occurred_at, EventRecord.event_id)
        )
    )


def iter_vectors(
    session: Session, event_ids: list[uuid.UUID], feature_version: str | None = None
) -> Iterator[FraudFeatureVector]:
    version = feature_version or DEFAULT_FEATURE_VERSION
    for i in range(0, len(event_ids), BATCH_SIZE):
        chunk = event_ids[i : i + BATCH_SIZE]
        contexts = load_contexts(session, chunk)  # bulk-loaded, not per event
        for event_id in chunk:
            yield compute_vector(session, contexts[event_id], version)


@dataclass(frozen=True)
class FeatureBatch:
    feature_version: str
    start: datetime
    end: datetime
    vectors: list[FraudFeatureVector]


def extract_training_features(
    session: Session,
    start_time: datetime,
    end_time: datetime,
    feature_version: str | None = None,
    kinds: Collection[EventKind] = (EventKind.LOGIN, EventKind.TRANSACTION),
) -> FeatureBatch:
    """Point-in-time vectors (each as of its own event time) for events in the range."""
    if ensure_utc(end_time) < ensure_utc(start_time):
        raise ValueError("end_time precedes start_time")
    version = feature_version or DEFAULT_FEATURE_VERSION
    ids = scorable_event_ids(session, start_time, end_time, kinds)
    return FeatureBatch(
        version,
        ensure_utc(start_time),
        ensure_utc(end_time),
        list(iter_vectors(session, ids, version)),
    )
