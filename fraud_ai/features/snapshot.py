"""Persistent feature snapshots.

A snapshot stores the exact vector computed for (event, feature_version, as_of). The
canonical payload (values + missing reasons) is stored as JSON together with its SHA-256.

* **Idempotent**: persisting the same vector twice returns the existing row.
* **Immutable**: if a recomputation yields a different hash for the same key, that is
  *drift* (the data behind the event changed, or code changed without a version bump) and
  :class:`SnapshotDriftError` is raised - the stored snapshot is never overwritten.
* **Tamper-evident**: loading verifies the stored JSON still matches its stored hash.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import FeatureSnapshot
from fraud_ai.features.definitions import EventKind
from fraud_ai.features.extractor import extract_features
from fraud_ai.features.vector import FraudFeatureVector, MissingReason, hash_payload
from fraud_ai.utils.time import ensure_utc


class SnapshotError(FraudAIError):
    pass


class SnapshotDriftError(SnapshotError):
    """A recomputed vector disagrees with the persisted snapshot for the same key."""


class SnapshotIntegrityError(SnapshotError):
    """A stored snapshot's payload no longer matches its stored hash."""


def find_snapshot(
    session: Session, event_id: uuid.UUID, feature_version: str, as_of: datetime
) -> FeatureSnapshot | None:
    return session.scalar(
        select(FeatureSnapshot).where(
            FeatureSnapshot.event_id == event_id,
            FeatureSnapshot.feature_version == feature_version,
            FeatureSnapshot.as_of_timestamp == ensure_utc(as_of),
        )
    )


def persist_snapshot(session: Session, vector: FraudFeatureVector) -> FeatureSnapshot:
    existing = find_snapshot(
        session, vector.event_id, vector.feature_version, vector.as_of_timestamp
    )
    if existing is not None:
        if existing.feature_hash != vector.feature_hash:
            raise SnapshotDriftError(
                f"event {vector.event_id} ({vector.feature_version}, as of "
                f"{vector.as_of_timestamp.isoformat()}): stored hash {existing.feature_hash[:12]} "
                f"!= recomputed {vector.feature_hash[:12]}"
            )
        return existing
    row = FeatureSnapshot(
        event_id=vector.event_id,
        user_id=vector.user_id,
        transaction_id=vector.transaction_id,
        login_event_id=vector.login_event_id,
        feature_version=vector.feature_version,
        as_of_timestamp=vector.as_of_timestamp,
        features=vector.canonical_payload(),
        feature_hash=vector.feature_hash,
        source_event_count=vector.source_event_count,
    )
    session.add(row)
    session.flush()
    return row


def snapshot_features(
    session: Session,
    event_id: uuid.UUID,
    as_of_timestamp: datetime | None = None,
    feature_version: str | None = None,
) -> FeatureSnapshot:
    return persist_snapshot(
        session, extract_features(session, event_id, as_of_timestamp, feature_version)
    )


def load_vector(snapshot: FeatureSnapshot, event_timestamp: datetime) -> FraudFeatureVector:
    """Rebuild the vector from a snapshot, verifying its integrity first."""
    payload = snapshot.features
    if hash_payload(payload) != snapshot.feature_hash:
        raise SnapshotIntegrityError(f"snapshot {snapshot.snapshot_id} payload/hash mismatch")
    if payload.get("feature_version") != snapshot.feature_version:
        raise SnapshotIntegrityError(f"snapshot {snapshot.snapshot_id} version mismatch")
    return FraudFeatureVector(
        feature_version=snapshot.feature_version,
        event_id=snapshot.event_id,
        event_kind=EventKind.TRANSACTION if snapshot.transaction_id else EventKind.LOGIN,
        event_timestamp=event_timestamp,
        as_of_timestamp=snapshot.as_of_timestamp,
        user_id=snapshot.user_id,
        transaction_id=snapshot.transaction_id,
        login_event_id=snapshot.login_event_id,
        source_event_count=snapshot.source_event_count,
        values=payload["values"],
        missing={k: MissingReason(v) for k, v in payload["missing"].items()},
    )


@dataclass(frozen=True)
class SnapshotCheck:
    snapshot_id: uuid.UUID
    event_id: uuid.UUID
    ok: bool
    problem: str | None = None


def verify_snapshots(session: Session, snapshots: Iterable[FeatureSnapshot]) -> list[SnapshotCheck]:
    """Integrity + reproducibility check: recompute each snapshot and compare hashes."""
    checks: list[SnapshotCheck] = []
    for snap in snapshots:
        if hash_payload(snap.features) != snap.feature_hash:
            checks.append(
                SnapshotCheck(
                    snap.snapshot_id,
                    snap.event_id,
                    False,
                    "stored payload does not match stored hash",
                )
            )
            continue
        try:
            fresh = extract_features(
                session, snap.event_id, snap.as_of_timestamp, snap.feature_version
            )
        except FraudAIError as exc:
            checks.append(
                SnapshotCheck(
                    snap.snapshot_id, snap.event_id, False, f"recomputation failed: {exc}"
                )
            )
            continue
        if fresh.feature_hash != snap.feature_hash:
            changed = sorted(
                name
                for name in set(fresh.values) | set(fresh.missing)
                if fresh.get(name) != snap.features["values"].get(name)
                or (name in fresh.missing) != (name in snap.features["missing"])
            )
            checks.append(
                SnapshotCheck(
                    snap.snapshot_id, snap.event_id, False, f"drift in: {', '.join(changed[:8])}"
                )
            )
        else:
            checks.append(SnapshotCheck(snap.snapshot_id, snap.event_id, True))
    return checks
