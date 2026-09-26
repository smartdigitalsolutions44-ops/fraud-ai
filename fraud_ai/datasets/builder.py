"""Training-dataset builder: X (point-in-time features) and y (policy-checked labels).

Nothing is trained. The builder produces aligned feature rows and labels, with full label
provenance and an explicit list of refused examples and why they were refused.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import EventRecord, FeatureSnapshot
from fraud_ai.datasets.labels import (
    LabelAvailabilityPolicy,
    LabelDecision,
    LabelTarget,
    resolve_labels,
)
from fraud_ai.features.batch import iter_vectors, scorable_event_ids
from fraud_ai.features.definitions import DEFAULT_FEATURE_VERSION, EventKind, get_feature_set
from fraud_ai.features.snapshot import load_vector, persist_snapshot
from fraud_ai.features.vector import FeatureScalar, FraudFeatureVector
from fraud_ai.utils.time import ensure_utc, utcnow


class DatasetBuildError(FraudAIError):
    pass


@dataclass(frozen=True)
class DatasetExample:
    event_id: uuid.UUID
    event_time: datetime
    event_kind: EventKind
    vector: FraudFeatureVector
    snapshot_id: uuid.UUID | None

    @property
    def feature_hash(self) -> str:
        return self.vector.feature_hash


@dataclass
class TrainingDataset:
    feature_version: str
    feature_names: tuple[str, ...]
    policy: LabelAvailabilityPolicy
    start: datetime
    end: datetime
    examples: list[DatasetExample]
    labels: list[LabelDecision]
    excluded: list[LabelDecision]
    snapshots_reused: int = 0
    snapshots_created: int = 0
    built_at: datetime = field(default_factory=utcnow)

    def X(self) -> list[list[FeatureScalar | None]]:
        """Raw rows in feature order. ``None`` = missing; no imputation happens here."""
        return [e.vector.ordered_values() for e in self.examples]

    def missing_reasons(self) -> list[dict[str, str]]:
        return [{k: v.value for k, v in e.vector.missing.items()} for e in self.examples]

    def y(self) -> list[int]:
        return [d.label for d in self.labels if d.label is not None]

    def manifest(self) -> dict[str, Any]:
        fs = get_feature_set(self.feature_version)
        statuses = Counter(d.status.value for d in [*self.labels, *self.excluded])
        return {
            "feature_version": self.feature_version,
            "feature_set_fingerprint": fs.fingerprint(),
            "feature_names": list(self.feature_names),
            "label_policy": self.policy.describe(),
            "event_range": {"start": self.start.isoformat(), "end": self.end.isoformat()},
            "built_at": self.built_at.isoformat(),
            "examples": len(self.examples),
            "positives": sum(self.y()),
            "negatives": len(self.y()) - sum(self.y()),
            "label_status_counts": dict(sorted(statuses.items())),
            "snapshots_reused": self.snapshots_reused,
            "snapshots_created": self.snapshots_created,
        }

    def write(self, directory: Path) -> dict[str, Path]:
        """features.jsonl, labels.jsonl (separate files, joined by event_id), manifest.json."""
        directory.mkdir(parents=True, exist_ok=True)
        paths = {
            name: directory / name
            for name in ("features.jsonl", "labels.jsonl", "excluded.jsonl", "manifest.json")
        }
        with paths["features.jsonl"].open("w") as fh:
            for e in self.examples:
                fh.write(
                    json.dumps(
                        {
                            "event_id": str(e.event_id),
                            "event_time": e.event_time.isoformat(),
                            "event_kind": e.event_kind.value,
                            "feature_hash": e.feature_hash,
                            "snapshot_id": str(e.snapshot_id) if e.snapshot_id else None,
                            **e.vector.canonical_payload(),
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
        for name, rows in (("labels.jsonl", self.labels), ("excluded.jsonl", self.excluded)):
            with paths[name].open("w") as fh:
                for d in rows:
                    fh.write(json.dumps(d.to_dict(), sort_keys=True) + "\n")
        paths["manifest.json"].write_text(json.dumps(self.manifest(), indent=2, sort_keys=True))
        return paths


class TrainingDatasetBuilder:
    def __init__(
        self, session: Session, policy: LabelAvailabilityPolicy, feature_version: str | None = None
    ) -> None:
        self.session = session
        self.policy = policy
        self.feature_version = feature_version or DEFAULT_FEATURE_VERSION
        get_feature_set(self.feature_version)

    def build(
        self,
        start: datetime,
        end: datetime,
        *,
        kinds: Collection[EventKind] = (EventKind.LOGIN, EventKind.TRANSACTION),
        use_snapshots: bool = False,
        persist_snapshots: bool = False,
    ) -> TrainingDataset:
        start, end = ensure_utc(start), ensure_utc(end)
        cutoff = ensure_utc(self.policy.label_cutoff)
        if end > cutoff:
            raise DatasetBuildError(
                "event range ends after the label cutoff: events after the cutoff did not "
                "exist when the dataset is notionally built"
            )
        ids = scorable_event_ids(self.session, start, end, kinds)
        event_times: dict[uuid.UUID, datetime] = {}
        for i in range(0, len(ids), 500):
            rows = self.session.execute(
                select(EventRecord.event_id, EventRecord.occurred_at).where(
                    EventRecord.event_id.in_(ids[i : i + 500])
                )
            )
            event_times.update({eid: ensure_utc(ts) for eid, ts in rows})
        vectors, snapshot_ids, reused, created = self._vectors(
            ids, event_times, use_snapshots, persist_snapshots
        )
        targets = [LabelTarget(v.event_id, v.event_timestamp, v.transaction_id) for v in vectors]
        decisions = resolve_labels(self.session, targets, self.policy)

        examples: list[DatasetExample] = []
        labels: list[LabelDecision] = []
        excluded: list[LabelDecision] = []
        for vector, snapshot_id in zip(vectors, snapshot_ids, strict=True):
            decision = decisions[vector.event_id]
            if decision.status.included:
                examples.append(
                    DatasetExample(
                        vector.event_id,
                        vector.event_timestamp,
                        vector.event_kind,
                        vector,
                        snapshot_id,
                    )
                )
                labels.append(decision)
            else:
                excluded.append(decision)
        return TrainingDataset(
            feature_version=self.feature_version,
            feature_names=get_feature_set(self.feature_version).names,
            policy=self.policy,
            start=start,
            end=end,
            examples=examples,
            labels=labels,
            excluded=excluded,
            snapshots_reused=reused,
            snapshots_created=created,
        )

    def _vectors(
        self,
        ids: list[uuid.UUID],
        event_times: dict[uuid.UUID, datetime],
        use_snapshots: bool,
        persist: bool,
    ) -> tuple[list[FraudFeatureVector], list[uuid.UUID | None], int, int]:
        snapshot_ids: list[uuid.UUID | None] = []
        existing: dict[uuid.UUID, FeatureSnapshot] = {}
        if use_snapshots and ids:
            for i in range(0, len(ids), 500):
                chunk = ids[i : i + 500]
                for snap in self.session.scalars(
                    select(FeatureSnapshot).where(
                        FeatureSnapshot.event_id.in_(chunk),
                        FeatureSnapshot.feature_version == self.feature_version,
                    )
                ):
                    # Only the point-in-time snapshot (as of the event itself) is valid.
                    if ensure_utc(snap.as_of_timestamp) == event_times[snap.event_id]:
                        existing[snap.event_id] = snap
        to_compute = [e for e in ids if e not in existing]
        computed = {
            v.event_id: v for v in iter_vectors(self.session, to_compute, self.feature_version)
        }
        vectors: list[FraudFeatureVector] = []
        reused = created = 0
        for event_id in ids:
            if event_id in existing:
                snap = existing[event_id]
                vectors.append(load_vector(snap, event_times[event_id]))
                snapshot_ids.append(snap.snapshot_id)
                reused += 1
                continue
            vector = computed[event_id]
            snapshot_id = None
            if persist:
                snapshot_id = persist_snapshot(self.session, vector).snapshot_id
                created += 1
            vectors.append(vector)
            snapshot_ids.append(snapshot_id)
        return vectors, snapshot_ids, reused, created
