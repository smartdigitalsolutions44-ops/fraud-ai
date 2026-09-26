"""Label availability policy and label resolution.

A training example may only carry a label that was *known* at the configured
``label_cutoff`` (the moment the dataset is notionally built). The policy, in order:

1. Only labels whose source is in ``allowed_sources`` are considered.
2. A label timestamped before its own event is impossible provenance: the example is
   excluded (``invalid_provenance``).
3. Labels with ``labelled_at > label_cutoff`` do not exist yet. If only such labels exist
   the example is refused (``label_not_yet_known``).
4. Any known FRAUD label makes the example positive (a chargeback overrides an earlier
   "legitimate" assessment).
5. A negative needs the event to have *matured*: ``event_time + maturity <= label_cutoff``,
   so late-arriving fraud (chargebacks can take weeks) has had time to appear. Immature
   negatives are excluded (``immature``).
6. Explicit LEGITIMATE labels give negatives; unlabelled mature events become negatives
   only when ``implicit_negatives`` is enabled, otherwise they are excluded
   (``unlabelled``).

Labels are matched to an example by its event id (e.g. a FRAUD_CONFIRMED on a login) or
its transaction id (e.g. a chargeback). They are never written into feature vectors.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import ColumnElement, or_, select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import FraudType, LabelSource, LabelValue
from fraud_ai.database.models import FraudLabel
from fraud_ai.utils.time import ensure_utc

POLICY_VERSION = "label-policy-1"


class LabelStatus(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEGATIVE_IMPLICIT = "negative_implicit"
    LABEL_NOT_YET_KNOWN = "label_not_yet_known"
    IMMATURE = "immature"
    UNLABELLED = "unlabelled"
    INVALID_PROVENANCE = "invalid_provenance"

    @property
    def included(self) -> bool:
        return self in {LabelStatus.POSITIVE, LabelStatus.NEGATIVE, LabelStatus.NEGATIVE_IMPLICIT}


@dataclass(frozen=True)
class LabelAvailabilityPolicy:
    label_cutoff: datetime
    maturity: timedelta = timedelta(days=30)
    allowed_sources: frozenset[LabelSource] = field(default_factory=lambda: frozenset(LabelSource))
    implicit_negatives: bool = False
    policy_version: str = POLICY_VERSION

    def __post_init__(self) -> None:
        if self.label_cutoff.tzinfo is None:
            raise ValueError("label_cutoff must be timezone-aware")
        if self.maturity < timedelta(0):
            raise ValueError("maturity must not be negative")

    def describe(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "label_cutoff": ensure_utc(self.label_cutoff).isoformat(),
            "maturity_days": self.maturity.total_seconds() / 86400,
            "allowed_sources": sorted(s.value for s in self.allowed_sources),
            "implicit_negatives": self.implicit_negatives,
        }


@dataclass(frozen=True)
class LabelProvenance:
    label_id: uuid.UUID
    label: LabelValue
    label_source: LabelSource
    labelled_at: datetime
    fraud_type: FraudType | None
    known_at_cutoff: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "label_id": str(self.label_id),
            "label": self.label.value,
            "label_source": self.label_source.value,
            "labelled_at": self.labelled_at.isoformat(),
            "fraud_type": self.fraud_type.value if self.fraud_type else None,
            "known_at_cutoff": self.known_at_cutoff,
        }


@dataclass(frozen=True)
class LabelDecision:
    event_id: uuid.UUID
    status: LabelStatus
    label: int | None
    provenance: tuple[LabelProvenance, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "label": self.label,
            "status": self.status.value,
            "provenance": [p.to_dict() for p in self.provenance],
        }


@dataclass(frozen=True)
class LabelTarget:
    event_id: uuid.UUID
    event_time: datetime
    transaction_id: uuid.UUID | None


def _decide(
    target: LabelTarget, labels: list[FraudLabel], policy: LabelAvailabilityPolicy
) -> LabelDecision:
    cutoff = ensure_utc(policy.label_cutoff)
    usable = [lbl for lbl in labels if lbl.label_source in policy.allowed_sources]
    provenance = tuple(
        LabelProvenance(
            lbl.label_id,
            lbl.label,
            lbl.label_source,
            ensure_utc(lbl.labelled_at),
            lbl.fraud_type,
            ensure_utc(lbl.labelled_at) <= cutoff,
        )
        for lbl in sorted(usable, key=lambda x: (x.labelled_at, str(x.label_id)))
    )
    if any(p.labelled_at < target.event_time for p in provenance):
        return LabelDecision(target.event_id, LabelStatus.INVALID_PROVENANCE, None, provenance)
    known = [p for p in provenance if p.known_at_cutoff]
    if any(p.label is LabelValue.FRAUD for p in known):
        return LabelDecision(target.event_id, LabelStatus.POSITIVE, 1, provenance)
    matured = target.event_time + policy.maturity <= cutoff
    if known:  # LEGITIMATE only
        status = LabelStatus.NEGATIVE if matured else LabelStatus.IMMATURE
        return LabelDecision(target.event_id, status, 0 if matured else None, provenance)
    if provenance:
        return LabelDecision(target.event_id, LabelStatus.LABEL_NOT_YET_KNOWN, None, provenance)
    if not policy.implicit_negatives:
        return LabelDecision(target.event_id, LabelStatus.UNLABELLED, None)
    if not matured:
        return LabelDecision(target.event_id, LabelStatus.IMMATURE, None)
    return LabelDecision(target.event_id, LabelStatus.NEGATIVE_IMPLICIT, 0)


def resolve_labels(
    session: Session, targets: Sequence[LabelTarget], policy: LabelAvailabilityPolicy
) -> dict[uuid.UUID, LabelDecision]:
    """Resolve labels for many examples with a bounded number of bulk queries."""
    by_event: dict[uuid.UUID, list[FraudLabel]] = defaultdict(list)
    by_txn: dict[uuid.UUID, list[FraudLabel]] = defaultdict(list)
    for i in range(0, len(targets), 500):
        chunk = targets[i : i + 500]
        event_ids = [t.event_id for t in chunk]
        txn_ids = [t.transaction_id for t in chunk if t.transaction_id is not None]
        condition: ColumnElement[bool] = FraudLabel.event_id.in_(event_ids)
        if txn_ids:
            condition = or_(condition, FraudLabel.transaction_id.in_(txn_ids))
        for lbl in session.scalars(select(FraudLabel).where(condition)):
            if lbl.event_id is not None:
                by_event[lbl.event_id].append(lbl)
            if lbl.transaction_id is not None:
                by_txn[lbl.transaction_id].append(lbl)
    decisions: dict[uuid.UUID, LabelDecision] = {}
    for target in targets:
        found = {lbl.label_id: lbl for lbl in by_event.get(target.event_id, [])}
        if target.transaction_id is not None:
            found.update({lbl.label_id: lbl for lbl in by_txn.get(target.transaction_id, [])})
        decisions[target.event_id] = _decide(target, list(found.values()), policy)
    return decisions
