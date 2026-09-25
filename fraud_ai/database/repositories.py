"""Small, reusable persistence helpers shared by services and the CLI."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import FraudType, LabelSource, LabelValue
from fraud_ai.database.base import Base
from fraud_ai.database.models import FraudLabel
from fraud_ai.utils.time import ensure_utc


def record_label(
    session: Session,
    *,
    user_id: uuid.UUID,
    label: LabelValue,
    label_source: LabelSource,
    labelled_at: datetime,
    transaction_id: uuid.UUID | None = None,
    event_id: uuid.UUID | None = None,
    source_event_id: uuid.UUID | None = None,
    fraud_type: FraudType | None = None,
    confidence: float = 1.0,
    notes: str | None = None,
) -> FraudLabel:
    if label is LabelValue.FRAUD and fraud_type is None:
        raise ValueError("a FRAUD label requires fraud_type")
    if label is LabelValue.LEGITIMATE and fraud_type is not None:
        raise ValueError("a LEGITIMATE label must not have a fraud_type")
    row = FraudLabel(
        user_id=user_id,
        transaction_id=transaction_id,
        event_id=event_id,
        source_event_id=source_event_id,
        label=label,
        fraud_type=fraud_type,
        label_source=label_source,
        confidence=confidence,
        labelled_at=ensure_utc(labelled_at),
        notes=notes,
    )
    session.add(row)
    return row


def table_row_counts(session: Session) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name, table in sorted(Base.metadata.tables.items()):
        counts[name] = int(session.execute(select(func.count()).select_from(table)).scalar_one())
    return counts
