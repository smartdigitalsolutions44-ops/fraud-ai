"""The internal manual-review queue (no UI; the CLI is the interface).

* An entry is created with the assessment, for every ``MANUAL_REVIEW`` and
  ``TEMPORARY_BLOCK`` decision.
* Priority runs from 1 (most urgent) to 5. A temporary block is 1, a fallback or a
  high/extreme risk level is 2, and other reviews are 3.
* :func:`resolve` appends an outcome (``legitimate``, ``fraud`` or
  ``needs_more_information``) and updates the queue entry's status. It **never** changes
  the risk assessment: the original decision stays exactly as issued.
* Notes are short, and they are refused if they contain personal data or secrets
  (emails, IPs, card numbers, tokens, phone numbers, street addresses).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import ReviewResolution, ReviewStatus
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import ReviewItem, ReviewOutcome, RiskAssessment
from fraud_ai.security.pii import text_violations


class ReviewError(FraudAIError):
    pass


@dataclass(frozen=True)
class ReviewDetail:
    item: ReviewItem
    assessment: RiskAssessment
    outcomes: list[ReviewOutcome]


def list_reviews(
    session: Session, *, status: ReviewStatus | None = ReviewStatus.OPEN, limit: int = 50
) -> list[ReviewItem]:
    stmt = select(ReviewItem)
    if status is not None:
        stmt = stmt.where(ReviewItem.status == status)
    stmt = stmt.order_by(ReviewItem.priority, ReviewItem.created_at, ReviewItem.review_id)
    return list(session.scalars(stmt.limit(limit)))


def queue_size(session: Session) -> dict[str, int]:
    rows = session.execute(select(ReviewItem.status, func.count()).group_by(ReviewItem.status))
    counts = {s.value: 0 for s in ReviewStatus}
    counts.update({str(getattr(status, "value", status)): int(n) for status, n in rows})
    return counts


def get_review(session: Session, review_id: uuid.UUID) -> ReviewDetail:
    item = session.get(ReviewItem, review_id)
    if item is None:
        raise ReviewError(f"no review item {review_id}")
    assessment = session.get(RiskAssessment, item.assessment_id)
    assert assessment is not None
    outcomes = list(
        session.scalars(
            select(ReviewOutcome)
            .where(ReviewOutcome.review_id == review_id)
            .order_by(ReviewOutcome.created_at)
        )
    )
    return ReviewDetail(item, assessment, outcomes)


def resolve(
    session: Session,
    review_id: uuid.UUID,
    resolution: ReviewResolution,
    *,
    note: str | None = None,
    now: datetime | None = None,
    reviewer: str | None = None,
) -> ReviewOutcome:
    item = session.get(ReviewItem, review_id)
    if item is None:
        raise ReviewError(f"no review item {review_id}")
    if item.status is ReviewStatus.RESOLVED:
        raise ReviewError(
            f"review {review_id} is already resolved ({item.outcome}); outcomes are not rewritten"
        )
    if note is not None:
        note = note.strip()
        if len(note) > 500:
            raise ReviewError("notes are limited to 500 characters")
        problems = [v for v in text_violations(note, free_text_allowed=True) if v]
        if problems:
            raise ReviewError(
                f"the note looks like it contains {', '.join(sorted(set(problems)))}; "
                "notes must not hold personal data or secrets"
            )
    when = now or datetime.now(UTC)
    outcome = ReviewOutcome(
        review_id=review_id,
        resolution=resolution,
        note=note or None,
        created_at=when,
        reviewer=reviewer[:120] if reviewer else None,
    )
    session.add(outcome)
    item.outcome = resolution
    item.reviewed_at = when
    item.status = (
        ReviewStatus.NEEDS_MORE_INFORMATION
        if resolution is ReviewResolution.NEEDS_MORE_INFORMATION
        else ReviewStatus.RESOLVED
    )
    session.flush()
    return outcome
