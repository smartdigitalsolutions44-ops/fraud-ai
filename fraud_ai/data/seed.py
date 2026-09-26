"""Seed a database with synthetic data through the real ingestion pipeline."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import LabelSource, LabelValue
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.data.synthetic import SyntheticDataGenerator
from fraud_ai.database.models import FraudLabel, Transaction, User
from fraud_ai.database.repositories import record_label
from fraud_ai.ingestion.processor import EventProcessor
from fraud_ai.security.hashing import Pseudonymiser
from fraud_ai.utils.logging import get_logger

log = get_logger(__name__)


class SeedError(FraudAIError):
    pass


@dataclass(frozen=True)
class SeedSummary:
    users: int
    events: int
    transactions: int
    fraud_labels: int
    legitimate_labels: int
    scenario_counts: dict[str, int]
    elapsed_seconds: float


def seed_synthetic_data(
    session: Session,
    pseudonymiser: Pseudonymiser,
    *,
    n_users: int,
    seed: int,
    reference_time: datetime,
    activity_days: int = 90,
    store_raw_ip: bool = False,
    fraud_multiplier: float = 1.0,
) -> SeedSummary:
    """Generate and ingest synthetic data. The caller owns the transaction."""
    existing = session.scalar(
        select(func.count()).select_from(User).where(User.synthetic_scenario.is_not(None))
    )
    if existing:
        raise SeedError(
            f"database already contains {existing} synthetic users; use a fresh database"
        )
    started = time.monotonic()
    log.info("generating synthetic data: users=%d seed=%d days=%d", n_users, seed, activity_days)
    dataset = SyntheticDataGenerator(
        seed=seed,
        reference_time=reference_time,
        activity_days=activity_days,
        fraud_multiplier=fraud_multiplier,
    ).generate(n_users)

    processor = EventProcessor(session, pseudonymiser, store_raw_ip=store_raw_ip)
    for event in dataset.events:
        processor.process(event, atomic=False)  # one transaction for the whole seed

    # Ground truth for every synthetic transaction without a fraud label. Known only at the
    # end of the observation window (labelled_at = reference time) to avoid leakage.
    fraud_labelled = set(
        session.scalars(
            select(FraudLabel.transaction_id).where(FraudLabel.transaction_id.is_not(None))
        )
    )
    legit = 0
    for txn in session.scalars(
        select(Transaction).join(User).where(User.synthetic_scenario.is_not(None))
    ):
        if (
            txn.transaction_id in fraud_labelled
            or txn.transaction_id in dataset.fraud_transaction_ids
        ):
            continue
        record_label(
            session,
            user_id=txn.user_id,
            transaction_id=txn.transaction_id,
            event_id=txn.event_id,
            label=LabelValue.LEGITIMATE,
            label_source=LabelSource.SYNTHETIC_GROUND_TRUTH,
            labelled_at=reference_time,
        )
        legit += 1
    session.flush()

    fraud = int(
        session.scalar(
            select(func.count()).select_from(FraudLabel).where(FraudLabel.label == LabelValue.FRAUD)
        )
        or 0
    )
    txns = int(session.scalar(select(func.count()).select_from(Transaction)) or 0)
    summary = SeedSummary(
        users=n_users,
        events=len(dataset.events),
        transactions=txns,
        fraud_labels=fraud,
        legitimate_labels=legit,
        scenario_counts=dataset.scenario_counts,
        elapsed_seconds=round(time.monotonic() - started, 2),
    )
    log.info("seed complete: %s", summary)
    return summary
