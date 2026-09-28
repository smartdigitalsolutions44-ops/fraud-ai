"""Seed a database with synthetic data through the real ingestion pipeline."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import EventType, LabelSource, LabelValue
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


#: Event types whose delivery may be delayed in a held-out live stream. Transactions are
#: never delayed: their approval/decline events depend on them.
LATE_CAPABLE = frozenset(
    {
        EventType.LOGIN_SUCCESS,
        EventType.LOGIN_FAILURE,
        EventType.PASSWORD_RESET,
        EventType.EMAIL_VERIFIED,
        EventType.PHONE_VERIFIED,
    }
)


@dataclass(frozen=True)
class LiveHoldout:
    history: SeedSummary
    cutoff: datetime
    events: list[dict[str, Any]]  # contract dicts, sorted by arrival_time
    late_events: int


def seed_with_live_holdout(
    session: Session,
    pseudonymiser: Pseudonymiser,
    *,
    n_users: int,
    seed: int,
    reference_time: datetime,
    activity_days: int = 90,
    live_days: int = 7,
    fraud_multiplier: float = 1.0,
    late_fraction: float = 0.02,
    max_late_hours: float = 6.0,
    store_raw_ip: bool = False,
) -> LiveHoldout:
    """Ingest the synthetic stream up to ``reference_time - live_days`` as history and
    return the rest as a *live* stream for real-time replay.

    * History transactions without a fraud outcome are labelled legitimate as of the
      cutoff (known only then, which avoids leakage).
    * Each live event carries an ``arrival_time``. It equals the event time, except for a
      deterministic ``late_fraction`` of late-capable events, which arrive up to
      ``max_late_hours`` late. That exercises late-arrival handling.

    Everything is synthetic.
    """
    if not 0 < live_days < activity_days:
        raise SeedError("live_days must be positive and shorter than activity_days")
    if not 0.0 <= late_fraction <= 1.0:
        raise SeedError("late_fraction must be in [0, 1]")
    existing = session.scalar(
        select(func.count()).select_from(User).where(User.synthetic_scenario.is_not(None))
    )
    if existing:
        raise SeedError(
            f"database already contains {existing} synthetic users; use a fresh database"
        )
    started = time.monotonic()
    dataset = SyntheticDataGenerator(
        seed=seed,
        reference_time=reference_time,
        activity_days=activity_days,
        fraud_multiplier=fraud_multiplier,
    ).generate(n_users)
    cutoff = reference_time - timedelta(days=live_days)
    processor = EventProcessor(session, pseudonymiser, store_raw_ip=store_raw_ip)
    history = [e for e in dataset.events if e.timestamp < cutoff]
    for event in history:
        processor.process(event, atomic=False)
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
            labelled_at=cutoff,
        )
        legit += 1
    session.flush()
    rng = random.Random(seed + 7919)  # nosec B311 # noqa: S311 - deterministic simulation, not security
    live: list[tuple[datetime, int, dict[str, Any]]] = []
    late = 0
    for i, event in enumerate(e for e in dataset.events if e.timestamp >= cutoff):
        arrival = event.timestamp
        if event.event_type in LATE_CAPABLE and rng.random() < late_fraction:
            arrival = event.timestamp + timedelta(hours=rng.uniform(0.25, max_late_hours))
            late += 1
        payload = event.model_dump(mode="json")
        payload["arrival_time"] = arrival.isoformat()
        live.append((arrival, i, payload))
    live.sort(key=lambda x: (x[0], x[1]))
    fraud = int(
        session.scalar(
            select(func.count()).select_from(FraudLabel).where(FraudLabel.label == LabelValue.FRAUD)
        )
        or 0
    )
    summary = SeedSummary(
        users=n_users,
        events=len(history),
        transactions=int(session.scalar(select(func.count()).select_from(Transaction)) or 0),
        fraud_labels=fraud,
        legitimate_labels=legit,
        scenario_counts=dataset.scenario_counts,
        elapsed_seconds=round(time.monotonic() - started, 2),
    )
    return LiveHoldout(summary, cutoff, [p for _, _, p in live], late)
