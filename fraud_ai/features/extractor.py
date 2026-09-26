"""Feature extraction API.

    extract_features(session, event_id, as_of_timestamp=None, feature_version=None)
        -> FraudFeatureVector

``as_of_timestamp`` defaults to the event's own timestamp - the only choice that is valid
for training data. A later ``as_of`` produces a retrospective vector (history up to that
moment, still excluding the event itself); an earlier one is rejected.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from datetime import datetime

from sqlalchemy.orm import Session

from fraud_ai.features import (
    account,
    address,
    behavioural,
    cross_entity,
    device,
    login,
    network,
    payment,
    security,
    transaction,
)
from fraud_ai.features._common import NA
from fraud_ai.features.context import FeatureExtractionError, ScoringContext, load_contexts
from fraud_ai.features.definitions import (
    DEFAULT_FEATURE_VERSION,
    FEATURE_VERSION_1_0_0,
    EventKind,
    get_feature_set,
)
from fraud_ai.features.history import History
from fraud_ai.features.vector import FeatureWriter, FraudFeatureVector
from fraud_ai.utils.time import ensure_utc

Computer = Callable[[History, FeatureWriter], None]


def _context_features(h: History, w: FeatureWriter) -> None:
    ctx = h.ctx
    w.put("event_kind", ctx.kind.value)
    if ctx.kind is EventKind.LOGIN and ctx.login is not None:
        w.put("login_outcome", ctx.login.outcome.value.lower())
    else:
        w.miss("login_outcome", NA)
    w.put("authenticated_user", ctx.user_id is not None)


# Each released feature version maps to a frozen pipeline. A new version gets a new entry;
# existing entries are never edited in a way that changes their output.
PIPELINES: dict[str, tuple[Computer, ...]] = {
    FEATURE_VERSION_1_0_0: (
        _context_features,
        account.compute,
        device.compute,
        network.compute,
        address.compute,
        payment.compute,
        transaction.compute,
        login.compute,
        security.compute,
        behavioural.compute,
        cross_entity.compute,
    ),
}


def compute_vector(
    session: Session, ctx: ScoringContext, feature_version: str
) -> FraudFeatureVector:
    get_feature_set(feature_version)  # raises for unknown versions
    pipeline = PIPELINES.get(feature_version)
    if pipeline is None:
        raise FeatureExtractionError(f"no extraction pipeline for {feature_version}")
    history = History(session, ctx)
    writer = FeatureWriter(feature_version)
    for step in pipeline:
        step(history, writer)
    if unassigned := writer.unassigned():
        raise FeatureExtractionError(f"features not computed: {sorted(unassigned)}")
    return FraudFeatureVector(
        feature_version=feature_version,
        event_id=ctx.event_id,
        event_kind=ctx.kind,
        event_timestamp=ctx.event_time,
        as_of_timestamp=ctx.as_of,
        user_id=ctx.user_id,
        transaction_id=ctx.transaction.transaction_id if ctx.transaction else None,
        login_event_id=ctx.login.login_event_id if ctx.login else None,
        source_event_count=history.source_event_count,
        values=writer.values,
        missing=writer.missing,
    )


def extract_features(
    session: Session,
    event_id: uuid.UUID,
    as_of_timestamp: datetime | None = None,
    feature_version: str | None = None,
) -> FraudFeatureVector:
    as_of = {event_id: ensure_utc(as_of_timestamp)} if as_of_timestamp else None
    ctx = load_contexts(session, [event_id], as_of)[event_id]
    return compute_vector(session, ctx, feature_version or DEFAULT_FEATURE_VERSION)


def extract_many(
    session: Session, event_ids: Sequence[uuid.UUID], feature_version: str | None = None
) -> list[FraudFeatureVector]:
    """Vectors for ``event_ids`` (each as of its own timestamp), in the given order."""
    version = feature_version or DEFAULT_FEATURE_VERSION
    contexts = load_contexts(session, event_ids)
    return [compute_vector(session, contexts[e], version) for e in event_ids]
