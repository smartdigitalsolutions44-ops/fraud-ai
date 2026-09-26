"""Scoring context: the scored event and its directly attached, immutable attributes.

Contexts are loaded in bulk (a fixed number of ``IN (...)`` queries per chunk of events),
so batch extraction does not issue per-event lookups for the event, its login/transaction
row, its network observation, address or payment method.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import EventType, LoginOutcome, NetworkType
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import (
    Address,
    EventRecord,
    LoginEvent,
    NetworkEvent,
    PaymentMethod,
    Transaction,
    User,
)
from fraud_ai.features.definitions import EventKind
from fraud_ai.utils.time import ensure_utc

LOGIN_EVENT_TYPES = frozenset(
    {EventType.LOGIN_ATTEMPT, EventType.LOGIN_SUCCESS, EventType.LOGIN_FAILURE}
)
SCORABLE_EVENT_TYPES = LOGIN_EVENT_TYPES | {EventType.TRANSACTION_CREATED}
_CHUNK = 500


class FeatureExtractionError(FraudAIError):
    pass


class UnsupportedEventError(FeatureExtractionError):
    pass


@dataclass(frozen=True)
class NetworkObservation:
    network_identity_id: uuid.UUID
    asn: int | None
    country: str | None
    network_type: NetworkType
    is_known_vpn: bool | None
    is_known_proxy: bool | None
    is_tor: bool | None
    is_datacenter: bool | None
    is_mobile_network: bool | None
    proxy_confidence: float | None


@dataclass(frozen=True)
class LoginInfo:
    login_event_id: uuid.UUID
    outcome: LoginOutcome
    mfa_used: bool


@dataclass(frozen=True)
class TransactionInfo:
    transaction_id: uuid.UUID
    amount_minor: int
    currency: str
    payment_method_id: uuid.UUID | None
    shipping_address_id: uuid.UUID | None


@dataclass(frozen=True)
class AddressInfo:
    address_id: uuid.UUID
    address_hash: str
    added_at: datetime
    verified_at: datetime | None


@dataclass(frozen=True)
class PaymentMethodInfo:
    payment_method_id: uuid.UUID
    added_at: datetime
    verified_at: datetime | None
    issuer_country: str | None
    fingerprint_hash: str | None


@dataclass(frozen=True)
class ScoringContext:
    event_id: uuid.UUID
    event_type: EventType
    kind: EventKind
    event_time: datetime
    as_of: datetime
    user_id: uuid.UUID | None
    account_created_at: datetime | None
    device_id: uuid.UUID | None
    network: NetworkObservation | None
    login: LoginInfo | None
    transaction: TransactionInfo | None
    address: AddressInfo | None
    payment_method: PaymentMethodInfo | None


def _chunks(items: Sequence[uuid.UUID]) -> Iterable[Sequence[uuid.UUID]]:
    for i in range(0, len(items), _CHUNK):
        yield items[i : i + _CHUNK]


def load_contexts(
    session: Session,
    event_ids: Sequence[uuid.UUID],
    as_of: dict[uuid.UUID, datetime] | None = None,
) -> dict[uuid.UUID, ScoringContext]:
    """Load scoring contexts for ``event_ids``; ``as_of`` defaults to each event's time."""
    result: dict[uuid.UUID, ScoringContext] = {}
    for chunk in _chunks(list(dict.fromkeys(event_ids))):
        result.update(_load_chunk(session, chunk, as_of or {}))
    missing = set(event_ids) - set(result)
    if missing:
        raise FeatureExtractionError(f"unknown event(s): {sorted(map(str, missing))[:5]}")
    return result


def _load_chunk(
    session: Session, ids: Sequence[uuid.UUID], as_of: dict[uuid.UUID, datetime]
) -> dict[uuid.UUID, ScoringContext]:
    rows = session.execute(
        select(EventRecord, User.account_created_at)
        .outerjoin(User, User.user_id == EventRecord.user_id)
        .where(EventRecord.event_id.in_(ids))
    ).all()
    logins = {
        r.event_id: r
        for r in session.scalars(select(LoginEvent).where(LoginEvent.event_id.in_(ids)))
    }
    txns = {
        r.event_id: r
        for r in session.scalars(select(Transaction).where(Transaction.event_id.in_(ids)))
    }
    nets = {
        r.event_id: r
        for r in session.scalars(select(NetworkEvent).where(NetworkEvent.event_id.in_(ids)))
    }
    address_ids = [t.shipping_address_id for t in txns.values() if t.shipping_address_id]
    pm_ids = [t.payment_method_id for t in txns.values() if t.payment_method_id]
    addresses = (
        {
            a.address_id: a
            for a in session.scalars(select(Address).where(Address.address_id.in_(address_ids)))
        }
        if address_ids
        else {}
    )
    pms = (
        {
            p.payment_method_id: p
            for p in session.scalars(
                select(PaymentMethod).where(PaymentMethod.payment_method_id.in_(pm_ids))
            )
        }
        if pm_ids
        else {}
    )

    out: dict[uuid.UUID, ScoringContext] = {}
    for record, created_at in rows:
        if record.event_type not in SCORABLE_EVENT_TYPES:
            raise UnsupportedEventError(
                f"event {record.event_id} is {record.event_type}; features are computed for "
                "login and TRANSACTION_CREATED events"
            )
        event_time = ensure_utc(record.occurred_at)
        point = ensure_utc(as_of.get(record.event_id, event_time))
        if point < event_time:
            raise FeatureExtractionError(
                f"as_of {point.isoformat()} precedes event {record.event_id} "
                f"({event_time.isoformat()}): the event did not exist yet"
            )
        login = logins.get(record.event_id)
        txn = txns.get(record.event_id)
        net = nets.get(record.event_id)
        address = (
            addresses.get(txn.shipping_address_id) if txn and txn.shipping_address_id else None
        )
        pm = pms.get(txn.payment_method_id) if txn and txn.payment_method_id else None
        kind = EventKind.TRANSACTION if txn is not None else EventKind.LOGIN
        if kind is EventKind.LOGIN and login is None:
            raise FeatureExtractionError(f"login row missing for event {record.event_id}")
        out[record.event_id] = ScoringContext(
            event_id=record.event_id,
            event_type=record.event_type,
            kind=kind,
            event_time=event_time,
            as_of=point,
            user_id=record.user_id,
            account_created_at=created_at,
            device_id=record.device_id,
            network=(
                NetworkObservation(
                    network_identity_id=net.network_identity_id,
                    asn=net.asn,
                    country=net.country,
                    network_type=net.network_type,
                    is_known_vpn=net.is_known_vpn,
                    is_known_proxy=net.is_known_proxy,
                    is_tor=net.is_tor,
                    is_datacenter=net.is_datacenter,
                    is_mobile_network=net.is_mobile_network,
                    proxy_confidence=net.proxy_confidence,
                )
                if net is not None
                else None
            ),
            login=(
                LoginInfo(login.login_event_id, login.outcome, login.mfa_used)
                if login is not None
                else None
            ),
            transaction=(
                TransactionInfo(
                    transaction_id=txn.transaction_id,
                    amount_minor=txn.amount_minor,
                    currency=txn.currency,
                    payment_method_id=txn.payment_method_id,
                    shipping_address_id=txn.shipping_address_id,
                )
                if txn is not None
                else None
            ),
            address=(
                AddressInfo(
                    address.address_id, address.address_hash, address.added_at, address.verified_at
                )
                if address is not None
                else None
            ),
            payment_method=(
                PaymentMethodInfo(
                    pm.payment_method_id,
                    pm.added_at,
                    pm.verified_at,
                    pm.issuer_country,
                    pm.fingerprint_hash,
                )
                if pm is not None
                else None
            ),
        )
    return out
