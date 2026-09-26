"""A small DSL for building point-in-time scenarios through the real ingestion path."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from fraud_ai.core.enums import EventSource, EventType
from fraud_ai.core.events import Event
from fraud_ai.features.extractor import extract_features
from fraud_ai.features.vector import FraudFeatureVector
from fraud_ai.ingestion.processor import EventProcessor

DESKTOP = {"os_family": "Windows", "client_family": "Firefox", "device_type": "desktop"}


def net(
    ip: str = "10.1.2.3",
    *,
    asn: int = 64601,
    country: str = "GB",
    network_type: str = "residential",
    **flags: Any,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ip": ip,
        "asn": asn,
        "country": country,
        "network_type": network_type,
        "is_known_vpn": False,
        "is_known_proxy": False,
        "is_tor": False,
        "is_datacenter": False,
        "is_mobile_network": network_type == "mobile",
    }
    base.update(flags)
    return base


HOME = net()
VPN = net(
    "198.51.100.7",
    asn=65001,
    country="NL",
    network_type="datacenter",
    is_known_vpn=True,
    is_datacenter=True,
    proxy_confidence=0.93,
)


class Scenario:
    def __init__(self, session: Session, processor: EventProcessor) -> None:
        self.session = session
        self.processor = processor

    def emit(
        self,
        event_type: EventType,
        at: datetime,
        user: uuid.UUID | None,
        metadata: dict[str, Any],
        *,
        device: str | None = "dev-A",
    ) -> Event:
        event = Event(
            event_type=event_type,
            timestamp=at,
            user_id=user,
            device_id=device,
            session_id="s",
            source=EventSource.API,
            metadata=metadata,
        )
        self.processor.process(event)
        return event

    def user(
        self, at: datetime, *, device: str | None = "dev-A", network: dict[str, Any] | None = None
    ) -> uuid.UUID:
        uid = uuid.uuid4()
        self.emit(
            EventType.ACCOUNT_CREATED,
            at,
            uid,
            {"external_ref": f"R-{uid.hex[:10]}", "network": network or HOME, "device": DESKTOP},
            device=device,
        )
        return uid

    def login(
        self,
        user: uuid.UUID | None,
        at: datetime,
        *,
        ok: bool = True,
        device: str | None = "dev-A",
        network: dict[str, Any] | None = None,
        mfa: bool = False,
    ) -> Event:
        meta: dict[str, Any] = {
            "auth_method": "password",
            "mfa_used": mfa,
            "network": network or HOME,
        }
        if not ok:
            meta["failure_reason"] = "bad_password"
        return self.emit(
            EventType.LOGIN_SUCCESS if ok else EventType.LOGIN_FAILURE,
            at,
            user,
            meta,
            device=device,
        )

    def address(
        self,
        user: uuid.UUID,
        at: datetime,
        *,
        text: str = "1 Test Road, Leeds",
        replaces: uuid.UUID | None = None,
        country: str = "GB",
    ) -> uuid.UUID:
        address_id = uuid.uuid4()
        meta: dict[str, Any] = {
            "address_id": str(address_id),
            "full_address": text,
            "country": country,
        }
        if replaces:
            meta["replaces_address_id"] = str(replaces)
        self.emit(
            EventType.ADDRESS_CHANGED if replaces else EventType.ADDRESS_ADDED, at, user, meta
        )
        return address_id

    def payment_method(
        self, user: uuid.UUID, at: datetime, *, issuer: str = "GB", fingerprint: str | None = None
    ) -> uuid.UUID:
        pm = uuid.uuid4()
        meta: dict[str, Any] = {
            "payment_method_id": str(pm),
            "token_reference": f"tok_{pm.hex}",
            "card_last4": "4242",
            "issuer_country": issuer,
        }
        if fingerprint:
            meta["fingerprint"] = fingerprint
        self.emit(EventType.PAYMENT_METHOD_ADDED, at, user, meta)
        return pm

    def purchase(
        self,
        user: uuid.UUID,
        at: datetime,
        amount: str,
        *,
        pm: uuid.UUID | None = None,
        address: uuid.UUID | None = None,
        decision: str | None = "approve",
        decide_after: timedelta = timedelta(seconds=2),
        currency: str = "GBP",
        device: str | None = "dev-A",
        network: dict[str, Any] | None = None,
    ) -> tuple[Event, uuid.UUID]:
        txn = uuid.uuid4()
        meta: dict[str, Any] = {
            "transaction_id": str(txn),
            "amount": amount,
            "currency": currency,
            "network": network or HOME,
        }
        if pm:
            meta["payment_method_id"] = str(pm)
        if address:
            meta["shipping_address_id"] = str(address)
        event = self.emit(EventType.TRANSACTION_CREATED, at, user, meta, device=device)
        if decision:
            self.decide(user, txn, at + decide_after, approve=decision == "approve")
        return event, txn

    def decide(
        self, user: uuid.UUID, txn: uuid.UUID, at: datetime, *, approve: bool = True
    ) -> None:
        self.emit(
            EventType.TRANSACTION_APPROVED if approve else EventType.TRANSACTION_DECLINED,
            at,
            user,
            {"transaction_id": str(txn)},
        )

    def lifecycle(self, user: uuid.UUID, at: datetime, event_type: EventType) -> None:
        self.emit(event_type, at, user, {})

    def chargeback(self, user: uuid.UUID, txn: uuid.UUID, at: datetime) -> None:
        self.emit(
            EventType.CHARGEBACK,
            at,
            user,
            {"transaction_id": str(txn), "reason_code": "10.4", "fraud_type": "account_takeover"},
        )

    def confirm_fraud(
        self,
        user: uuid.UUID,
        at: datetime,
        *,
        target: uuid.UUID | None = None,
        txn: uuid.UUID | None = None,
    ) -> None:
        meta: dict[str, Any] = {"fraud_type": "account_takeover", "label_source": "analyst"}
        if target:
            meta["target_event_id"] = str(target)
        if txn:
            meta["transaction_id"] = str(txn)
        self.emit(EventType.FRAUD_CONFIRMED, at, user, meta)

    def features(self, event: Event, as_of: datetime | None = None) -> FraudFeatureVector:
        self.session.flush()
        return extract_features(self.session, event.event_id, as_of)
