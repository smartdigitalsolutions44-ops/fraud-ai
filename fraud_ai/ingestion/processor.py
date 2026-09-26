"""The event processor: the single write path from an :class:`Event` into the fraud database.

For each event it:

1. rejects duplicates (idempotent on ``event_id``),
2. resolves/creates the device and network identity (pseudonymised, with history),
3. appends a sanitised copy of the event to the ``events`` log,
4. applies the event to the domain tables (logins, addresses, payment methods,
   transactions, security events, labels),
5. records network-intelligence evidence as ``fraud_signals``.

Each event is applied inside a SAVEPOINT, so a rejected event never leaves partial state.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import (
    EventType,
    LabelSource,
    LabelValue,
    LoginOutcome,
    SecurityEventType,
    SignalSource,
    TransactionDecision,
    TransactionStatus,
)
from fraud_ai.core.events import (
    AccountCreatedPayload,
    AddressPayload,
    AddressVerifiedPayload,
    ChargebackPayload,
    DeviceContext,
    Event,
    FraudConfirmedPayload,
    LoginPayload,
    NetworkContext,
    PaymentMethodAddedPayload,
    PaymentMethodVerifiedPayload,
    TransactionCreatedPayload,
    TransactionDecisionPayload,
)
from fraud_ai.core.exceptions import EventProcessingError
from fraud_ai.database.models import (
    Address,
    Device,
    EventRecord,
    FraudSignal,
    LoginEvent,
    NetworkEvent,
    NetworkIdentity,
    PaymentMethod,
    SecurityEvent,
    Transaction,
    User,
    UserDevice,
)
from fraud_ai.database.repositories import record_label
from fraud_ai.security.hashing import Pseudonymiser
from fraud_ai.security.redaction import redact_mapping
from fraud_ai.utils.logging import get_logger

log = get_logger(__name__)

_LOGIN_OUTCOMES = {
    EventType.LOGIN_ATTEMPT: LoginOutcome.ATTEMPT,
    EventType.LOGIN_SUCCESS: LoginOutcome.SUCCESS,
    EventType.LOGIN_FAILURE: LoginOutcome.FAILURE,
}
_DEVICE_REQUIRED = frozenset({EventType.NEW_DEVICE})


@dataclass(frozen=True)
class ProcessResult:
    event_id: uuid.UUID
    event_type: EventType
    duplicate: bool = False


@dataclass
class _Context:
    event: Event
    payload: Any
    user: User | None
    device: Device | None
    network: NetworkIdentity | None
    record: EventRecord


class EventProcessor:
    def __init__(
        self, session: Session, pseudonymiser: Pseudonymiser, *, store_raw_ip: bool = False
    ) -> None:
        self._session = session
        self._pseudo = pseudonymiser
        self._store_raw_ip = store_raw_ip
        # Per-processor lookup caches (the session identity map handles primary keys).
        self._devices: dict[str, Device] = {}
        self._networks: dict[str, NetworkIdentity] = {}
        self._ip_users: set[tuple[uuid.UUID, uuid.UUID]] = set()

    # ------------------------------------------------------------------ public API
    def process(self, event: Event, *, atomic: bool = True) -> ProcessResult:
        """Apply one event.

        ``atomic=True`` wraps the event in a SAVEPOINT so a failure leaves no partial state
        and the surrounding transaction stays usable. Bulk loaders that roll back the
        whole batch on any failure may pass ``atomic=False`` for throughput.
        """
        if self._session.get(EventRecord, event.event_id) is not None:
            log.info("duplicate event ignored: %s", event.event_id)
            return ProcessResult(event.event_id, event.event_type, duplicate=True)
        if not atomic:
            self._apply(event)
            return ProcessResult(event.event_id, event.event_type)
        savepoint = self._session.begin_nested()
        try:
            self._apply(event)
            savepoint.commit()
        except Exception:
            savepoint.rollback()
            # Caches may reference rolled-back objects.
            self._devices.clear()
            self._networks.clear()
            self._ip_users.clear()
            raise
        return ProcessResult(event.event_id, event.event_type)

    # ------------------------------------------------------------------ pipeline
    def _apply(self, event: Event) -> None:
        payload = event.payload()
        user = self._resolve_user(event, payload)
        if event.event_type in _DEVICE_REQUIRED and event.device_id is None:
            raise EventProcessingError(f"{event.event_type} requires device_id")
        device_ctx: DeviceContext | None = getattr(payload, "device", None)
        device = self._resolve_device(event, device_ctx, user)
        network_ctx: NetworkContext | None = getattr(payload, "network", None)
        network = self._resolve_network(network_ctx, event.timestamp) if network_ctx else None
        if self._session.new:
            self._session.flush()  # entities must exist before the event row references them

        record = EventRecord(
            event_id=event.event_id,
            event_type=event.event_type,
            occurred_at=event.timestamp,
            user_id=user.user_id if user else None,
            session_id=event.session_id,
            device_id=device.device_id if device else None,
            source=event.source,
            metadata_json=self._sanitise(payload),
            schema_version=event.schema_version,
        )
        self._session.add(record)
        self._session.flush()
        ctx = _Context(event, payload, user, device, network, record)

        if network is not None and network_ctx is not None:
            self._record_network_observation(ctx, network_ctx)

        handler = _HANDLERS.get(event.event_type)
        if handler is not None:
            handler(self, ctx)

    def _resolve_user(self, event: Event, payload: Any) -> User | None:
        if event.event_type is EventType.ACCOUNT_CREATED:
            assert isinstance(payload, AccountCreatedPayload) and event.user_id is not None
            if self._session.get(User, event.user_id) is not None:
                raise EventProcessingError(f"user {event.user_id} already exists")
            user = User(
                user_id=event.user_id,
                external_ref=payload.external_ref,
                account_created_at=event.timestamp,
                home_country=payload.home_country,
                synthetic_scenario=payload.synthetic_scenario,
            )
            self._session.add(user)
            return user
        if event.user_id is None:
            return None
        existing = self._session.get(User, event.user_id)
        if existing is None:
            raise EventProcessingError(f"unknown user {event.user_id}")
        return existing

    def _resolve_device(
        self, event: Event, ctx: DeviceContext | None, user: User | None
    ) -> Device | None:
        if event.device_id is None:
            return None
        ts = event.timestamp
        device_hash = self._pseudo.hash_device(event.device_id)
        device = self._devices.get(device_hash) or self._session.scalar(
            select(Device).where(Device.device_hash == device_hash)
        )
        if device is None:
            device = Device(
                device_id=uuid.uuid4(),
                device_hash=device_hash,
                first_seen_at=ts,
                last_seen_at=ts,
                successful_logins=0,
                failed_logins=0,
            )
            self._session.add(device)
        else:
            device.first_seen_at = min(device.first_seen_at, ts)
            device.last_seen_at = max(device.last_seen_at, ts)
        if ctx is not None:
            device.os_family = ctx.os_family or device.os_family
            device.client_family = ctx.client_family or device.client_family
            device.device_type = ctx.device_type
        self._devices[device_hash] = device

        if user is not None:
            link = self._session.get(UserDevice, (user.user_id, device.device_id))
            if link is None:
                link = UserDevice(
                    user_id=user.user_id,
                    device_id=device.device_id,
                    first_seen_at=ts,
                    last_seen_at=ts,
                    is_trusted=False,
                    successful_logins=0,
                    failed_logins=0,
                )
                self._session.add(link)
            else:
                link.first_seen_at = min(link.first_seen_at, ts)
                link.last_seen_at = max(link.last_seen_at, ts)
        return device

    def _resolve_network(self, ctx: NetworkContext, ts: datetime) -> NetworkIdentity:
        ip_hash = self._pseudo.hash_ip(ctx.ip)
        identity = self._networks.get(ip_hash) or self._session.scalar(
            select(NetworkIdentity).where(NetworkIdentity.ip_hash == ip_hash)
        )
        if identity is None:
            identity = NetworkIdentity(
                network_identity_id=uuid.uuid4(),
                ip_hash=ip_hash,
                ip_version=6 if ":" in ctx.ip else 4,
                first_seen_at=ts,
                last_seen_at=ts,
                distinct_user_count=0,
                failed_login_count=0,
                successful_login_count=0,
            )
            self._session.add(identity)
        else:
            identity.first_seen_at = min(identity.first_seen_at, ts)
            identity.last_seen_at = max(identity.last_seen_at, ts)
        if self._store_raw_ip:
            identity.ip_address = ctx.ip
        # Latest intelligence wins; the per-event snapshot keeps the history.
        identity.asn = ctx.asn
        identity.asn_org = ctx.asn_org
        identity.country = ctx.country
        identity.region = ctx.region
        identity.network_type = ctx.network_type
        identity.is_mobile_network = ctx.is_mobile_network
        identity.is_datacenter = ctx.is_datacenter
        identity.is_known_proxy = ctx.is_known_proxy
        identity.is_known_vpn = ctx.is_known_vpn
        identity.is_tor = ctx.is_tor
        identity.proxy_confidence = ctx.proxy_confidence
        identity.intel_source = ctx.intel_source
        identity.intel_updated_at = ts
        self._networks[ip_hash] = identity
        return identity

    def _record_network_observation(self, ctx: _Context, net: NetworkContext) -> None:
        identity = ctx.network
        assert identity is not None
        user_id = ctx.user.user_id if ctx.user else None
        if user_id is not None:
            key = (identity.network_identity_id, user_id)
            if key not in self._ip_users:
                seen = self._session.scalar(
                    select(
                        exists().where(
                            NetworkEvent.network_identity_id == identity.network_identity_id,
                            NetworkEvent.user_id == user_id,
                        )
                    )
                )
                if not seen:
                    identity.distinct_user_count += 1
                self._ip_users.add(key)
        self._session.add(
            NetworkEvent(
                event_id=ctx.event.event_id,
                network_identity_id=identity.network_identity_id,
                user_id=user_id,
                device_id=ctx.device.device_id if ctx.device else None,
                observed_at=ctx.event.timestamp,
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
        )
        # Network intelligence is evidence, never proof: store it as a signal.
        flags = {
            "vpn_detected": net.is_known_vpn,
            "proxy_detected": net.is_known_proxy,
            "tor_detected": net.is_tor,
            "datacenter_network": net.is_datacenter,
        }
        for name, flag in flags.items():
            if flag:
                self._session.add(
                    FraudSignal(
                        event_id=ctx.event.event_id,
                        user_id=user_id,
                        signal_name=name,
                        signal_source=SignalSource.NETWORK_INTEL,
                        value=net.proxy_confidence if net.proxy_confidence is not None else 1.0,
                        details={"intel_source": net.intel_source},
                        observed_at=ctx.event.timestamp,
                    )
                )

    def _sanitise(self, payload: Any) -> dict[str, Any]:
        """Produce the metadata stored in the event log: no raw IP, device ID or address."""
        data: dict[str, Any] = payload.model_dump(mode="json", exclude_none=True)
        network = data.get("network")
        if isinstance(network, dict) and "ip" in network:
            network["ip_hash"] = self._pseudo.hash_ip(network.pop("ip"))
        if "full_address" in data:
            data["address_hash"] = self._pseudo.hash_address(data.pop("full_address"))
        if "fingerprint" in data:
            data["fingerprint_hash"] = self._pseudo.hash_payment_fingerprint(
                data.pop("fingerprint")
            )
        return redact_mapping(data)

    # ------------------------------------------------------------------ handlers
    def _require_user(self, ctx: _Context) -> User:
        if ctx.user is None:
            raise EventProcessingError(f"{ctx.event.event_type} requires a known user")
        return ctx.user

    def _security_event(self, ctx: _Context, kind: SecurityEventType, **details: Any) -> None:
        user = self._require_user(ctx)
        self._session.add(
            SecurityEvent(
                event_id=ctx.event.event_id,
                user_id=user.user_id,
                device_id=ctx.device.device_id if ctx.device else None,
                network_identity_id=ctx.network.network_identity_id if ctx.network else None,
                security_event_type=kind,
                occurred_at=ctx.event.timestamp,
                details=redact_mapping(details),
            )
        )

    def _on_login(self, ctx: _Context) -> None:
        payload: LoginPayload = ctx.payload
        outcome = _LOGIN_OUTCOMES[ctx.event.event_type]
        self._session.add(
            LoginEvent(
                event_id=ctx.event.event_id,
                user_id=ctx.user.user_id if ctx.user else None,
                device_id=ctx.device.device_id if ctx.device else None,
                network_identity_id=ctx.network.network_identity_id if ctx.network else None,
                session_id=ctx.event.session_id,
                occurred_at=ctx.event.timestamp,
                outcome=outcome,
                auth_method=payload.auth_method,
                mfa_used=payload.mfa_used,
                failure_reason=payload.failure_reason,
            )
        )
        if outcome is LoginOutcome.ATTEMPT:
            return
        success = outcome is LoginOutcome.SUCCESS
        link = (
            self._session.get(UserDevice, (ctx.user.user_id, ctx.device.device_id))
            if ctx.user and ctx.device
            else None
        )
        if ctx.device is not None:
            if success:
                ctx.device.successful_logins += 1
            else:
                ctx.device.failed_logins += 1
        if link is not None:
            if success:
                link.successful_logins += 1
                # Application trust policy: a device becomes trusted for a user after a
                # successful login that completed multi-factor authentication.
                if payload.mfa_used:
                    link.is_trusted = True
            else:
                link.failed_logins += 1
        if ctx.network is not None:
            if success:
                ctx.network.successful_login_count += 1
            else:
                ctx.network.failed_login_count += 1

    def _on_password_reset(self, ctx: _Context) -> None:
        self._security_event(ctx, SecurityEventType.PASSWORD_RESET, method=ctx.payload.method)

    def _on_new_device(self, ctx: _Context) -> None:
        self._security_event(ctx, SecurityEventType.NEW_DEVICE)

    def _on_address(self, ctx: _Context) -> None:
        user = self._require_user(ctx)
        payload: AddressPayload = ctx.payload
        if self._session.get(Address, payload.address_id) is not None:
            raise EventProcessingError(f"address {payload.address_id} already exists")
        replaced: Address | None = None
        if ctx.event.event_type is EventType.ADDRESS_CHANGED:
            if payload.replaces_address_id is None:
                raise EventProcessingError("ADDRESS_CHANGED requires replaces_address_id")
            replaced = self._session.get(Address, payload.replaces_address_id)
            if replaced is None or replaced.user_id != user.user_id:
                raise EventProcessingError("replaced address not found for this user")
            replaced.is_active = False
            replaced.superseded_at = ctx.event.timestamp
        self._session.add(
            Address(
                address_id=payload.address_id,
                user_id=user.user_id,
                address_hash=self._pseudo.hash_address(payload.full_address),
                address_type=payload.address_type,
                country=payload.country.upper(),
                region=payload.region,
                postal_prefix=payload.postal_prefix,
                added_at=ctx.event.timestamp,
                is_active=True,
                replaces_address_id=replaced.address_id if replaced else None,
                created_event_id=ctx.event.event_id,
            )
        )
        if replaced is not None:
            self._security_event(
                ctx, SecurityEventType.ADDRESS_CHANGED, address_id=str(payload.address_id)
            )

    def _on_payment_method(self, ctx: _Context) -> None:
        user = self._require_user(ctx)
        payload: PaymentMethodAddedPayload = ctx.payload
        if self._session.get(PaymentMethod, payload.payment_method_id) is not None:
            raise EventProcessingError(f"payment method {payload.payment_method_id} exists")
        self._session.add(
            PaymentMethod(
                payment_method_id=payload.payment_method_id,
                user_id=user.user_id,
                token_reference=payload.token_reference,
                method_type=payload.method_type,
                card_brand=payload.card_brand,
                card_last4=payload.card_last4,
                funding=payload.funding,
                issuer_country=payload.issuer_country,
                fingerprint_hash=(
                    self._pseudo.hash_payment_fingerprint(payload.fingerprint)
                    if payload.fingerprint
                    else None
                ),
                added_at=ctx.event.timestamp,
                created_event_id=ctx.event.event_id,
            )
        )
        self._security_event(
            ctx,
            SecurityEventType.PAYMENT_METHOD_ADDED,
            payment_method_id=str(payload.payment_method_id),
        )

    def _on_transaction_created(self, ctx: _Context) -> None:
        user = self._require_user(ctx)
        payload: TransactionCreatedPayload = ctx.payload
        if self._session.get(Transaction, payload.transaction_id) is not None:
            raise EventProcessingError(f"transaction {payload.transaction_id} exists")
        if payload.payment_method_id is not None:
            pm = self._session.get(PaymentMethod, payload.payment_method_id)
            if pm is None or pm.user_id != user.user_id:
                raise EventProcessingError("payment method not found for this user")
        if payload.shipping_address_id is not None:
            addr = self._session.get(Address, payload.shipping_address_id)
            if addr is None or addr.user_id != user.user_id:
                raise EventProcessingError("shipping address not found for this user")
        self._session.add(
            Transaction(
                transaction_id=payload.transaction_id,
                event_id=ctx.event.event_id,
                user_id=user.user_id,
                payment_method_id=payload.payment_method_id,
                shipping_address_id=payload.shipping_address_id,
                device_id=ctx.device.device_id if ctx.device else None,
                network_identity_id=ctx.network.network_identity_id if ctx.network else None,
                session_id=ctx.event.session_id,
                amount_minor=payload.amount_minor,
                currency=payload.currency,
                merchant_category=payload.merchant_category,
                channel=payload.channel,
                status=TransactionStatus.PENDING,
                occurred_at=ctx.event.timestamp,
            )
        )

    def _get_user_transaction(self, ctx: _Context, transaction_id: uuid.UUID) -> Transaction:
        user = self._require_user(ctx)
        txn = self._session.get(Transaction, transaction_id)
        if txn is None or txn.user_id != user.user_id:
            raise EventProcessingError(f"transaction {transaction_id} not found for this user")
        return txn

    def _on_transaction_decision(self, ctx: _Context) -> None:
        payload: TransactionDecisionPayload = ctx.payload
        txn = self._get_user_transaction(ctx, payload.transaction_id)
        if txn.status is not TransactionStatus.PENDING:
            raise EventProcessingError(f"transaction already {txn.status}")
        if ctx.event.timestamp < txn.occurred_at:
            raise EventProcessingError("decision precedes transaction creation")
        approved = ctx.event.event_type is EventType.TRANSACTION_APPROVED
        txn.status = TransactionStatus.APPROVED if approved else TransactionStatus.DECLINED
        txn.decision_outcome = (
            TransactionDecision.APPROVED if approved else TransactionDecision.DECLINED
        )
        txn.decided_at = ctx.event.timestamp
        txn.decision_reason = payload.reason

    def _on_chargeback(self, ctx: _Context) -> None:
        payload: ChargebackPayload = ctx.payload
        txn = self._get_user_transaction(ctx, payload.transaction_id)
        if txn.status is not TransactionStatus.APPROVED:
            raise EventProcessingError("only approved transactions can be charged back")
        txn.status = TransactionStatus.CHARGEBACK
        record_label(
            self._session,
            user_id=txn.user_id,
            transaction_id=txn.transaction_id,
            event_id=txn.event_id,
            source_event_id=ctx.event.event_id,
            label=LabelValue.FRAUD,
            fraud_type=payload.fraud_type,
            label_source=LabelSource.CHARGEBACK,
            labelled_at=ctx.event.timestamp,
            notes=f"reason_code={payload.reason_code}",
        )

    def _on_fraud_confirmed(self, ctx: _Context) -> None:
        user = self._require_user(ctx)
        payload: FraudConfirmedPayload = ctx.payload
        target_event_id = payload.target_event_id
        if payload.transaction_id is not None:
            txn = self._get_user_transaction(ctx, payload.transaction_id)
            target_event_id = target_event_id or txn.event_id
        if target_event_id is not None and self._session.get(EventRecord, target_event_id) is None:
            raise EventProcessingError(f"target event {target_event_id} not found")
        record_label(
            self._session,
            user_id=user.user_id,
            transaction_id=payload.transaction_id,
            event_id=target_event_id,
            source_event_id=ctx.event.event_id,
            label=LabelValue.FRAUD,
            fraud_type=payload.fraud_type,
            label_source=payload.label_source,
            confidence=payload.confidence,
            labelled_at=ctx.event.timestamp,
            notes=payload.notes,
        )

    def _on_account_lifecycle(self, ctx: _Context) -> None:
        kind = SecurityEventType(ctx.event.event_type.value)
        method = ctx.payload.method
        self._security_event(ctx, kind, **({"method": method} if method else {}))

    def _on_address_verified(self, ctx: _Context) -> None:
        user = self._require_user(ctx)
        payload: AddressVerifiedPayload = ctx.payload
        address = self._session.get(Address, payload.address_id)
        if address is None or address.user_id != user.user_id:
            raise EventProcessingError("address not found for this user")
        if ctx.event.timestamp < address.added_at:
            raise EventProcessingError("verification precedes address creation")
        # Keep the first verification time: verification is monotone in time.
        if address.verified_at is None or ctx.event.timestamp < address.verified_at:
            address.verified_at = ctx.event.timestamp

    def _on_payment_method_verified(self, ctx: _Context) -> None:
        user = self._require_user(ctx)
        payload: PaymentMethodVerifiedPayload = ctx.payload
        pm = self._session.get(PaymentMethod, payload.payment_method_id)
        if pm is None or pm.user_id != user.user_id:
            raise EventProcessingError("payment method not found for this user")
        if ctx.event.timestamp < pm.added_at:
            raise EventProcessingError("verification precedes payment method creation")
        if pm.verified_at is None or ctx.event.timestamp < pm.verified_at:
            pm.verified_at = ctx.event.timestamp


_HANDLERS = {
    EventType.LOGIN_ATTEMPT: EventProcessor._on_login,
    EventType.LOGIN_SUCCESS: EventProcessor._on_login,
    EventType.LOGIN_FAILURE: EventProcessor._on_login,
    EventType.PASSWORD_RESET: EventProcessor._on_password_reset,
    EventType.NEW_DEVICE: EventProcessor._on_new_device,
    EventType.ADDRESS_ADDED: EventProcessor._on_address,
    EventType.ADDRESS_CHANGED: EventProcessor._on_address,
    EventType.PAYMENT_METHOD_ADDED: EventProcessor._on_payment_method,
    EventType.TRANSACTION_CREATED: EventProcessor._on_transaction_created,
    EventType.TRANSACTION_APPROVED: EventProcessor._on_transaction_decision,
    EventType.TRANSACTION_DECLINED: EventProcessor._on_transaction_decision,
    EventType.CHARGEBACK: EventProcessor._on_chargeback,
    EventType.FRAUD_CONFIRMED: EventProcessor._on_fraud_confirmed,
    EventType.EMAIL_VERIFIED: EventProcessor._on_account_lifecycle,
    EventType.EMAIL_CHANGED: EventProcessor._on_account_lifecycle,
    EventType.PHONE_VERIFIED: EventProcessor._on_account_lifecycle,
    EventType.PHONE_CHANGED: EventProcessor._on_account_lifecycle,
    EventType.MFA_ENABLED: EventProcessor._on_account_lifecycle,
    EventType.MFA_DISABLED: EventProcessor._on_account_lifecycle,
    EventType.ADDRESS_VERIFIED: EventProcessor._on_address_verified,
    EventType.PAYMENT_METHOD_VERIFIED: EventProcessor._on_payment_method_verified,
}
