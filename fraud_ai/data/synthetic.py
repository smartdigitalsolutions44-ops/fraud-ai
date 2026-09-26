"""Deterministic synthetic behaviour generator.

Produces a chronological stream of :class:`~fraud_ai.core.events.Event` objects covering
legitimate and suspicious behaviour. Events are ingested through the real
:class:`~fraud_ai.ingestion.EventProcessor`, so synthetic data exercises the same write
path as production data.

Scenarios
---------
normal                  same device/address, consistent spending, occasional mobile IPs
legitimate_vpn          long-term VPN user with otherwise normal, stable behaviour
shared_network          many legitimate accounts behind one office NAT / carrier CGNAT
new_home_address        a legitimate move: new address + new ISP, *not* fraud
account_takeover        new device + new network + password reset + new address + big buy
suspicious_velocity     accounts hit by a credential-stuffing burst from few IPs/devices

Safety: every IP address is drawn from private, CGNAT or documentation ranges and every
ASN from the private-use range, so no real network or person is referenced.
"""

from __future__ import annotations

import random
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from fraud_ai.core.enums import (
    AuthMethod,
    CardFunding,
    DeviceType,
    EventSource,
    EventType,
    FraudType,
    LabelSource,
    NetworkType,
)
from fraud_ai.core.events import Event

SCENARIO_WEIGHTS: dict[str, float] = {
    "normal": 0.45,
    "shared_network": 0.15,
    "suspicious_velocity": 0.12,
    "legitimate_vpn": 0.10,
    "new_home_address": 0.10,
    "account_takeover": 0.08,
}
SCENARIOS = tuple(SCENARIO_WEIGHTS)

_STREETS = [
    "High Street",
    "Station Road",
    "Church Lane",
    "Mill Road",
    "Park Avenue",
    "Victoria Road",
    "Green Lane",
    "Kings Road",
    "Queens Drive",
    "Manor Way",
]
_TOWNS = [
    ("GB", "England", "Leeds", "LS1"),
    ("GB", "England", "Bristol", "BS1"),
    ("GB", "Scotland", "Glasgow", "G1"),
    ("GB", "Wales", "Cardiff", "CF10"),
    ("GB", "England", "York", "YO1"),
    ("GB", "England", "Norwich", "NR1"),
]
_FOREIGN_TOWNS = [
    ("NL", "North Holland", "Amsterdam", "1012"),
    ("RO", "Bucharest", "Bucharest", "0100"),
    ("NG", "Lagos", "Lagos", "1000"),
    ("US", "Florida", "Miami", "331"),
]
_MCCS = ["5411", "5812", "5999", "5732", "4121", "5311", "5942", "5691"]


@dataclass(frozen=True)
class _Asn:
    asn: int
    org: str
    network_type: NetworkType
    country: str
    vpn: bool = False
    proxy: bool = False
    tor: bool = False
    datacenter: bool = False
    mobile: bool = False
    proxy_confidence: float | None = None


# Private-use ASNs (RFC 6996) with synthetic organisations.
_RESIDENTIAL = [
    _Asn(64601, "Synthetic Broadband GB", NetworkType.RESIDENTIAL, "GB"),
    _Asn(64602, "Example Fibre GB", NetworkType.RESIDENTIAL, "GB"),
    _Asn(64603, "Demo Cable GB", NetworkType.RESIDENTIAL, "GB"),
]
_MOBILE = [
    _Asn(64701, "Synthetic Mobile GB", NetworkType.MOBILE, "GB", mobile=True),
    _Asn(64702, "Example Wireless GB", NetworkType.MOBILE, "GB", mobile=True),
]
_BUSINESS = _Asn(64801, "Example Corp Offices", NetworkType.BUSINESS, "GB")
_VPN = [
    _Asn(
        65001,
        "Synthetic VPN Service",
        NetworkType.DATACENTER,
        "GB",
        vpn=True,
        datacenter=True,
        proxy_confidence=0.93,
    ),
    _Asn(
        65002,
        "Example Privacy Network",
        NetworkType.DATACENTER,
        "NL",
        vpn=True,
        datacenter=True,
        proxy_confidence=0.88,
    ),
]
_HOSTING = [
    _Asn(
        65101,
        "Synthetic Cloud Hosting",
        NetworkType.DATACENTER,
        "NL",
        datacenter=True,
        proxy=True,
        proxy_confidence=0.76,
    ),
    _Asn(
        65102,
        "Example Bulletproof Hosting",
        NetworkType.DATACENTER,
        "RO",
        datacenter=True,
        proxy=True,
        proxy_confidence=0.91,
    ),
]
_TOR = _Asn(
    65201,
    "Synthetic Tor Exit Relay",
    NetworkType.DATACENTER,
    "DE",
    tor=True,
    datacenter=True,
    proxy_confidence=0.99,
)
_FOREIGN_RESIDENTIAL = _Asn(64901, "Overseas Home ISP", NetworkType.RESIDENTIAL, "RO")


def _network(ip: str, asn: _Asn, region: str | None = None) -> dict[str, Any]:
    net: dict[str, Any] = {
        "ip": ip,
        "asn": asn.asn,
        "asn_org": asn.org,
        "country": asn.country,
        "network_type": asn.network_type.value,
        "is_mobile_network": asn.mobile,
        "is_datacenter": asn.datacenter,
        "is_known_proxy": asn.proxy,
        "is_known_vpn": asn.vpn,
        "is_tor": asn.tor,
        "intel_source": "synthetic",
    }
    if region:
        net["region"] = region
    if asn.proxy_confidence is not None:
        net["proxy_confidence"] = asn.proxy_confidence
    return net


@dataclass
class _DeviceProfile:
    identifier: str
    context: dict[str, Any]


@dataclass
class _Profile:
    user_id: uuid.UUID
    scenario: str
    created_at: datetime
    home_address_id: uuid.UUID
    home_town: tuple[str, str, str, str]
    home_network: dict[str, Any]
    primary_device: _DeviceProfile
    mobile_device: _DeviceProfile | None
    payment_method_id: uuid.UUID
    avg_amount: float
    login_rate_per_day: float
    known_devices: set[str] = field(default_factory=set)
    mfa_enabled: bool = False


@dataclass
class SyntheticDataset:
    events: list[Event]
    fraud_transaction_ids: set[uuid.UUID]
    scenario_counts: dict[str, int]
    reference_time: datetime

    @property
    def event_type_counts(self) -> dict[str, int]:
        return dict(Counter(e.event_type.value for e in self.events))


class SyntheticDataGenerator:
    def __init__(self, *, seed: int, reference_time: datetime, activity_days: int = 90) -> None:
        if activity_days < 30:
            raise ValueError("activity_days must be at least 30")
        self.rng = random.Random(seed)
        self.end = reference_time
        self.start = reference_time - timedelta(days=activity_days)
        self.activity_days = activity_days
        self._events: list[tuple[datetime, int, Event]] = []
        self._seq = 0
        self._fraud_txns: set[uuid.UUID] = set()
        self._ip_counter = 0
        self._office_ips = [f"192.0.2.{i}" for i in (10, 20, 30)]  # TEST-NET-1
        self._cgnat_pool = [f"100.64.{i}.{j}" for i in range(4) for j in (5, 9, 17, 33)]
        self._vpn_ips = [f"198.51.100.{i}" for i in range(10, 40)]  # TEST-NET-2
        self._hosting_ips = [f"203.0.113.{i}" for i in range(10, 60)]  # TEST-NET-3
        self._tor_ips = [f"203.0.113.{i}" for i in range(200, 206)]
        # One fraud ring operates several takeovers from shared infrastructure.
        self._ring_ips = [f"203.0.113.{i}" for i in (70, 71)]
        self._ring_device: _DeviceProfile | None = None

    # ------------------------------------------------------------------ helpers
    def _uuid(self) -> uuid.UUID:
        return uuid.UUID(int=self.rng.getrandbits(128), version=4)

    def _emit(
        self,
        event_type: EventType,
        ts: datetime,
        user_id: uuid.UUID | None,
        metadata: dict[str, Any],
        *,
        device: str | None = None,
        session_id: str | None = None,
    ) -> Event:
        event = Event(
            event_id=self._uuid(),
            event_type=event_type,
            timestamp=ts,
            user_id=user_id,
            session_id=session_id,
            device_id=device,
            source=EventSource.SYNTHETIC,
            metadata=metadata,
        )
        self._events.append((ts, self._seq, event))
        self._seq += 1
        return event

    def _residential_ip(self) -> str:
        self._ip_counter += 1
        n = self._ip_counter
        return f"10.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255 or 1}"

    def _device(self, kind: DeviceType) -> _DeviceProfile:
        os_family, client = {
            DeviceType.MOBILE: self.rng.choice(
                [("iOS", "ExampleApp iOS"), ("Android", "ExampleApp Android")]
            ),
            DeviceType.DESKTOP: self.rng.choice(
                [("Windows", "Firefox"), ("macOS", "Safari"), ("Windows", "Chrome")]
            ),
            DeviceType.TABLET: ("iPadOS", "Safari"),
        }.get(kind, ("Linux", "Chrome"))
        return _DeviceProfile(
            identifier=f"syn-dev-{self._uuid().hex}",
            context={"os_family": os_family, "client_family": client, "device_type": kind.value},
        )

    def _address_text(self, town: tuple[str, str, str, str]) -> str:
        number, street = self.rng.randint(1, 250), self.rng.choice(_STREETS)
        return f"{number} {street}, {town[2]} {town[3]} {self.rng.randint(1, 9)}XX"

    def _amount(self, mean: float, spread: float = 0.35) -> str:
        value = max(1.0, self.rng.lognormvariate(0, spread) * mean)
        return str(Decimal(str(round(value, 2))).quantize(Decimal("0.01")))

    def _login_times(self, rate: float, start: datetime, end: datetime) -> list[datetime]:
        times: list[datetime] = []
        t = start
        while True:
            t = t + timedelta(days=self.rng.expovariate(rate))
            if t >= end:
                return times
            hour = self.rng.choice([7, 8, 12, 13, 18, 19, 20, 21, 22])
            times.append(
                t.replace(
                    hour=hour,
                    minute=self.rng.randint(0, 59),
                    second=self.rng.randint(0, 59),
                    microsecond=0,
                )
            )

    # ------------------------------------------------------------------ building blocks
    def _create_account(
        self, scenario: str, *, min_age_days: int = 60, max_age_days: int = 1500
    ) -> _Profile:
        user_id = self._uuid()
        created = self.end - timedelta(
            days=self.rng.randint(min_age_days, max_age_days), minutes=self.rng.randint(0, 1439)
        )
        town = self.rng.choice(_TOWNS)
        home_net = _network(self._residential_ip(), self.rng.choice(_RESIDENTIAL), town[1])
        primary = self._device(self.rng.choice([DeviceType.DESKTOP, DeviceType.MOBILE]))
        mobile = self._device(DeviceType.MOBILE) if self.rng.random() < 0.6 else None
        profile = _Profile(
            user_id=user_id,
            scenario=scenario,
            created_at=created,
            home_address_id=self._uuid(),
            home_town=town,
            home_network=home_net,
            primary_device=primary,
            mobile_device=mobile,
            payment_method_id=self._uuid(),
            avg_amount=self.rng.uniform(15, 120),
            login_rate_per_day=self.rng.uniform(0.25, 0.8),
        )
        session = f"s-{self._uuid().hex[:16]}"
        self._emit(
            EventType.ACCOUNT_CREATED,
            created,
            user_id,
            {
                "external_ref": f"SYN-{user_id.hex[:12].upper()}",
                "home_country": "GB",
                "synthetic_scenario": scenario,
                "network": home_net,
                "device": primary.context,
            },
            device=primary.identifier,
            session_id=session,
        )
        self._new_device(profile, primary, created + timedelta(seconds=5), home_net, session)
        self._emit(
            EventType.ADDRESS_ADDED,
            created + timedelta(minutes=2),
            user_id,
            {
                "address_id": str(profile.home_address_id),
                "address_type": "home",
                "full_address": self._address_text(town),
                "country": town[0],
                "region": town[1],
                "postal_prefix": town[3],
            },
            device=primary.identifier,
            session_id=session,
        )
        self._emit(
            EventType.PAYMENT_METHOD_ADDED,
            created + timedelta(minutes=4),
            user_id,
            self._card(profile.payment_method_id, "GB"),
            device=primary.identifier,
            session_id=session,
        )
        self._onboarding_verifications(profile, created, session)
        return profile

    def _onboarding_verifications(self, profile: _Profile, created: datetime, session: str) -> None:
        """Typical post-signup verifications (they carry no contact details)."""
        device = profile.primary_device.identifier
        if self.rng.random() < 0.95:
            self._emit(
                EventType.EMAIL_VERIFIED,
                created + timedelta(minutes=10),
                profile.user_id,
                {"method": "email_link"},
                device=device,
                session_id=session,
            )
        if self.rng.random() < 0.6:
            self._emit(
                EventType.PHONE_VERIFIED,
                created + timedelta(hours=20),
                profile.user_id,
                {"method": "sms_code"},
                device=device,
            )
        if self.rng.random() < 0.35:
            profile.mfa_enabled = True
            self._emit(
                EventType.MFA_ENABLED,
                created + timedelta(days=2),
                profile.user_id,
                {"method": "totp"},
                device=device,
            )
        if self.rng.random() < 0.8:
            self._emit(
                EventType.PAYMENT_METHOD_VERIFIED,
                created + timedelta(minutes=5),
                profile.user_id,
                {"payment_method_id": str(profile.payment_method_id), "method": "3ds"},
                device=device,
                session_id=session,
            )
        if self.rng.random() < 0.7:
            self._emit(
                EventType.ADDRESS_VERIFIED,
                created + timedelta(days=1),
                profile.user_id,
                {"address_id": str(profile.home_address_id), "method": "avs"},
            )

    def _card(self, pm_id: uuid.UUID, issuer_country: str) -> dict[str, Any]:
        return {
            "payment_method_id": str(pm_id),
            "token_reference": f"tok_syn_{pm_id.hex[:20]}",
            "method_type": "card",
            "card_brand": self.rng.choice(["visa", "mastercard", "amex"]),
            "card_last4": f"{self.rng.randint(0, 9999):04d}",
            "funding": self.rng.choice([CardFunding.DEBIT, CardFunding.CREDIT]).value,
            "issuer_country": issuer_country,
            "fingerprint": f"fp_syn_{self._uuid().hex}",
        }

    def _new_device(
        self,
        profile: _Profile,
        device: _DeviceProfile,
        ts: datetime,
        net: dict[str, Any],
        session: str | None,
    ) -> None:
        if device.identifier in profile.known_devices:
            return
        profile.known_devices.add(device.identifier)
        self._emit(
            EventType.NEW_DEVICE,
            ts,
            profile.user_id,
            {"device": device.context, "network": net},
            device=device.identifier,
            session_id=session,
        )

    def _login(
        self,
        profile: _Profile,
        ts: datetime,
        device: _DeviceProfile,
        net: dict[str, Any],
        *,
        typo: bool = False,
        mfa: bool = False,
    ) -> tuple[Event, str]:
        session = f"s-{self._uuid().hex[:16]}"
        if device.identifier not in profile.known_devices:
            self._new_device(profile, device, ts - timedelta(seconds=30), net, session)
        if typo:
            self._emit(
                EventType.LOGIN_FAILURE,
                ts - timedelta(seconds=40),
                profile.user_id,
                {
                    "auth_method": "password",
                    "failure_reason": "bad_password",
                    "network": net,
                    "device": device.context,
                },
                device=device.identifier,
                session_id=session,
            )
        event = self._emit(
            EventType.LOGIN_SUCCESS,
            ts,
            profile.user_id,
            {
                "auth_method": AuthMethod.PASSWORD.value,
                "mfa_used": mfa,
                "network": net,
                "device": device.context,
            },
            device=device.identifier,
            session_id=session,
        )
        return event, session

    def _purchase(
        self,
        profile: _Profile,
        ts: datetime,
        device: _DeviceProfile,
        net: dict[str, Any],
        session: str,
        amount: str,
        *,
        address_id: uuid.UUID | None = None,
        pm_id: uuid.UUID | None = None,
        approve_prob: float = 0.98,
    ) -> tuple[uuid.UUID, bool]:
        txn_id = self._uuid()
        self._emit(
            EventType.TRANSACTION_CREATED,
            ts,
            profile.user_id,
            {
                "transaction_id": str(txn_id),
                "amount": amount,
                "currency": "GBP",
                "payment_method_id": str(pm_id or profile.payment_method_id),
                "shipping_address_id": str(address_id or profile.home_address_id),
                "merchant_category": self.rng.choice(_MCCS),
                "channel": "mobile_app" if device.context["device_type"] == "mobile" else "web",
                "network": net,
                "device": device.context,
            },
            device=device.identifier,
            session_id=session,
        )
        approved = self.rng.random() < approve_prob
        decision = EventType.TRANSACTION_APPROVED if approved else EventType.TRANSACTION_DECLINED
        self._emit(
            decision,
            ts + timedelta(seconds=self.rng.randint(1, 4)),
            profile.user_id,
            {
                "transaction_id": str(txn_id),
                **({} if approved else {"reason": "insufficient_funds"}),
            },
            device=device.identifier,
            session_id=session,
        )
        return txn_id, approved

    def _routine_activity(
        self,
        profile: _Profile,
        start: datetime,
        end: datetime,
        *,
        network_picker: Any = None,
        purchase_prob: float = 0.4,
    ) -> None:
        begin = max(start, profile.created_at + timedelta(hours=1))
        for ts in self._login_times(profile.login_rate_per_day, begin, end):
            device = profile.primary_device
            net = profile.home_network
            if profile.mobile_device and self.rng.random() < 0.25:
                device = profile.mobile_device
                cgnat = self.rng.choice(self._cgnat_pool)
                net = _network(cgnat, self.rng.choice(_MOBILE))
            if network_picker is not None:
                net = network_picker(ts, net)
            _, session = self._login(
                profile, ts, device, net, typo=self.rng.random() < 0.05, mfa=self.rng.random() < 0.1
            )
            if self.rng.random() < purchase_prob:
                self._purchase(
                    profile,
                    ts + timedelta(minutes=self.rng.randint(1, 20)),
                    device,
                    net,
                    session,
                    self._amount(profile.avg_amount),
                )

    # ------------------------------------------------------------------ scenarios
    def _scenario_normal(self) -> None:
        profile = self._create_account("normal")
        self._routine_activity(profile, self.start, self.end)

    def _scenario_legitimate_vpn(self) -> None:
        profile = self._create_account("legitimate_vpn", min_age_days=365)
        vpn = self.rng.choice(_VPN)

        def pick(_ts: datetime, net: dict[str, Any]) -> dict[str, Any]:
            if self.rng.random() < 0.8:
                return _network(self.rng.choice(self._vpn_ips), vpn)
            return net

        # VPN use spans a long history (up to a year), not just the activity window.
        history_start = max(profile.created_at, self.end - timedelta(days=365))
        self._routine_activity(
            profile, history_start, self.end, network_picker=pick, purchase_prob=0.3
        )

    def _scenario_shared_network(self, office_ip: str) -> None:
        profile = self._create_account("shared_network")

        def pick(ts: datetime, net: dict[str, Any]) -> dict[str, Any]:
            if ts.weekday() < 5 and 8 <= ts.hour <= 18 and self.rng.random() < 0.7:
                return _network(office_ip, _BUSINESS, "England")
            return net

        self._routine_activity(profile, self.start, self.end, network_picker=pick)

    def _scenario_new_home_address(self) -> None:
        profile = self._create_account("new_home_address", min_age_days=200)
        third = self.activity_days // 3
        move = self.start + timedelta(
            days=self.rng.randint(third, max(third, self.activity_days - 20)),
            hours=self.rng.randint(9, 17),
        )
        self._routine_activity(profile, self.start, move)
        new_town = self.rng.choice([t for t in _TOWNS if t != profile.home_town])
        new_net = _network(self._residential_ip(), self.rng.choice(_RESIDENTIAL), new_town[1])
        new_address = self._uuid()
        _, session = self._login(profile, move, profile.primary_device, profile.home_network)
        self._emit(
            EventType.ADDRESS_CHANGED,
            move + timedelta(minutes=3),
            profile.user_id,
            {
                "address_id": str(new_address),
                "address_type": "home",
                "full_address": self._address_text(new_town),
                "country": new_town[0],
                "region": new_town[1],
                "postal_prefix": new_town[3],
                "replaces_address_id": str(profile.home_address_id),
            },
            device=profile.primary_device.identifier,
            session_id=session,
        )
        if self.rng.random() < 0.6:
            self._emit(
                EventType.ADDRESS_VERIFIED,
                move + timedelta(days=self.rng.randint(1, 3)),
                profile.user_id,
                {"address_id": str(new_address), "method": "postal"},
            )
        profile.home_address_id = new_address
        profile.home_network = new_net
        profile.home_town = new_town
        if self.rng.random() < 0.5:  # e.g. bought a new laptop for the new home
            profile.primary_device = self._device(DeviceType.DESKTOP)
        # A legitimate, larger-than-usual purchase to the new address (furniture etc.).
        buy_at = move + timedelta(days=self.rng.randint(1, 5), hours=2)
        _, session = self._login(profile, buy_at, profile.primary_device, new_net, mfa=True)
        self._purchase(
            profile,
            buy_at + timedelta(minutes=6),
            profile.primary_device,
            new_net,
            session,
            self._amount(profile.avg_amount * self.rng.uniform(2.0, 4.0), 0.1),
        )
        self._routine_activity(profile, buy_at + timedelta(hours=6), self.end)

    def _scenario_account_takeover(self) -> None:
        profile = self._create_account("account_takeover", min_age_days=180)
        latest = min(35, self.activity_days - 5)
        attack = self.end - timedelta(
            days=self.rng.randint(min(12, latest), latest), hours=self.rng.randint(0, 20)
        )
        self._routine_activity(profile, self.start, attack - timedelta(hours=2))

        attacker_dev = self._device(DeviceType.DESKTOP)
        if self.rng.random() < 0.5:
            # Fraud ring: the same attacker device and hosting IPs across several victims.
            if self._ring_device is None:
                self._ring_device = self._device(DeviceType.DESKTOP)
            attacker_dev = self._ring_device
            attacker_net = _network(self.rng.choice(self._ring_ips), _HOSTING[1])
        elif self.rng.random() < 0.6:
            asn = self.rng.choice(_HOSTING)
            attacker_net = _network(self.rng.choice(self._hosting_ips), asn)
        else:
            attacker_net = _network(self._residential_ip(), _FOREIGN_RESIDENTIAL, "Bucharest")
        session = f"s-{self._uuid().hex[:16]}"
        t = attack
        for _ in range(self.rng.randint(2, 5)):
            self._emit(
                EventType.LOGIN_FAILURE,
                t,
                profile.user_id,
                {
                    "auth_method": "password",
                    "failure_reason": "bad_password",
                    "network": attacker_net,
                    "device": attacker_dev.context,
                },
                device=attacker_dev.identifier,
                session_id=session,
            )
            t += timedelta(seconds=self.rng.randint(5, 40))
        self._emit(
            EventType.PASSWORD_RESET,
            t + timedelta(minutes=2),
            profile.user_id,
            {"method": "email_link", "network": attacker_net, "device": attacker_dev.context},
            device=attacker_dev.identifier,
            session_id=session,
        )
        login, session = self._login(profile, t + timedelta(minutes=9), attacker_dev, attacker_net)
        # Lock the owner out: change the email, sometimes the phone, remove MFA.
        for kind, probability, offset in (
            (EventType.EMAIL_CHANGED, 0.6, 10),
            (EventType.PHONE_CHANGED, 0.25, 11),
            (EventType.MFA_DISABLED, 0.8 if profile.mfa_enabled else 0.0, 11),
        ):
            if self.rng.random() < probability:
                self._emit(
                    kind,
                    t + timedelta(minutes=offset, seconds=30),
                    profile.user_id,
                    {"network": attacker_net, "device": attacker_dev.context},
                    device=attacker_dev.identifier,
                    session_id=session,
                )
        drop_town = self.rng.choice(_FOREIGN_TOWNS)
        drop_address = self._uuid()
        self._emit(
            EventType.ADDRESS_ADDED,
            t + timedelta(minutes=12),
            profile.user_id,
            {
                "address_id": str(drop_address),
                "address_type": "shipping",
                "full_address": self._address_text(drop_town),
                "country": drop_town[0],
                "region": drop_town[1],
                "postal_prefix": drop_town[3],
            },
            device=attacker_dev.identifier,
            session_id=session,
        )
        pm_id = None
        if self.rng.random() < 0.4:
            pm_id = self._uuid()
            self._emit(
                EventType.PAYMENT_METHOD_ADDED,
                t + timedelta(minutes=14),
                profile.user_id,
                {**self._card(pm_id, drop_town[0]), "funding": "prepaid"},
                device=attacker_dev.identifier,
                session_id=session,
            )
        amount = self._amount(profile.avg_amount * self.rng.uniform(5.0, 12.0), 0.1)
        txn_id, approved = self._purchase(
            profile,
            t + timedelta(minutes=17),
            attacker_dev,
            attacker_net,
            session,
            amount,
            address_id=drop_address,
            pm_id=pm_id,
            approve_prob=0.8,
        )
        self._fraud_txns.add(txn_id)
        # Victim reports the takeover; the malicious login is labelled.
        report = t + timedelta(days=self.rng.randint(1, 3))
        self._emit(
            EventType.FRAUD_CONFIRMED,
            report,
            profile.user_id,
            {
                "target_event_id": str(login.event_id),
                "fraud_type": "account_takeover",
                "label_source": LabelSource.CUSTOMER_REPORT.value,
                "confidence": 1.0,
            },
        )
        if approved:
            cb = min(t + timedelta(days=self.rng.randint(6, 11)), self.end - timedelta(hours=1))
            self._emit(
                EventType.CHARGEBACK,
                cb,
                profile.user_id,
                {
                    "transaction_id": str(txn_id),
                    "reason_code": "10.4",
                    "fraud_type": FraudType.ACCOUNT_TAKEOVER.value,
                },
            )
        else:
            self._emit(
                EventType.FRAUD_CONFIRMED,
                report + timedelta(minutes=5),
                profile.user_id,
                {
                    "transaction_id": str(txn_id),
                    "fraud_type": "account_takeover",
                    "label_source": LabelSource.ANALYST.value,
                    "confidence": 0.95,
                },
            )
        # The genuine owner recovers the account and carries on normally.
        self._routine_activity(profile, report + timedelta(hours=4), self.end)

    def _credential_stuffing_campaign(self, victims: list[_Profile]) -> None:
        when = self.end - timedelta(days=self.rng.randint(5, 25), hours=self.rng.randint(0, 23))
        ips = [self.rng.choice(self._hosting_ips) for _ in range(3)] + [
            self.rng.choice(self._tor_ips)
        ]
        bot = self._device(DeviceType.DESKTOP)  # one automation client reused across accounts
        bot.context = {
            "os_family": "Linux",
            "client_family": "HeadlessClient",
            "device_type": DeviceType.DESKTOP.value,
        }
        targets: list[tuple[_Profile | None, int]] = [(v, self.rng.randint(1, 3)) for v in victims]
        targets += [(None, 1) for _ in range(self.rng.randint(20, 40))]  # unknown usernames
        self.rng.shuffle(targets)
        t = when
        cracked = set(self.rng.sample(range(len(victims)), k=min(2, len(victims))))
        for victim, attempts in targets:
            for _ in range(attempts):
                ip = self.rng.choice(ips)
                asn = _TOR if ip in self._tor_ips else self.rng.choice(_HOSTING)
                net = _network(ip, asn)
                self._emit(
                    EventType.LOGIN_FAILURE,
                    t,
                    victim.user_id if victim else None,
                    {
                        "auth_method": "password",
                        "failure_reason": "bad_password" if victim else "unknown_user",
                        "network": net,
                        "device": bot.context,
                    },
                    device=bot.identifier,
                    session_id=f"s-{self._uuid().hex[:16]}",
                )
                t += timedelta(seconds=self.rng.randint(1, 6))
        # Reused passwords: a couple of victims are actually compromised.
        for idx in sorted(cracked):
            victim = victims[idx]
            t += timedelta(seconds=self.rng.randint(2, 8))
            net = _network(self.rng.choice(ips), self.rng.choice(_HOSTING))
            login, _ = self._login(victim, t, bot, net)
            self._emit(
                EventType.FRAUD_CONFIRMED,
                t + timedelta(hours=self.rng.randint(2, 30)),
                victim.user_id,
                {
                    "target_event_id": str(login.event_id),
                    "fraud_type": FraudType.CREDENTIAL_STUFFING.value,
                    "label_source": LabelSource.ANALYST.value,
                    "confidence": 0.9,
                },
            )

    # ------------------------------------------------------------------ orchestration
    @staticmethod
    def allocate(n_users: int) -> dict[str, int]:
        if n_users < len(SCENARIOS):
            raise ValueError(f"need at least {len(SCENARIOS)} users (one per scenario)")
        counts = {s: max(1, int(w * n_users)) for s, w in SCENARIO_WEIGHTS.items()}
        counts["normal"] += n_users - sum(counts.values())
        if counts["normal"] < 1:
            raise ValueError("user allocation failed")
        return counts

    def generate(self, n_users: int) -> SyntheticDataset:
        counts = self.allocate(n_users)
        for _ in range(counts["normal"]):
            self._scenario_normal()
        for _ in range(counts["legitimate_vpn"]):
            self._scenario_legitimate_vpn()
        for i in range(counts["shared_network"]):
            self._scenario_shared_network(self._office_ips[i % len(self._office_ips)])
        for _ in range(counts["new_home_address"]):
            self._scenario_new_home_address()
        for _ in range(counts["account_takeover"]):
            self._scenario_account_takeover()
        victims = []
        for _ in range(counts["suspicious_velocity"]):
            victim = self._create_account("suspicious_velocity")
            self._routine_activity(victim, self.start, self.end)
            victims.append(victim)
        self._credential_stuffing_campaign(victims)

        ordered = [e for _, _, e in sorted(self._events, key=lambda x: (x[0], x[1]))]
        return SyntheticDataset(
            events=ordered,
            fraud_transaction_ids=set(self._fraud_txns),
            scenario_counts=counts,
            reference_time=self.end,
        )
