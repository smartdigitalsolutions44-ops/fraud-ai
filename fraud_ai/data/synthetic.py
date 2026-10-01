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
new_customer            legitimate new account whose first purchase is larger than typical
new_account_fraud       new account + fresh (often prepaid/foreign) card + high-value buy
friendly_fraud          an entirely normal-looking purchase later charged back
slow_account_takeover   temporal takeovers spread over days (Stage 6): failed logins days
                        before a quiet purchase, gradual address/payment changes on a
                        hijacked device, a small test purchase then a larger one, normal
                        amounts at an abnormal cadence, a hijacked trusted session
legitimate_lookalike    legitimate mirrors of those patterns: travelling, a new phone,
                        a forgotten password over several days, gradual legitimate
                        changes, bursts of small purchases, a large buy after inactivity

Fraud is spread across the whole activity window (so that time-ordered train/validation/
test splits all contain positives) and deliberately overlaps legitimate behaviour: some
takeovers are stealthy (no failed logins or password reset, a domestic residential IP,
modest amounts), legitimate customers make occasional large purchases, change phones, use
VPNs or move house, and new customers look much like new-account fraud.

Safety: every IP address is drawn from private, CGNAT or documentation ranges and every
ASN from the private-use range, so no real network or person is referenced.
"""

from __future__ import annotations

import random
import uuid
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
    "normal": 0.27,
    "slow_account_takeover": 0.05,
    "legitimate_lookalike": 0.04,
    "shared_network": 0.11,
    "account_takeover": 0.11,
    "suspicious_velocity": 0.08,
    "legitimate_vpn": 0.08,
    "new_home_address": 0.08,
    "new_customer": 0.08,
    "new_account_fraud": 0.06,
    "friendly_fraud": 0.04,
}
SCENARIOS = tuple(SCENARIO_WEIGHTS)
FRAUD_SCENARIOS = (
    "account_takeover",
    "slow_account_takeover",
    "new_account_fraud",
    "friendly_fraud",
)

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


class SyntheticDataGenerator:
    def __init__(
        self,
        *,
        seed: int,
        reference_time: datetime,
        activity_days: int = 90,
        fraud_multiplier: float = 1.0,
    ) -> None:
        if activity_days < 30:
            raise ValueError("activity_days must be at least 30")
        self.rng = random.Random(seed)  # nosec B311 - seeded PRNG for SYNTHETIC data
        self.end = reference_time
        self.start = reference_time - timedelta(days=activity_days)
        self.activity_days = activity_days
        if not 0 < fraud_multiplier <= 3:
            raise ValueError("fraud_multiplier must be in (0, 3]")
        self.fraud_multiplier = fraud_multiplier
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
            snapped = t.replace(
                hour=hour,
                minute=self.rng.randint(0, 59),
                second=self.rng.randint(0, 59),
                microsecond=0,
            )
            # Snapping to a typical hour must never move activity before ``start`` (e.g.
            # before the account existed) or past ``end``.
            if start <= snapped < end:
                times.append(snapped)

    # ------------------------------------------------------------------ building blocks
    def _create_account(
        self,
        scenario: str,
        *,
        min_age_days: int = 60,
        max_age_days: int = 1500,
        created_at: datetime | None = None,
    ) -> _Profile:
        user_id = self._uuid()
        created = created_at or self.end - timedelta(
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
        ship: bool = True,
    ) -> tuple[uuid.UUID, bool]:
        """``ship=False`` models digital goods: no shipping address at all."""
        txn_id = self._uuid()
        metadata: dict[str, Any] = {
            "transaction_id": str(txn_id),
            "amount": amount,
            "currency": "GBP",
            "payment_method_id": str(pm_id or profile.payment_method_id),
            "merchant_category": self.rng.choice(_MCCS),
            "channel": "mobile_app" if device.context["device_type"] == "mobile" else "web",
            "network": net,
            "device": device.context,
        }
        if ship:
            metadata["shipping_address_id"] = str(address_id or profile.home_address_id)
        self._emit(
            EventType.TRANSACTION_CREATED,
            ts,
            profile.user_id,
            metadata,
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
            if self.rng.random() < 0.08:  # away from home: a friend's Wi-Fi, a hotel, a cafe
                net = _network(self._residential_ip(), self.rng.choice(_RESIDENTIAL), "England")
            if self.rng.random() < 0.04:  # a one-off device: work PC, a friend's laptop...
                device = self._device(self.rng.choice([DeviceType.DESKTOP, DeviceType.TABLET]))
            forgot = self.rng.random() < 0.02  # legitimate "forgot password" before shopping
            if forgot:
                self._emit(
                    EventType.PASSWORD_RESET,
                    ts - timedelta(minutes=3),
                    profile.user_id,
                    {"method": "email_link", "network": net, "device": device.context},
                    device=device.identifier,
                )
            _, session = self._login(
                profile, ts, device, net, typo=self.rng.random() < 0.05, mfa=self.rng.random() < 0.1
            )
            if forgot or self.rng.random() < purchase_prob:
                at = ts + timedelta(minutes=self.rng.randint(1, 20))
                # ~8% of legitimate purchases are unusually large (a TV, a holiday...).
                big = self.rng.random() < 0.08
                mean = profile.avg_amount * (self.rng.uniform(3.0, 9.0) if big else 1.0)
                kind = self.rng.random()
                if kind < 0.15:  # digital goods: no shipping address
                    self._purchase(
                        profile,
                        at,
                        device,
                        net,
                        session,
                        self._amount(mean, 0.15 if big else 0.35),
                        ship=False,
                    )
                    continue
                address = None
                if kind < 0.18:  # a gift sent to a newly added address
                    address = self._uuid()
                    town = self.rng.choice(_TOWNS)
                    self._emit(
                        EventType.ADDRESS_ADDED,
                        at - timedelta(minutes=1),
                        profile.user_id,
                        {
                            "address_id": str(address),
                            "address_type": "shipping",
                            "full_address": self._address_text(town),
                            "country": town[0],
                            "region": town[1],
                            "postal_prefix": town[3],
                        },
                        device=device.identifier,
                        session_id=session,
                    )
                self._purchase(
                    profile,
                    at,
                    device,
                    net,
                    session,
                    self._amount(mean, 0.15 if big else 0.35),
                    address_id=address,
                )

    # ------------------------------------------------------------------ scenarios
    def _attack_time(self) -> datetime:
        """Uniform over the window, leaving room for labels (chargebacks) to arrive."""
        span = max(1, self.activity_days - 20)
        return self.start + timedelta(days=5 + self.rng.random() * span)

    def _scenario_normal(self) -> None:
        profile = self._create_account("normal")
        if self.rng.random() < 0.2:  # upgrades their phone part-way through
            switch = self.start + timedelta(days=self.rng.random() * self.activity_days)
            self._routine_activity(profile, self.start, switch)
            profile.mobile_device = self._device(DeviceType.MOBILE)
            profile.primary_device = (
                profile.mobile_device
                if profile.primary_device.context["device_type"] == "mobile"
                else profile.primary_device
            )
            self._routine_activity(profile, switch, self.end)
            return
        self._routine_activity(profile, self.start, self.end)

    def _fraud_outcome(
        self,
        profile: _Profile,
        txn_id: uuid.UUID,
        approved: bool,
        at: datetime,
        fraud_type: FraudType,
    ) -> None:
        """Approved fraud is charged back later; declined fraud is confirmed by an analyst."""
        self._fraud_txns.add(txn_id)
        latest = self.end - timedelta(hours=1)
        if approved:
            cb = min(at + timedelta(days=self.rng.randint(5, 12)), latest)
            self._emit(
                EventType.CHARGEBACK,
                max(cb, at + timedelta(minutes=1)),
                profile.user_id,
                {
                    "transaction_id": str(txn_id),
                    "reason_code": "10.4",
                    "fraud_type": fraud_type.value,
                },
            )
        else:
            confirmed = min(at + timedelta(days=self.rng.randint(1, 3)), latest)
            self._emit(
                EventType.FRAUD_CONFIRMED,
                max(confirmed, at + timedelta(minutes=1)),
                profile.user_id,
                {
                    "transaction_id": str(txn_id),
                    "fraud_type": fraud_type.value,
                    "label_source": LabelSource.ANALYST.value,
                    "confidence": 0.95,
                },
            )

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
        # Victims must exist before the attack, which can fall anywhere in the window.
        profile = self._create_account(
            "account_takeover", min_age_days=max(180, self.activity_days + 10)
        )
        attack = self._attack_time()
        self._routine_activity(profile, self.start, attack - timedelta(hours=2))
        variant = self.rng.random()
        hijack = variant < 0.20  # malware / session hijack on the victim's own device
        stealth = hijack or variant < 0.50

        attacker_dev = self._device(self.rng.choice([DeviceType.DESKTOP, DeviceType.MOBILE]))
        if hijack:
            attacker_dev = profile.primary_device
            attacker_net = profile.home_network
        elif stealth:
            # Credential reuse from a domestic residential connection: few loud signals.
            attacker_net = _network(
                self._residential_ip(), self.rng.choice(_RESIDENTIAL), "England"
            )
        elif self.rng.random() < 0.5:
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
        if not stealth:
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
        if not stealth:
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
        drop_town = self.rng.choice(_TOWNS if stealth else _FOREIGN_TOWNS)
        destination = self.rng.random()
        ship = destination >= 0.30  # 30% digital goods (gift cards, top-ups): nothing shipped
        drop_address: uuid.UUID | None = None
        if destination >= 0.50:  # 50% a new drop address; 20% the victim's own address
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
        if self.rng.random() < (0.2 if stealth else 0.4):
            pm_id = self._uuid()
            self._emit(
                EventType.PAYMENT_METHOD_ADDED,
                t + timedelta(minutes=14),
                profile.user_id,
                {**self._card(pm_id, drop_town[0]), "funding": "prepaid"},
                device=attacker_dev.identifier,
                session_id=session,
            )
        # Amounts overlap legitimate large purchases (which reach 3-9x the usual spend).
        multiplier = (1.0, 3.0) if stealth else (2.0, 6.0)
        purchase_at = t + timedelta(minutes=17)
        for _ in range(self.rng.randint(1, 3)):
            amount = self._amount(profile.avg_amount * self.rng.uniform(*multiplier), 0.1)
            txn_id, approved = self._purchase(
                profile,
                purchase_at,
                attacker_dev,
                attacker_net,
                session,
                amount,
                address_id=drop_address,
                pm_id=pm_id,
                approve_prob=0.85,
                ship=ship,
            )
            self._fraud_outcome(profile, txn_id, approved, purchase_at, FraudType.ACCOUNT_TAKEOVER)
            purchase_at += timedelta(minutes=self.rng.randint(3, 40))
        # Victim reports the takeover; the malicious login is labelled.
        report = min(t + timedelta(days=self.rng.randint(1, 3)), self.end - timedelta(hours=1))
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
        # The genuine owner recovers the account and carries on normally.
        self._routine_activity(profile, report + timedelta(hours=4), self.end)

    def _new_account(self, scenario: str) -> tuple[_Profile, datetime]:
        created = self.start + timedelta(days=self.rng.random() * max(1, self.activity_days - 15))
        return self._create_account(scenario, created_at=created), created

    def _scenario_new_customer(self) -> None:
        """Legitimate: a new account whose first purchase is larger than typical."""
        profile, created = self._new_account("new_customer")
        net = profile.home_network
        if self.rng.random() < 0.15:  # privacy-conscious from day one
            net = _network(self.rng.choice(self._vpn_ips), self.rng.choice(_VPN))
        first = created + timedelta(hours=self.rng.uniform(0.2, 36))
        _, session = self._login(profile, first, profile.primary_device, net)
        pm = profile.payment_method_id
        if self.rng.random() < 0.3:  # adds a second (sometimes prepaid) card before buying
            pm = self._uuid()
            self._emit(
                EventType.PAYMENT_METHOD_ADDED,
                first + timedelta(minutes=2),
                profile.user_id,
                {**self._card(pm, "GB"), "funding": self.rng.choice(["prepaid", "debit"])},
                device=profile.primary_device.identifier,
                session_id=session,
            )
        self._purchase(
            profile,
            first + timedelta(minutes=5),
            profile.primary_device,
            net,
            session,
            self._amount(self.rng.uniform(80, 400), 0.2),
            pm_id=pm,
        )
        self._routine_activity(profile, first + timedelta(hours=2), self.end)

    def _scenario_new_account_fraud(self) -> None:
        """Fraud: new account, fresh card (often prepaid/foreign), quick high-value orders."""
        profile, created = self._new_account("new_account_fraud")
        if self.rng.random() < 0.3:
            net = _network(self.rng.choice(self._vpn_ips), self.rng.choice(_VPN))
        elif self.rng.random() < 0.3:
            net = _network(self.rng.choice(self._hosting_ips), self.rng.choice(_HOSTING))
        else:
            net = profile.home_network
        at = created + timedelta(hours=self.rng.uniform(0.1, 30))
        _, session = self._login(profile, at, profile.primary_device, net)
        pm = self._uuid()
        issuer = self.rng.choice(["GB", "GB", "RO", "NG", "US"])
        self._emit(
            EventType.PAYMENT_METHOD_ADDED,
            at + timedelta(minutes=1),
            profile.user_id,
            {
                **self._card(pm, issuer),
                "funding": self.rng.choice(["prepaid", "prepaid", "credit"]),
            },
            device=profile.primary_device.identifier,
            session_id=session,
        )
        purchase_at = at + timedelta(minutes=self.rng.randint(3, 30))
        for _ in range(self.rng.randint(1, 2)):
            txn_id, approved = self._purchase(
                profile,
                purchase_at,
                profile.primary_device,
                net,
                session,
                self._amount(self.rng.uniform(40, 450), 0.3),
                pm_id=pm,
                approve_prob=0.85,
            )
            self._fraud_outcome(
                profile, txn_id, approved, purchase_at, FraudType.STOLEN_PAYMENT_METHOD
            )
            purchase_at += timedelta(hours=self.rng.uniform(0.2, 6))

    def _scenario_friendly_fraud(self) -> None:
        """A normal customer disputes one purchase as fraud: nearly indistinguishable."""
        profile = self._create_account("friendly_fraud", min_age_days=self.activity_days + 10)
        disputed_at = self._attack_time()
        self._routine_activity(profile, self.start, disputed_at - timedelta(hours=1))
        _, session = self._login(profile, disputed_at, profile.primary_device, profile.home_network)
        txn_id, approved = self._purchase(
            profile,
            disputed_at + timedelta(minutes=4),
            profile.primary_device,
            profile.home_network,
            session,
            self._amount(profile.avg_amount * self.rng.uniform(1.0, 3.0), 0.2),
            approve_prob=1.0,
        )
        self._fraud_outcome(profile, txn_id, approved, disputed_at, FraudType.FRIENDLY_FRAUD)
        self._routine_activity(profile, disputed_at + timedelta(hours=6), self.end)

    def _credential_stuffing_campaign(self, victims: list[_Profile]) -> None:
        when = self._attack_time()
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
    # ------------------------------------------------------------------ Stage 6: temporal
    def _failed_login(
        self, profile: _Profile, ts: datetime, device: _DeviceProfile, net: dict[str, Any]
    ) -> None:
        self._emit(
            EventType.LOGIN_FAILURE,
            ts,
            profile.user_id,
            {
                "auth_method": "password",
                "failure_reason": "bad_password",
                "network": net,
                "device": device.context,
            },
            device=device.identifier,
        )

    def _add_address(
        self, profile: _Profile, ts: datetime, device: _DeviceProfile, session: str | None
    ) -> uuid.UUID:
        address = self._uuid()
        town = self.rng.choice(_TOWNS)
        self._emit(
            EventType.ADDRESS_ADDED,
            ts,
            profile.user_id,
            {
                "address_id": str(address),
                "address_type": "shipping",
                "full_address": self._address_text(town),
                "country": town[0],
                "region": town[1],
                "postal_prefix": town[3],
            },
            device=device.identifier,
            session_id=session,
        )
        return address

    def _add_card(
        self, profile: _Profile, ts: datetime, device: _DeviceProfile, session: str | None
    ) -> uuid.UUID:
        pm_id = self._uuid()
        self._emit(
            EventType.PAYMENT_METHOD_ADDED,
            ts,
            profile.user_id,
            self._card(pm_id, "GB"),
            device=device.identifier,
            session_id=session,
        )
        return pm_id

    def _fraud_buy(
        self,
        profile: _Profile,
        at: datetime,
        device: _DeviceProfile,
        net: dict[str, Any],
        session: str,
        amount: float,
        **kw: Any,
    ) -> None:
        txn_id, approved = self._purchase(
            profile, at, device, net, session, self._amount(amount, 0.1), approve_prob=0.9, **kw
        )
        self._fraud_outcome(profile, txn_id, approved, at, FraudType.ACCOUNT_TAKEOVER)

    def _scenario_slow_account_takeover(self) -> None:
        """Takeovers whose tell-tale signs are spread over days, not visible in one event.

        A  failed logins on several days, a successful login, a quiet period, then an
           ordinary-looking purchase from a device that is by then "known";
        B  a hijacked trusted device on the home network adds an address, then a card over
           a few days, then buys;
        C  a tiny test purchase, then a larger purchase a day or more later;
        D  normal amounts, but several purchases in a burst at night;
        E  a hijacked trusted session: victim's device and network, normal amount - only
           the timing differs.
        """
        profile = self._create_account(
            "slow_account_takeover", min_age_days=max(180, self.activity_days + 10)
        )
        attack = self._attack_time()
        opening = max(self.start + timedelta(days=1), attack - timedelta(days=6))
        self._routine_activity(profile, self.start, opening)
        variant = self.rng.choice("ABCDE")
        domestic = _network(self._residential_ip(), self.rng.choice(_RESIDENTIAL), "England")
        attacker = self._device(self.rng.choice([DeviceType.DESKTOP, DeviceType.MOBILE]))
        base = profile.avg_amount
        latest = self.end - timedelta(days=3)
        if variant == "A":
            t = opening
            for _ in range(self.rng.randint(2, 4)):  # probing on several days
                for _ in range(self.rng.randint(1, 3)):
                    self._failed_login(
                        profile, t + timedelta(minutes=self.rng.randint(0, 90)), attacker, domestic
                    )
                t += timedelta(days=1, hours=self.rng.randint(-3, 3))
            login, session = self._login(profile, t, attacker, domestic)
            buy_at = min(t + timedelta(days=self.rng.uniform(1.0, 3.0)), latest)
            _, session = self._login(profile, buy_at, attacker, domestic)
            self._fraud_buy(
                profile,
                buy_at + timedelta(minutes=6),
                attacker,
                domestic,
                session,
                base * self.rng.uniform(0.8, 2.0),
                ship=self.rng.random() < 0.5,
            )
            end_of_attack = buy_at
        elif variant == "B":
            device, net = profile.primary_device, profile.home_network
            login, session = self._login(profile, opening, device, net)
            address = self._add_address(profile, opening + timedelta(minutes=5), device, session)
            t = opening + timedelta(days=self.rng.uniform(1.0, 2.5))
            _, session = self._login(profile, t, device, net)
            pm_id = self._add_card(profile, t + timedelta(minutes=4), device, session)
            buy_at = min(t + timedelta(days=self.rng.uniform(1.0, 2.5)), latest)
            _, session = self._login(profile, buy_at, device, net)
            self._fraud_buy(
                profile,
                buy_at + timedelta(minutes=8),
                device,
                net,
                session,
                base * self.rng.uniform(1.0, 2.5),
                address_id=address,
                pm_id=pm_id,
            )
            end_of_attack = buy_at
        elif variant == "C":
            login, session = self._login(profile, opening, attacker, domestic)
            self._fraud_buy(
                profile,
                opening + timedelta(minutes=3),
                attacker,
                domestic,
                session,
                self.rng.uniform(1.0, 5.0),
                ship=False,
            )
            buy_at = min(opening + timedelta(days=self.rng.uniform(1.0, 4.0)), latest)
            _, session = self._login(profile, buy_at, attacker, domestic)
            self._fraud_buy(
                profile,
                buy_at + timedelta(minutes=5),
                attacker,
                domestic,
                session,
                base * self.rng.uniform(1.5, 3.0),
                ship=self.rng.random() < 0.6,
            )
            end_of_attack = buy_at
        elif variant == "D":
            device = profile.mobile_device or profile.primary_device
            night = opening.replace(hour=self.rng.randint(1, 4), minute=self.rng.randint(0, 59))
            login, session = self._login(profile, night, device, domestic)
            t = night
            for _ in range(self.rng.randint(3, 5)):
                t += timedelta(minutes=self.rng.randint(2, 12))
                self._fraud_buy(
                    profile,
                    t,
                    device,
                    domestic,
                    session,
                    base * self.rng.uniform(0.7, 1.3),
                    ship=False,
                )
            end_of_attack = t
        else:  # E: hijacked trusted session
            device, net = profile.primary_device, profile.home_network
            t = opening.replace(hour=self.rng.randint(0, 5), minute=self.rng.randint(0, 59))
            login, session = self._login(profile, t, device, net)
            for _ in range(self.rng.randint(1, 2)):
                t += timedelta(minutes=self.rng.randint(1, 5))
                self._fraud_buy(
                    profile,
                    t,
                    device,
                    net,
                    session,
                    base * self.rng.uniform(0.8, 1.6),
                    ship=self.rng.random() < 0.3,
                )
            end_of_attack = t
        report = min(
            end_of_attack + timedelta(days=self.rng.randint(1, 3)), self.end - timedelta(hours=1)
        )
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
        self._routine_activity(profile, report + timedelta(hours=4), self.end)

    def _scenario_legitimate_lookalike(self) -> None:
        """Legitimate behaviour that mirrors the temporal takeovers above."""
        profile = self._create_account("legitimate_lookalike", min_age_days=120)
        moment = self._attack_time()
        self._routine_activity(profile, self.start, moment)
        variant = self.rng.choice(
            [
                "travel",
                "new_phone",
                "forgot_password",
                "gradual_changes",
                "small_burst",
                "long_inactivity",
            ]
        )
        base = profile.avg_amount
        resume = moment
        if variant == "travel":  # a week abroad: new networks, a new country, purchases
            town = self.rng.choice(_FOREIGN_TOWNS)
            t = moment
            for _ in range(self.rng.randint(3, 7)):
                net = _network(self._residential_ip(), _FOREIGN_RESIDENTIAL, town[1])
                _, session = self._login(
                    profile, t, profile.mobile_device or profile.primary_device, net
                )
                if self.rng.random() < 0.6:
                    self._purchase(
                        profile,
                        t + timedelta(minutes=9),
                        profile.mobile_device or profile.primary_device,
                        net,
                        session,
                        self._amount(base * self.rng.uniform(0.7, 2.0)),
                        ship=False,
                    )
                t += timedelta(days=1, hours=self.rng.randint(-4, 4))
            resume = t
        elif variant == "new_phone":  # new device, buys straight away, then keeps using it
            phone = self._device(DeviceType.MOBILE)
            profile.mobile_device = phone
            _, session = self._login(profile, moment, phone, profile.home_network)
            self._purchase(
                profile,
                moment + timedelta(minutes=4),
                phone,
                profile.home_network,
                session,
                self._amount(base * self.rng.uniform(1.0, 2.5)),
            )
            resume = moment + timedelta(hours=2)
        elif variant == "forgot_password":  # failed logins on several days, then success
            device, net = profile.primary_device, profile.home_network
            t = moment
            for _ in range(self.rng.randint(2, 4)):
                for _ in range(self.rng.randint(1, 3)):
                    self._failed_login(
                        profile, t + timedelta(minutes=self.rng.randint(0, 20)), device, net
                    )
                t += timedelta(days=1, hours=self.rng.randint(-3, 3))
            self._emit(
                EventType.PASSWORD_RESET,
                t,
                profile.user_id,
                {"method": "email_link", "network": net, "device": device.context},
                device=device.identifier,
            )
            _, session = self._login(profile, t + timedelta(minutes=3), device, net)
            self._purchase(
                profile,
                t + timedelta(minutes=10),
                device,
                net,
                session,
                self._amount(base * self.rng.uniform(0.8, 2.0)),
            )
            resume = t + timedelta(hours=1)
        elif variant == "gradual_changes":  # new address, then a new card, then a purchase
            device, net = profile.primary_device, profile.home_network
            _, session = self._login(profile, moment, device, net)
            address = self._add_address(profile, moment + timedelta(minutes=5), device, session)
            t = moment + timedelta(days=self.rng.uniform(1.0, 2.5))
            _, session = self._login(profile, t, device, net)
            pm_id = self._add_card(profile, t + timedelta(minutes=4), device, session)
            buy_at = t + timedelta(days=self.rng.uniform(1.0, 2.5))
            _, session = self._login(profile, buy_at, device, net)
            self._purchase(
                profile,
                buy_at + timedelta(minutes=8),
                device,
                net,
                session,
                self._amount(base * self.rng.uniform(1.0, 2.5)),
                address_id=address,
                pm_id=pm_id,
            )
            resume = buy_at + timedelta(hours=1)
        elif variant == "small_burst":  # several small purchases within an hour
            device = profile.mobile_device or profile.primary_device
            _, session = self._login(profile, moment, device, profile.home_network)
            t = moment
            for _ in range(self.rng.randint(3, 6)):
                t += timedelta(minutes=self.rng.randint(3, 15))
                self._purchase(
                    profile,
                    t,
                    device,
                    profile.home_network,
                    session,
                    self._amount(base * self.rng.uniform(0.2, 0.8)),
                    ship=False,
                )
            resume = t + timedelta(hours=1)
        else:  # long_inactivity: silent for 1-2 months, then a large purchase
            back = moment + timedelta(days=self.rng.randint(30, 60))
            back = min(back, self.end - timedelta(days=2))
            _, session = self._login(profile, back, profile.primary_device, profile.home_network)
            self._purchase(
                profile,
                back + timedelta(minutes=7),
                profile.primary_device,
                profile.home_network,
                session,
                self._amount(base * self.rng.uniform(3.0, 6.0)),
            )
            resume = back + timedelta(hours=1)
        self._routine_activity(profile, resume, self.end)

    @staticmethod
    def allocate(n_users: int, fraud_multiplier: float = 1.0) -> dict[str, int]:
        """Users per scenario. ``fraud_multiplier`` scales the fraud scenarios (prevalence
        experiments); ``normal`` absorbs the difference."""
        if n_users < len(SCENARIOS):
            raise ValueError(f"need at least {len(SCENARIOS)} users (one per scenario)")
        weights = {
            s: w * (fraud_multiplier if s in FRAUD_SCENARIOS else 1.0)
            for s, w in SCENARIO_WEIGHTS.items()
        }
        fraud = sum(w for s, w in weights.items() if s in FRAUD_SCENARIOS)
        if fraud > 0.85:
            raise ValueError("fraud_multiplier too high: fraud scenarios would exceed 85%")
        others = [s for s in weights if s not in FRAUD_SCENARIOS and s != "normal"]
        room = 0.95 - fraud  # keep at least 5% "normal" customers
        total = sum(weights[s] for s in others)
        if total > room:  # shrink the other legitimate scenarios proportionally
            for s in others:
                weights[s] *= room / total
        counts = {s: max(1, int(w * n_users)) for s, w in weights.items()}
        counts["normal"] += n_users - sum(counts.values())
        if counts["normal"] < 1:
            raise ValueError("user allocation failed")
        return counts

    def generate(self, n_users: int) -> SyntheticDataset:
        counts = self.allocate(n_users, self.fraud_multiplier)
        for _ in range(counts["normal"]):
            self._scenario_normal()
        for _ in range(counts["legitimate_vpn"]):
            self._scenario_legitimate_vpn()
        for i in range(counts["shared_network"]):  # offices of (at least) two staff
            self._scenario_shared_network(self._office_ips[(i // 2) % len(self._office_ips)])
        for _ in range(counts["new_home_address"]):
            self._scenario_new_home_address()
        for _ in range(counts["account_takeover"]):
            self._scenario_account_takeover()
        for _ in range(counts["new_customer"]):
            self._scenario_new_customer()
        for _ in range(counts["new_account_fraud"]):
            self._scenario_new_account_fraud()
        for _ in range(counts["friendly_fraud"]):
            self._scenario_friendly_fraud()
        for _ in range(counts["slow_account_takeover"]):
            self._scenario_slow_account_takeover()
        for _ in range(counts["legitimate_lookalike"]):
            self._scenario_legitimate_lookalike()
        victims = []
        for _ in range(counts["suspicious_velocity"]):
            victim = self._create_account(
                "suspicious_velocity", min_age_days=self.activity_days + 10
            )
            self._routine_activity(victim, self.start, self.end)
            victims.append(victim)
        # One campaign per ~6 victims, spread across the window.
        for i in range(0, len(victims), 6):
            self._credential_stuffing_campaign(victims[i : i + 6])

        ordered = [e for _, _, e in sorted(self._events, key=lambda x: (x[0], x[1]))]
        return SyntheticDataset(
            events=ordered,
            fraud_transaction_ids=set(self._fraud_txns),
            scenario_counts=counts,
            reference_time=self.end,
        )
