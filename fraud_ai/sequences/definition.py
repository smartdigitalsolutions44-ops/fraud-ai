"""Versioned sequence definitions.

A sequence definition fixes everything about how a scored event becomes a model input:

* **Window:** the last ``max_events`` events of the user strictly before the scoring point.
  Optionally, only events from the last ``max_age_days`` are kept.
* **Lookback:** ``lookback_days`` of history is read to decide whether a device, network,
  address or payment method was already *known*. Only the window itself is emitted.
* **Vocabularies:** the categorical vocabularies (embedding indices).
* **Numeric features:** their order and their time transforms.

The definition is data. Its SHA-256 fingerprint is recorded with every sequence model, and a
model refuses a definition whose fingerprint differs from the one it was trained with.
Changing anything means a new version; a released version is never edited.

The vocabularies hold **event and context types only**: event type, network type, device
type, authentication method and channel. User ids, IP addresses, device ids, addresses and
payment tokens are never tokens, so no embedding can become a lookup table for
individual customers.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from fraud_ai.core.enums import AuthMethod, DeviceType, EventType, NetworkType, TransactionChannel

SEQUENCE_VERSION = "fraud-sequence-1.0.0"
EVENT_SCHEMA_VERSION = 1
PAD, UNKNOWN = "<pad>", "<unk>"  # index 0 and 1 of every vocabulary

EVENT_TYPES: tuple[str, ...] = tuple(e.value for e in EventType)
# "none" = the event carries no such context (e.g. a transaction has no auth method).
NETWORK_TYPES: tuple[str, ...] = ("none", *(e.value for e in NetworkType))
DEVICE_TYPES: tuple[str, ...] = ("none", *(e.value for e in DeviceType))
AUTH_METHODS: tuple[str, ...] = ("none", *(e.value for e in AuthMethod))
CHANNELS: tuple[str, ...] = ("none", *(e.value for e in TransactionChannel))

# Numeric features per event (all known at that event's time) and their transforms.
NUMERIC_FEATURES: tuple[tuple[str, str], ...] = (
    ("log_minutes_since_previous", "log1p(minutes since the previous event in the window)"),
    ("log_hours_before_target", "log1p(hours between this event and the scoring point)"),
    ("log_account_age_days", "log1p(days since the account was created, at this event)"),
    ("is_target", "1 for the scored event itself (always the last position)"),
    ("has_amount", "1 if the event carries a transaction amount"),
    ("log_amount", "log1p(amount in major units)"),
    ("has_device", "1 if the event came from an identified device"),
    ("device_known", "device seen for this user before this event (within the lookback)"),
    ("log_device_age_days", "log1p(days since this user first used the device)"),
    ("device_changed", "device differs from the previous identified device"),
    ("has_network", "1 if network intelligence is present"),
    ("network_known", "network (keyed IP hash) seen for this user before"),
    ("asn_changed", "ASN differs from the previous networked event"),
    ("country_changed", "country differs from the previous networked event"),
    ("vpn", "known VPN"),
    ("proxy_or_tor", "known proxy or Tor"),
    ("datacenter", "datacenter network"),
    ("proxy_confidence", "proxy confidence (0 if absent)"),
    ("mfa_used", "login used MFA"),
    ("has_address", "transaction ships to an address, or the event adds one"),
    ("address_known", "the shipping address was added or used before this event"),
    ("log_address_age_days", "log1p(days since the address first appeared)"),
    ("has_payment_method", "transaction names a payment method"),
    ("payment_method_known", "the payment method was added or used before this event"),
    ("log_payment_method_age_days", "log1p(days since the payment method first appeared)"),
    ("is_security_event", "password reset, email/phone/MFA change"),
    ("is_label_event", "chargeback or fraud confirmation known at this time"),
)

CATEGORICAL_FEATURES: dict[str, tuple[str, ...]] = {
    "event_type": EVENT_TYPES,
    "network_type": NETWORK_TYPES,
    "device_type": DEVICE_TYPES,
    "auth_method": AUTH_METHODS,
    "channel": CHANNELS,
}


def vocabulary(values: tuple[str, ...]) -> dict[str, int]:
    return {PAD: 0, UNKNOWN: 1, **{v: i + 2 for i, v in enumerate(values)}}


@dataclass(frozen=True)
class SequenceDefinition:
    # 16 was chosen on the 1,000-user benchmark: validation PR-AUC 0.809 vs 0.815 (32) and
    # 0.816 (64) - within noise - at a fraction of the training and inference cost.
    max_events: int = 16
    max_age_days: float | None = None
    lookback_days: float = 365.0
    version: str = SEQUENCE_VERSION
    event_schema_version: int = EVENT_SCHEMA_VERSION
    padding: str = field(default="right", init=False)  # valid events first, padding after

    def __post_init__(self) -> None:
        if not 1 <= self.max_events <= 512:
            raise ValueError("max_events must be between 1 and 512")
        if self.max_age_days is not None and self.max_age_days <= 0:
            raise ValueError("max_age_days must be positive")
        if self.lookback_days <= 0:
            raise ValueError("lookback_days must be positive")
        if self.max_age_days is not None and self.max_age_days > self.lookback_days:
            raise ValueError("max_age_days cannot exceed lookback_days")
        if self.version != SEQUENCE_VERSION:
            raise ValueError(f"unsupported sequence version {self.version!r}")

    @property
    def length(self) -> int:
        """Positions per sequence: the history window plus the scored event."""
        return self.max_events + 1

    def describe(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "numeric_features": [
                {"name": name, "transform": transform} for name, transform in NUMERIC_FEATURES
            ],
            "vocabularies": {name: vocabulary(v) for name, v in CATEGORICAL_FEATURES.items()},
            "ordering": "occurred_at, then event_id; strictly before the scoring point",
            "target": "the scored event is appended as the last valid position",
        }

    def fingerprint(self) -> str:
        blob = json.dumps(self.describe(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_events": self.max_events,
            "max_age_days": self.max_age_days,
            "lookback_days": self.lookback_days,
            "version": self.version,
            "event_schema_version": self.event_schema_version,
            "fingerprint": self.fingerprint(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SequenceDefinition:
        definition = cls(
            max_events=int(data["max_events"]),
            max_age_days=data.get("max_age_days"),
            lookback_days=float(data["lookback_days"]),
            version=data["version"],
            event_schema_version=int(data["event_schema_version"]),
        )
        if "fingerprint" in data and data["fingerprint"] != definition.fingerprint():
            raise ValueError(
                "sequence definition fingerprint differs from this build's "
                f"{definition.version} (the schema or vocabularies changed)"
            )
        return definition
