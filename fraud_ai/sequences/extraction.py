"""Point-in-time sequence extraction.

For a scored event at time ``T`` with user ``u``:

1. **Load** the events of ``u`` with ``T - lookback_days <= occurred_at < T``, ordered by
   ``(occurred_at, event_id)``. Only rows of the append-only ``events`` table are read:
   * each event's immutable payload (network intelligence and hashed IP, device context,
     amounts, address and payment-method ids);
   * ``events.device_id``, as an identity for the *known* flags.

   Mutable state, such as device trust flags, login counters, address ``is_active`` or
   transaction status, is never read. A later decision or label therefore cannot change a
   historical sequence (tested by mutation).
2. **Replay** those events in order. Before updating the state with an event, encode it
   using only what was known at that moment:
   * whether its device, network, address and payment method were already known;
   * how old they were;
   * whether the device, ASN or country changed from the previous event;
   * the time since the previous event.
3. **Emit** the last ``max_events`` events (optionally only those within
   ``max_age_days``), then the scored event itself as the final position, flagged
   ``is_target``. The scored event's own outcome (approval, decline, later chargeback) is
   *after* ``T`` and never appears.

Batch extraction (the dataset builder) and single-event extraction (scoring, the CLI) call
the same function on the same event slice, so they produce identical sequences (tested).
"""

from __future__ import annotations

import bisect
import contextlib
import hashlib
import math
import uuid
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import numpy.typing as npt
from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import EventRecord, User
from fraud_ai.sequences.definition import (
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    SequenceDefinition,
    vocabulary,
)
from fraud_ai.utils.time import ensure_utc

SECURITY_EVENTS = frozenset(
    {"PASSWORD_RESET", "EMAIL_CHANGED", "PHONE_CHANGED", "MFA_ENABLED", "MFA_DISABLED"}
)
LABEL_EVENTS = frozenset({"CHARGEBACK", "FRAUD_CONFIRMED"})
ADDRESS_EVENTS = frozenset({"ADDRESS_ADDED", "ADDRESS_CHANGED"})
NUMERIC_NAMES = tuple(name for name, _ in NUMERIC_FEATURES)
CATEGORICAL_NAMES = tuple(CATEGORICAL_FEATURES)
VOCABULARIES = {name: vocabulary(values) for name, values in CATEGORICAL_FEATURES.items()}
BATCH = 400


class SequenceError(FraudAIError):
    pass


@dataclass(frozen=True)
class RawEvent:
    """An immutable view of one ``events`` row (no mutable table is consulted)."""

    event_id: uuid.UUID
    event_type: str
    occurred_at: datetime
    user_id: uuid.UUID | None
    device_id: uuid.UUID | None
    metadata: dict[str, Any]

    @classmethod
    def from_record(cls, row: EventRecord) -> RawEvent:
        return cls(
            row.event_id,
            str(row.event_type.value if hasattr(row.event_type, "value") else row.event_type),
            ensure_utc(row.occurred_at),
            row.user_id,
            row.device_id,
            dict(row.metadata_json or {}),
        )

    @property
    def key(self) -> tuple[datetime, str]:
        return (self.occurred_at, str(self.event_id))


@dataclass
class _State:
    devices: dict[uuid.UUID, datetime] = field(default_factory=dict)
    networks: set[str] = field(default_factory=set)
    addresses: dict[str, datetime] = field(default_factory=dict)
    payment_methods: dict[str, datetime] = field(default_factory=dict)
    last_device: uuid.UUID | None = None
    last_asn: Any = None
    last_country: Any = None
    last_time: datetime | None = None

    def update(self, ev: RawEvent) -> None:
        md = ev.metadata
        if ev.device_id is not None:
            self.devices.setdefault(ev.device_id, ev.occurred_at)
            self.last_device = ev.device_id
        net = md.get("network")
        if isinstance(net, dict):
            if net.get("ip_hash"):
                self.networks.add(str(net["ip_hash"]))
            self.last_asn, self.last_country = net.get("asn"), net.get("country")
        for key in ("address_id", "shipping_address_id"):
            if (a := md.get(key)) and (ev.event_type in ADDRESS_EVENTS or key != "address_id"):
                self.addresses.setdefault(str(a), ev.occurred_at)
        if pm := md.get("payment_method_id"):
            self.payment_methods.setdefault(str(pm), ev.occurred_at)
        self.last_time = ev.occurred_at


def _log1p_days(later: datetime, earlier: datetime) -> float:
    return math.log1p(max(0.0, (later - earlier).total_seconds()) / 86400)


def _token(name: str, value: Any) -> int:
    vocab = VOCABULARIES[name]
    if value is None:
        return vocab["none"]
    return vocab.get(str(value), vocab["<unk>"])


def _encode(
    ev: RawEvent,
    state: _State,
    target_time: datetime,
    created: datetime | None,
    lookback_start: datetime,
    is_target: bool,
) -> tuple[list[int], list[float]]:
    md = ev.metadata
    net = md.get("network") if isinstance(md.get("network"), dict) else None
    dev = md.get("device") if isinstance(md.get("device"), dict) else None
    t = ev.occurred_at
    previous = state.last_time or lookback_start
    f: dict[str, float] = dict.fromkeys(NUMERIC_NAMES, 0.0)
    f["log_minutes_since_previous"] = math.log1p(max(0.0, (t - previous).total_seconds()) / 60)
    f["log_hours_before_target"] = math.log1p(max(0.0, (target_time - t).total_seconds()) / 3600)
    f["log_account_age_days"] = _log1p_days(t, created) if created else 0.0
    f["is_target"] = 1.0 if is_target else 0.0
    if (amount := md.get("amount")) is not None:
        with contextlib.suppress(TypeError, ValueError):  # malformed amounts stay absent
            f["has_amount"], f["log_amount"] = 1.0, math.log1p(max(0.0, float(amount)))
    if ev.device_id is not None:
        f["has_device"] = 1.0
        first = state.devices.get(ev.device_id)
        f["device_known"] = 1.0 if first is not None else 0.0
        f["log_device_age_days"] = _log1p_days(t, first) if first else 0.0
        f["device_changed"] = float(
            state.last_device is not None and state.last_device != ev.device_id
        )
    if net is not None:
        f["has_network"] = 1.0
        f["network_known"] = float(str(net.get("ip_hash")) in state.networks)
        f["asn_changed"] = float(state.last_asn is not None and net.get("asn") != state.last_asn)
        f["country_changed"] = float(
            state.last_country is not None and net.get("country") != state.last_country
        )
        f["vpn"] = float(net.get("is_known_vpn") is True)
        f["proxy_or_tor"] = float(net.get("is_known_proxy") is True or net.get("is_tor") is True)
        f["datacenter"] = float(net.get("is_datacenter") is True)
        conf = net.get("proxy_confidence")
        f["proxy_confidence"] = float(conf) if isinstance(conf, int | float) else 0.0
    f["mfa_used"] = float(md.get("mfa_used") is True)
    address = md.get("shipping_address_id") or (
        md.get("address_id") if ev.event_type in ADDRESS_EVENTS else None
    )
    if address:
        f["has_address"] = 1.0
        first_addr = state.addresses.get(str(address))
        f["address_known"] = 1.0 if first_addr is not None else 0.0
        f["log_address_age_days"] = _log1p_days(t, first_addr) if first_addr else 0.0
    if (pm := md.get("payment_method_id")) and ev.event_type != "PAYMENT_METHOD_ADDED":
        f["has_payment_method"] = 1.0
        first_pm = state.payment_methods.get(str(pm))
        f["payment_method_known"] = 1.0 if first_pm is not None else 0.0
        f["log_payment_method_age_days"] = _log1p_days(t, first_pm) if first_pm else 0.0
    f["is_security_event"] = float(ev.event_type in SECURITY_EVENTS)
    f["is_label_event"] = float(ev.event_type in LABEL_EVENTS)
    tokens = [
        VOCABULARIES["event_type"].get(ev.event_type, 1),
        _token("network_type", None if net is None else net.get("network_type")),
        _token("device_type", None if dev is None else dev.get("device_type")),
        _token("auth_method", md.get("auth_method")),
        _token("channel", md.get("channel")),
    ]
    return tokens, [f[name] for name in NUMERIC_NAMES]


def encode_sequence(
    definition: SequenceDefinition,
    history: Sequence[RawEvent],
    target: RawEvent,
    created: datetime | None,
) -> tuple[npt.NDArray[np.int64], npt.NDArray[np.float32], int]:
    """``history`` must be the user's events before ``target`` (any superset is filtered)."""
    T = target.occurred_at
    lookback_start = T - timedelta(days=definition.lookback_days)
    context = sorted(
        (e for e in history if lookback_start <= e.occurred_at < T), key=lambda e: e.key
    )
    if definition.max_age_days is not None:
        oldest = T - timedelta(days=definition.max_age_days)
        eligible = [i for i, e in enumerate(context) if e.occurred_at >= oldest]
    else:
        eligible = list(range(len(context)))
    window = set(eligible[-definition.max_events :])
    state = _State()
    rows: list[tuple[list[int], list[float]]] = []
    for i, ev in enumerate(context):
        if i in window:
            rows.append(_encode(ev, state, T, created, lookback_start, False))
        state.update(ev)
    rows.append(_encode(target, state, T, created, lookback_start, True))
    L, C, F = definition.length, len(CATEGORICAL_NAMES), len(NUMERIC_NAMES)
    cat = np.zeros((L, C), dtype=np.int64)
    num = np.zeros((L, F), dtype=np.float32)
    for j, (tokens, values) in enumerate(rows):
        cat[j], num[j] = tokens, values
    return cat, num, len(rows)


@dataclass(frozen=True)
class SequenceBatch:
    """Right-padded sequences: positions ``[0, length)`` are valid, the rest is padding."""

    definition: SequenceDefinition
    categorical: npt.NDArray[np.int64]  # [N, L, C] vocabulary indices (0 = padding)
    numeric: npt.NDArray[np.float32]  # [N, L, F]
    lengths: npt.NDArray[np.int64]  # [N], >= 1 (the scored event is always present)

    def __len__(self) -> int:
        return len(self.lengths)

    def take(self, indices: Sequence[int] | npt.NDArray[np.int_]) -> SequenceBatch:
        idx = np.asarray(indices, dtype=np.int64)
        return SequenceBatch(
            self.definition, self.categorical[idx], self.numeric[idx], self.lengths[idx]
        )

    def mask(self) -> npt.NDArray[np.bool_]:
        return np.arange(self.definition.length)[None, :] < self.lengths[:, None]

    def digest(self) -> str:
        """Reproducibility digest of the exact model inputs (and their definition)."""
        h = hashlib.sha256(self.definition.fingerprint().encode())
        for array in (self.categorical, self.numeric, self.lengths):
            h.update(np.ascontiguousarray(array).tobytes())
        return h.hexdigest()

    def decode(self, row: int) -> list[dict[str, Any]]:
        """Human-readable positions of one sequence (inspection only)."""
        inverse = {
            name: {i: tok for tok, i in VOCABULARIES[name].items()} for name in CATEGORICAL_NAMES
        }
        out = []
        for j in range(int(self.lengths[row])):
            entry: dict[str, Any] = {
                name: inverse[name][int(self.categorical[row, j, k])]
                for k, name in enumerate(CATEGORICAL_NAMES)
            }
            entry.update(
                {
                    name: round(float(self.numeric[row, j, k]), 4)
                    for k, name in enumerate(NUMERIC_NAMES)
                }
            )
            out.append(entry)
        return out


def _stack(
    definition: SequenceDefinition,
    items: list[tuple[npt.NDArray[np.int64], npt.NDArray[np.float32], int]],
) -> SequenceBatch:
    L, C, F = definition.length, len(CATEGORICAL_NAMES), len(NUMERIC_NAMES)
    if not items:
        return SequenceBatch(
            definition,
            np.zeros((0, L, C), np.int64),
            np.zeros((0, L, F), np.float32),
            np.zeros(0, np.int64),
        )
    return SequenceBatch(
        definition,
        np.stack([c for c, _, _ in items]),
        np.stack([n for _, n, _ in items]),
        np.asarray([n for _, _, n in items], dtype=np.int64),
    )


def _load_events(session: Session, event_ids: Iterable[uuid.UUID]) -> dict[uuid.UUID, RawEvent]:
    ids = list(event_ids)
    out: dict[uuid.UUID, RawEvent] = {}
    for i in range(0, len(ids), BATCH):
        for row in session.scalars(
            select(EventRecord).where(EventRecord.event_id.in_(ids[i : i + BATCH]))
        ):
            out[row.event_id] = RawEvent.from_record(row)
    return out


def _load_histories(
    session: Session, spans: dict[uuid.UUID, tuple[datetime, datetime]]
) -> dict[uuid.UUID, list[RawEvent]]:
    """Events of each user in ``[start, end)``, ordered by (occurred_at, event_id)."""
    out: dict[uuid.UUID, list[RawEvent]] = defaultdict(list)
    users = list(spans)
    for i in range(0, len(users), 50):
        chunk = users[i : i + 50]
        start = min(spans[u][0] for u in chunk)
        end = max(spans[u][1] for u in chunk)
        rows = session.scalars(
            select(EventRecord).where(
                EventRecord.user_id.in_(chunk),
                EventRecord.occurred_at >= start,
                EventRecord.occurred_at < end,
            )
        )
        for row in rows:
            ev = RawEvent.from_record(row)
            s, e = spans[ev.user_id]  # type: ignore[index]
            if s <= ev.occurred_at < e:
                out[ev.user_id].append(ev)  # type: ignore[index]
    for events in out.values():
        events.sort(key=lambda e: e.key)
    return out


def _created(session: Session, users: Iterable[uuid.UUID]) -> dict[uuid.UUID, datetime]:
    ids = list(users)
    out: dict[uuid.UUID, datetime] = {}
    for i in range(0, len(ids), BATCH):
        for uid, created in session.execute(
            select(User.user_id, User.account_created_at).where(
                User.user_id.in_(ids[i : i + BATCH])
            )
        ):
            out[uid] = ensure_utc(created)
    return out


def build_sequences(
    session: Session, event_ids: Sequence[uuid.UUID], definition: SequenceDefinition
) -> SequenceBatch:
    """Sequences for many scored events, in the order given (the dataset order)."""
    targets = _load_events(session, event_ids)
    if missing := [e for e in event_ids if e not in targets]:
        raise SequenceError(f"unknown event {missing[0]}")
    lookback = timedelta(days=definition.lookback_days)
    spans: dict[uuid.UUID, tuple[datetime, datetime]] = {}
    for ev in targets.values():
        if ev.user_id is None:
            continue
        s, e = ev.occurred_at - lookback, ev.occurred_at
        if ev.user_id in spans:
            s, e = min(s, spans[ev.user_id][0]), max(e, spans[ev.user_id][1])
        spans[ev.user_id] = (s, e)
    histories = _load_histories(session, spans)
    created = _created(session, spans)
    times = {u: [e.occurred_at for e in evs] for u, evs in histories.items()}
    items = []
    for event_id in event_ids:
        target = targets[event_id]
        history: list[RawEvent] = []
        if target.user_id is not None:
            events = histories.get(target.user_id, [])
            ts = times.get(target.user_id, [])
            lo = bisect.bisect_left(ts, target.occurred_at - lookback)
            hi = bisect.bisect_left(ts, target.occurred_at)
            history = events[lo:hi]
        items.append(
            encode_sequence(
                definition, history, target, created.get(target.user_id) if target.user_id else None
            )
        )
    return _stack(definition, items)


def build_sequence(
    session: Session, event_id: uuid.UUID, definition: SequenceDefinition
) -> SequenceBatch:
    """One scored event (scoring and the CLI); identical to the batch path."""
    return build_sequences(session, [event_id], definition)
