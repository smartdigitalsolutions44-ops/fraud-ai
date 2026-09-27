"""The incoming real-time event contract (``realtime-event-1``).

Builds on the Stage 1 envelope (:class:`fraud_ai.core.events.Event`) and adds what a live
decision needs:

| Field | Rule |
|---|---|
| `event_id` | **required** (never generated), because idempotency depends on it |
| `event_type` | a supported `EventType` |
| `timestamp` | the *event time*: timezone-aware, at most `max_clock_skew` after arrival |
| `user_id` | the user reference; required except for anonymous login attempts |
| `session_id` | required for decision-point events (logins, transaction creation) |
| `metadata` | the payload, validated against the per-type schema; forbidden data is refused |
| `schema_version` | **required** and supported |
| `arrival_time` | *replay only*: a recorded arrival time; live scoring refuses it |

Malformed, unsupported or forbidden-data events are rejected with a
:class:`EventContractError`. Error messages name fields, never values.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from fraud_ai.core.enums import EventType
from fraud_ai.core.events import Event, parse_event
from fraud_ai.core.exceptions import EventValidationError
from fraud_ai.utils.time import ensure_utc

CONTRACT_VERSION = "realtime-event-1"
REQUIRED_FIELDS = ("event_id", "event_type", "timestamp", "schema_version", "source")
SESSION_REQUIRED = frozenset(
    {
        EventType.LOGIN_ATTEMPT,
        EventType.LOGIN_SUCCESS,
        EventType.LOGIN_FAILURE,
        EventType.TRANSACTION_CREATED,
    }
)
DECISION_KINDS: dict[EventType, str] = {
    EventType.LOGIN_ATTEMPT: "login",
    EventType.LOGIN_SUCCESS: "login",
    EventType.LOGIN_FAILURE: "login",
    EventType.TRANSACTION_CREATED: "transaction",
}
DEFAULT_MAX_CLOCK_SKEW = timedelta(minutes=5)


class EventContractError(EventValidationError):
    """The incoming event violates the real-time contract."""


@dataclass(frozen=True)
class IncomingEvent:
    event: Event
    arrival_time: datetime | None  # set only for replayed historical events

    @property
    def decision_kind(self) -> str | None:
        return DECISION_KINDS.get(self.event.event_type)


def parse_incoming(data: Any, *, allow_arrival_time: bool = False) -> IncomingEvent:
    if not isinstance(data, dict):
        raise EventContractError("an event must be a JSON object")
    missing = [f for f in REQUIRED_FIELDS if f not in data or data[f] in (None, "")]
    if missing:
        raise EventContractError(f"missing required field(s): {', '.join(missing)}")
    body = dict(data)
    raw_arrival = body.pop("arrival_time", None)
    if raw_arrival is not None and not allow_arrival_time:
        raise EventContractError(
            "arrival_time is set by the platform on receipt; a client may not supply it "
            "(it is accepted only when replaying recorded events)"
        )
    try:
        event = parse_event(body)
    except EventValidationError as exc:
        raise EventContractError(str(exc)) from None
    if event.event_type in SESSION_REQUIRED and not event.session_id:
        raise EventContractError(f"{event.event_type.value} requires session_id")
    arrival = None
    if raw_arrival is not None:
        try:
            arrival = ensure_utc(datetime.fromisoformat(str(raw_arrival)))
        except ValueError:
            raise EventContractError("arrival_time is not an ISO-8601 timestamp") from None
    return IncomingEvent(event, arrival)


def check_clock(
    event: Event, arrival: datetime, max_skew: timedelta = DEFAULT_MAX_CLOCK_SKEW
) -> None:
    if event.timestamp > arrival + max_skew:
        raise EventContractError(
            f"event time is more than {max_skew} after its arrival time; refusing an event "
            "from the future"
        )
