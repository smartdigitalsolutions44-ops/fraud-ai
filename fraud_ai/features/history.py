"""Point-in-time history queries for one scoring context.

Rules enforced by every query in this module:

* **Upper bound** - only rows with their timestamp ``<= :as_of`` are read.
* **Self-exclusion** - the scored event (and its transaction) never counts as its own
  history, even when ``as_of`` is later than the event.
* **No mutable state** - entity counters, ``last_seen_at``, ``is_trusted``, current intel
  and ``transactions.status`` are never read; everything is derived from timestamped rows.
* **Aggregation in the database** - each group of features is one aggregate query with
  conditional counts, so the number of queries per event is constant, independent of how
  much history an account has (verified by a test).

Statements are built once per shape (``functools.cache``) with bind parameters and reused
for every event; only parameter values change. Results are cached per context because
several feature categories share them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from functools import cache, cached_property
from typing import Any, TypeAlias

from sqlalchemy import (
    ColumnElement,
    Select,
    Uuid,
    and_,
    bindparam,
    case,
    distinct,
    false,
    func,
    or_,
    select,
    true,
)
from sqlalchemy.orm import Session

from fraud_ai.core.enums import (
    LabelSource,
    LabelValue,
    LoginOutcome,
    NetworkType,
    SecurityEventType,
    TransactionDecision,
)
from fraud_ai.database.models import (
    Address,
    EventRecord,
    FraudLabel,
    LoginEvent,
    NetworkEvent,
    PaymentMethod,
    SecurityEvent,
    Transaction,
)
from fraud_ai.features.context import ScoringContext
from fraud_ai.features.windows import (
    RECENT_WINDOW,
    W1H,
    W5M,
    W7D,
    W15M,
    W24H,
    W30D,
    count_if,
    in_window_param,
    lower_param,
    upto_param,
    window_params,
)

# Any-row SELECT (SQLAlchemy 2.1 ``Select`` is variadic over its column types).
AnySelect: TypeAlias = Select[*tuple[Any, ...]]

LOGIN_WINDOWS = (W5M, W15M, W1H, W24H, W7D, W30D)
FAILED_LOGIN_WINDOWS = (W5M, W15M, W1H)
TRANSACTION_WINDOWS = (W5M, W1H, W24H, W7D, W30D)


def _p(name: str) -> Any:
    return bindparam(name, type_=Uuid()) if name != "currency" else bindparam(name)


def _int(value: Any) -> int:
    return int(value or 0)


def _not_event(column: Any) -> ColumnElement[bool]:
    return column != _p("event_id")  # type: ignore[no-any-return]


def _not_txn(has_txn: bool) -> ColumnElement[bool]:
    return Transaction.transaction_id != _p("txn_id") if has_txn else true()


def _decided(outcome: TransactionDecision) -> ColumnElement[bool]:
    return and_(Transaction.decision_outcome == outcome, upto_param(Transaction.decided_at))


# --------------------------------------------------------------------------- statements
@cache
def _security_stmt() -> AnySelect:
    S = SecurityEvent
    return (
        select(S.security_event_type, func.max(S.occurred_at))
        .where(S.user_id == _p("user_id"), upto_param(S.occurred_at))
        .group_by(S.security_event_type)
    )


@cache
def _user_logins_stmt(has_device: bool) -> AnySelect:
    L = LoginEvent
    success, failure = L.outcome == LoginOutcome.SUCCESS, L.outcome == LoginOutcome.FAILURE
    trust = (
        and_(L.device_id == _p("device_id"), success, L.mfa_used.is_(True))
        if has_device
        else false()
    )
    last_1h = in_window_param(L.occurred_at, W1H)
    return select(
        count_if(success),
        count_if(failure),
        *(count_if(in_window_param(L.occurred_at, w)) for w in LOGIN_WINDOWS),
        *(count_if(and_(failure, in_window_param(L.occurred_at, w))) for w in FAILED_LOGIN_WINDOWS),
        count_if(and_(success, last_1h)),
        func.count(distinct(case((last_1h, L.network_identity_id)))),
        func.count(distinct(case((last_1h, L.device_id)))),
        count_if(trust),
    ).where(L.user_id == _p("user_id"), upto_param(L.occurred_at), _not_event(L.event_id))


@cache
def _user_transactions_stmt(has_txn: bool) -> AnySelect:
    T = Transaction
    same = T.currency == _p("currency")
    return select(
        count_if(_decided(TransactionDecision.APPROVED)),
        count_if(_decided(TransactionDecision.DECLINED)),
        *(count_if(in_window_param(T.occurred_at, w)) for w in TRANSACTION_WINDOWS),
        count_if(same),
        func.coalesce(func.sum(case((same, T.amount_minor), else_=0)), 0),
        func.max(case((same, T.amount_minor))),
        func.coalesce(
            func.sum(
                case((and_(same, in_window_param(T.occurred_at, W24H)), T.amount_minor), else_=0)
            ),
            0,
        ),
        func.max(T.occurred_at),
    ).where(T.user_id == _p("user_id"), upto_param(T.occurred_at), _not_txn(has_txn))


@cache
def _previous_issuer_stmt(has_txn: bool) -> AnySelect:
    T, P = Transaction, PaymentMethod
    return (
        select(T.payment_method_id, P.issuer_country)
        .outerjoin(P, P.payment_method_id == T.payment_method_id)
        .where(T.user_id == _p("user_id"), upto_param(T.occurred_at), _not_txn(has_txn))
        .order_by(T.occurred_at.desc(), T.transaction_id.desc())
        .limit(1)
    )


@cache
def _labels_stmt(has_txn: bool) -> AnySelect:
    FL = FraudLabel
    conditions: list[ColumnElement[bool]] = [
        FL.user_id == _p("user_id"),
        upto_param(FL.labelled_at),
        or_(FL.event_id.is_(None), FL.event_id != _p("event_id")),
    ]
    if has_txn:
        conditions.append(or_(FL.transaction_id.is_(None), FL.transaction_id != _p("txn_id")))
    chargeback = FL.label_source == LabelSource.CHARGEBACK
    return select(
        count_if(chargeback), count_if(and_(FL.label == LabelValue.FRAUD, ~chargeback))
    ).where(*conditions)


@cache
def _device_events_stmt(has_user: bool) -> AnySelect:
    E = EventRecord
    this_user = E.user_id == _p("user_id") if has_user else false()
    other_user = E.user_id != _p("user_id") if has_user else E.user_id.is_not(None)
    return select(
        func.count(),
        func.count(distinct(E.user_id)),
        func.count(distinct(case((other_user, E.user_id)))),
        func.count(distinct(case((in_window_param(E.occurred_at, W24H), E.user_id)))),
        func.max(E.occurred_at),
        func.min(case((this_user, E.occurred_at))),
        count_if(this_user),
    ).where(E.device_id == _p("device_id"), upto_param(E.occurred_at), _not_event(E.event_id))


@cache
def _device_logins_stmt() -> AnySelect:
    L = LoginEvent
    return select(
        count_if(L.outcome == LoginOutcome.SUCCESS), count_if(L.outcome == LoginOutcome.FAILURE)
    ).where(L.device_id == _p("device_id"), upto_param(L.occurred_at), _not_event(L.event_id))


@cache
def _network_obs_stmt(has_user: bool) -> AnySelect:
    N = NetworkEvent
    other_user = N.user_id != _p("user_id") if has_user else N.user_id.is_not(None)
    return select(
        func.count(),
        func.min(N.observed_at),
        func.count(distinct(N.user_id)),
        func.count(distinct(case((other_user, N.user_id)))),
        func.count(distinct(case((in_window_param(N.observed_at, W1H), N.user_id)))),
    ).where(
        N.network_identity_id == _p("identity"), upto_param(N.observed_at), _not_event(N.event_id)
    )


@cache
def _network_logins_stmt() -> AnySelect:
    L = LoginEvent
    failure = L.outcome == LoginOutcome.FAILURE
    return select(
        count_if(L.outcome == LoginOutcome.SUCCESS),
        count_if(failure),
        count_if(and_(failure, in_window_param(L.occurred_at, W1H))),
    ).where(
        L.network_identity_id == _p("identity"), upto_param(L.occurred_at), _not_event(L.event_id)
    )


@cache
def _previous_observation_stmt() -> AnySelect:
    N = NetworkEvent
    return (
        select(N.country, N.asn, N.network_type)
        .where(N.user_id == _p("user_id"), upto_param(N.observed_at), _not_event(N.event_id))
        .order_by(N.observed_at.desc(), N.network_event_id.desc())
        .limit(1)
    )


@cache
def _recent_network_values_stmt() -> AnySelect:
    N = NetworkEvent
    return (
        select(N.country, N.asn)
        .distinct()
        .where(N.user_id == _p("user_id"), in_window_param(N.observed_at, RECENT_WINDOW))
    )


@cache
def _before_recent_window_stmt() -> AnySelect:
    N = NetworkEvent
    return (
        select(N.country, N.asn, N.network_type)
        .where(N.user_id == _p("user_id"), N.observed_at <= lower_param(RECENT_WINDOW))
        .order_by(N.observed_at.desc(), N.network_event_id.desc())
        .limit(1)
    )


@cache
def _networks_per_account_stmt() -> AnySelect:
    N = NetworkEvent
    return select(func.count(distinct(N.network_identity_id))).where(
        N.user_id == _p("user_id"), upto_param(N.observed_at)
    )


@cache
def _user_devices_stmt() -> AnySelect:
    E = EventRecord
    first_seen = (
        select(E.device_id, func.min(E.occurred_at).label("first_seen"))
        .where(E.user_id == _p("user_id"), E.device_id.is_not(None), upto_param(E.occurred_at))
        .group_by(E.device_id)
        .subquery()
    )
    lower = lower_param(RECENT_WINDOW)
    return select(
        func.count(),
        count_if(first_seen.c.first_seen > lower),
        count_if(first_seen.c.first_seen <= lower),
    )


@cache
def _registered_stmt(model: type[Address] | type[PaymentMethod]) -> AnySelect:
    lower = lower_param(RECENT_WINDOW)
    return select(
        func.count(), count_if(model.added_at > lower), count_if(model.added_at <= lower)
    ).where(model.user_id == _p("user_id"), upto_param(model.added_at))


@cache
def _usage_stmt(column_name: str) -> AnySelect:
    T = Transaction
    column = getattr(T, column_name)
    return select(
        func.count(),
        count_if(_decided(TransactionDecision.APPROVED)),
        count_if(_decided(TransactionDecision.DECLINED)),
        func.max(T.occurred_at),
    ).where(column == _p("entity_id"), upto_param(T.occurred_at), _not_txn(True))


@cache
def _sharing_stmt(model: type[Address] | type[PaymentMethod], hash_column: str) -> AnySelect:
    return select(func.count(distinct(model.user_id))).where(
        getattr(model, hash_column) == bindparam("hash_value"),
        model.user_id != _p("user_id"),
        upto_param(model.added_at),
    )


@cache
def _source_count_user_stmt() -> AnySelect:
    E = EventRecord
    return select(func.count()).where(E.user_id == _p("user_id"), upto_param(E.occurred_at))


@cache
def _source_count_network_stmt() -> AnySelect:
    N = NetworkEvent
    return select(func.count()).where(
        N.network_identity_id == _p("identity"), upto_param(N.observed_at)
    )


# --------------------------------------------------------------------------- results
@dataclass(frozen=True)
class UserLogins:
    success_total: int
    failure_total: int
    last: dict[str, int]
    failed_last: dict[str, int]
    success_last_1h: int
    distinct_networks_1h: int
    distinct_devices_1h: int
    mfa_successes_on_device: int


@dataclass(frozen=True)
class UserTransactions:
    approved: int
    declined: int
    last: dict[str, int]
    same_currency_count: int
    same_currency_sum: int
    same_currency_max: int | None
    same_currency_value_24h: int
    last_occurred_at: datetime | None


@dataclass(frozen=True)
class DeviceHistory:
    prior_events: int
    accounts: int
    other_accounts: int
    accounts_24h: int
    last_seen: datetime | None
    first_for_user: datetime | None
    prior_for_user: int
    successful_logins: int
    failed_logins: int


@dataclass(frozen=True)
class NetworkHistory:
    prior_observations: int
    first_seen: datetime | None
    accounts: int
    other_accounts: int
    accounts_1h: int
    successful_logins: int
    failed_logins: int
    failed_logins_1h: int


@dataclass(frozen=True)
class PreviousObservation:
    country: str | None
    asn: int | None
    network_type: NetworkType


@dataclass(frozen=True)
class EntityCounts:
    """Rows registered by as_of, split around the recent window."""

    total: int
    in_recent_window: int
    before_recent_window: int


@dataclass(frozen=True)
class UsageCounts:
    orders: int
    approved: int
    declined: int
    last_used: datetime | None


class History:
    def __init__(self, session: Session, ctx: ScoringContext) -> None:
        self.s = session
        self.ctx = ctx
        self.as_of = ctx.as_of
        txn = ctx.transaction
        self._has_txn = txn is not None
        self._params: dict[str, Any] = {
            **window_params(ctx.as_of),
            "event_id": ctx.event_id,
            "user_id": ctx.user_id,
            "device_id": ctx.device_id,
            "identity": ctx.network.network_identity_id if ctx.network else None,
            "txn_id": txn.transaction_id if txn else None,
            "currency": txn.currency if txn else "",
        }

    def _run(self, stmt: AnySelect, **extra: Any) -> Any:
        return self.s.execute(stmt, {**self._params, **extra} if extra else self._params)

    # ------------------------------------------------------------------ account-scoped
    @cached_property
    def security_last(self) -> dict[SecurityEventType, datetime]:
        """Latest occurrence of each security event type by as_of."""
        return {kind: ts for kind, ts in self._run(_security_stmt()).all()}

    @cached_property
    def user_logins(self) -> UserLogins:
        vals = [_int(v) for v in self._run(_user_logins_stmt(self.ctx.device_id is not None)).one()]
        n, f = len(LOGIN_WINDOWS), len(FAILED_LOGIN_WINDOWS)
        rest = vals[2 + n + f :]
        return UserLogins(
            success_total=vals[0],
            failure_total=vals[1],
            last={w.name: v for w, v in zip(LOGIN_WINDOWS, vals[2 : 2 + n], strict=True)},
            failed_last={
                w.name: v
                for w, v in zip(FAILED_LOGIN_WINDOWS, vals[2 + n : 2 + n + f], strict=True)
            },
            success_last_1h=rest[0],
            distinct_networks_1h=rest[1],
            distinct_devices_1h=rest[2],
            mfa_successes_on_device=rest[3],
        )

    @cached_property
    def user_transactions(self) -> UserTransactions:
        row = self._run(_user_transactions_stmt(self._has_txn)).one()
        n = len(TRANSACTION_WINDOWS)
        # Layout: approved, declined, <n windows>, count, sum, max, value_24h, last.
        count, total, maximum, value_24h, last = row[2 + n : 7 + n]
        return UserTransactions(
            approved=_int(row[0]),
            declined=_int(row[1]),
            last={
                w.name: _int(v) for w, v in zip(TRANSACTION_WINDOWS, row[2 : 2 + n], strict=True)
            },
            same_currency_count=_int(count),
            same_currency_sum=_int(total),
            same_currency_max=int(maximum) if maximum is not None else None,
            same_currency_value_24h=_int(value_24h),
            last_occurred_at=last,
        )

    def median_same_currency(self, count: int) -> float | None:
        """Median of prior same-currency amounts via ORDER BY + OFFSET (portable)."""
        if not self._has_txn or count == 0:
            return None
        T = Transaction
        amounts = list(
            self.s.scalars(
                select(T.amount_minor)
                .where(
                    T.user_id == _p("user_id"),
                    upto_param(T.occurred_at),
                    _not_txn(True),
                    T.currency == _p("currency"),
                )
                .order_by(T.amount_minor, T.transaction_id)
                .offset((count - 1) // 2)
                .limit(2 if count % 2 == 0 else 1),
                self._params,
            )
        )
        return sum(amounts) / len(amounts)

    @cached_property
    def previous_transaction_issuer(self) -> tuple[bool, bool, str | None]:
        """(has_previous_txn, previous_had_payment_method, previous issuer country)."""
        row = self._run(_previous_issuer_stmt(self._has_txn)).first()
        if row is None:
            return (False, False, None)
        return (True, row[0] is not None, row[1])

    @cached_property
    def label_counts(self) -> tuple[int, int]:
        """(chargebacks, other confirmed fraud) known by as_of, excluding the scored target."""
        row = self._run(_labels_stmt(self._has_txn)).one()
        return _int(row[0]), _int(row[1])

    # ------------------------------------------------------------------ device
    @cached_property
    def device(self) -> DeviceHistory:
        ev = self._run(_device_events_stmt(self.ctx.user_id is not None)).one()
        logins = self._run(_device_logins_stmt()).one()
        return DeviceHistory(
            prior_events=_int(ev[0]),
            accounts=_int(ev[1]),
            other_accounts=_int(ev[2]),
            accounts_24h=_int(ev[3]),
            last_seen=ev[4],
            first_for_user=ev[5],
            prior_for_user=_int(ev[6]),
            successful_logins=_int(logins[0]),
            failed_logins=_int(logins[1]),
        )

    # ------------------------------------------------------------------ network
    @cached_property
    def network(self) -> NetworkHistory:
        obs = self._run(_network_obs_stmt(self.ctx.user_id is not None)).one()
        logins = self._run(_network_logins_stmt()).one()
        return NetworkHistory(
            prior_observations=_int(obs[0]),
            first_seen=obs[1],
            accounts=_int(obs[2]),
            other_accounts=_int(obs[3]),
            accounts_1h=_int(obs[4]),
            successful_logins=_int(logins[0]),
            failed_logins=_int(logins[1]),
            failed_logins_1h=_int(logins[2]),
        )

    @cached_property
    def previous_user_observation(self) -> PreviousObservation | None:
        row = self._run(_previous_observation_stmt()).first()
        return PreviousObservation(row[0], row[1], row[2]) if row is not None else None

    @cached_property
    def recent_network_values(
        self,
    ) -> tuple[list[tuple[str | None, int | None]], PreviousObservation | None]:
        """(country, asn) of the account's observations in the recent window (including
        the scored event) and the last observation before the window."""
        inside = [(c, a) for c, a in self._run(_recent_network_values_stmt()).all()]
        before = self._run(_before_recent_window_stmt()).first()
        return inside, (PreviousObservation(before[0], before[1], before[2]) if before else None)

    @cached_property
    def networks_per_account(self) -> int:
        return _int(self._run(_networks_per_account_stmt()).scalar())

    # ------------------------------------------------------------------ account entities
    @cached_property
    def user_devices(self) -> EntityCounts:
        """Devices of the account by first-seen time (including the scored event)."""
        row = self._run(_user_devices_stmt()).one()
        return EntityCounts(_int(row[0]), _int(row[1]), _int(row[2]))

    @cached_property
    def user_addresses(self) -> EntityCounts:
        row = self._run(_registered_stmt(Address)).one()
        return EntityCounts(_int(row[0]), _int(row[1]), _int(row[2]))

    @cached_property
    def user_payment_methods(self) -> EntityCounts:
        row = self._run(_registered_stmt(PaymentMethod)).one()
        return EntityCounts(_int(row[0]), _int(row[1]), _int(row[2]))

    # ------------------------------------------------------------------ address / payment
    def _usage(self, column_name: str, entity_id: uuid.UUID) -> UsageCounts:
        row = self._run(_usage_stmt(column_name), entity_id=entity_id).one()
        return UsageCounts(_int(row[0]), _int(row[1]), _int(row[2]), row[3])

    @cached_property
    def address_usage(self) -> UsageCounts:
        assert self.ctx.address is not None
        return self._usage("shipping_address_id", self.ctx.address.address_id)

    @cached_property
    def payment_method_usage(self) -> UsageCounts:
        assert self.ctx.payment_method is not None
        return self._usage("payment_method_id", self.ctx.payment_method.payment_method_id)

    @cached_property
    def accounts_sharing_address(self) -> int:
        assert self.ctx.address is not None
        stmt = _sharing_stmt(Address, "address_hash")
        return _int(self._run(stmt, hash_value=self.ctx.address.address_hash).scalar())

    @cached_property
    def accounts_sharing_fingerprint(self) -> int | None:
        assert self.ctx.payment_method is not None
        fingerprint = self.ctx.payment_method.fingerprint_hash
        if fingerprint is None:
            return None
        stmt = _sharing_stmt(PaymentMethod, "fingerprint_hash")
        return _int(self._run(stmt, hash_value=fingerprint).scalar())

    # ------------------------------------------------------------------ provenance
    @cached_property
    def source_event_count(self) -> int:
        """History size behind the vector: the account's events by as_of (anonymous events:
        observations of the network; otherwise 0)."""
        if self.ctx.user_id is not None:
            return _int(self._run(_source_count_user_stmt()).scalar())
        if self.ctx.network is not None:
            return _int(self._run(_source_count_network_stmt()).scalar())
        return 0
