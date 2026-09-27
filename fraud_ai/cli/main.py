"""``fraud-ai`` command-line entry point.

Only commands with real functionality exist.
"""

from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

import click
from pydantic import ValidationError
from sqlalchemy import Engine, case, func, select
from sqlalchemy.exc import SQLAlchemyError

from fraud_ai import __version__
from fraud_ai.config.settings import Environment, Settings, get_settings
from fraud_ai.core.enums import LabelValue, LoginOutcome
from fraud_ai.core.events import parse_event
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database import engine_from_settings, make_session_factory, session_scope
from fraud_ai.database import migrations as mig
from fraud_ai.database.models import (
    EventRecord,
    FraudLabel,
    LoginEvent,
    NetworkEvent,
    Transaction,
    User,
)
from fraud_ai.database.repositories import table_row_counts
from fraud_ai.utils.logging import configure_logging, get_logger

log = get_logger("cli")


class AppContext:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._engine: Engine | None = None

    @property
    def engine(self) -> Engine:
        if self._engine is None:
            self._engine = engine_from_settings(self.settings)
        return self._engine

    def require_migrated(self) -> None:
        status = mig.schema_status(self.engine, self.settings.resolved_database_url)
        if not status.initialised:
            raise click.ClickException("database is not initialised; run `fraud-ai db init`")
        if not status.up_to_date:
            raise click.ClickException(
                f"database is at {status.current}, head is {status.head}; run `fraud-ai db migrate`"
            )


pass_app = click.make_pass_decorator(AppContext)


@click.group()
@click.version_option(__version__, prog_name="fraud-ai")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """fraud-ai: local fraud-prevention platform."""
    try:
        settings = get_settings()
    except ValidationError as exc:
        raise click.ClickException(f"invalid configuration:\n{exc}") from None
    configure_logging(settings.log_level)
    log.debug("starting fraud-ai %s (environment=%s)", __version__, settings.environment)
    ctx.obj = AppContext(settings)
    ctx.call_on_close(lambda: ctx.obj._engine.dispose() if ctx.obj._engine else None)


# --------------------------------------------------------------------------- db
@cli.group()
def db() -> None:
    """Database management."""


@db.command("init")
@pass_app
def db_init(app: AppContext) -> None:
    """Create the schema in a new, empty database (migrates to head)."""
    url = app.settings.resolved_database_url
    status = mig.schema_status(app.engine, url)
    if status.initialised:
        raise click.ClickException(
            f"database already initialised at revision {status.current}; use `fraud-ai db migrate`"
        )
    if status.tables:
        raise click.ClickException(
            f"database contains unmanaged tables ({', '.join(status.tables)}); refusing to init"
        )
    mig.upgrade(url)
    click.echo(f"initialised {app.settings.safe_database_url} at revision {mig.head_revision(url)}")


@db.command("migrate")
@click.option("--revision", default="head", show_default=True, help="Target revision.")
@pass_app
def db_migrate(app: AppContext, revision: str) -> None:
    """Apply pending migrations to an existing database."""
    url = app.settings.resolved_database_url
    before = mig.current_revision(app.engine)
    mig.upgrade(url, revision)
    after = mig.current_revision(app.engine)
    if before == after:
        click.echo(f"already at revision {after}; nothing to do")
    else:
        click.echo(f"migrated {before or '<empty>'} -> {after}")


@db.command("status")
@pass_app
def db_status(app: AppContext) -> None:
    """Show connection, migration state and row counts."""
    url = app.settings.resolved_database_url
    try:
        status = mig.schema_status(app.engine, url)
    except SQLAlchemyError as exc:
        raise click.ClickException(
            f"cannot connect to database: {exc.__class__.__name__}"
        ) from None
    click.echo(f"database:  {app.settings.safe_database_url}")
    click.echo(f"backend:   {app.engine.dialect.name}")
    click.echo(f"revision:  {status.current or '<not initialised>'}")
    click.echo(f"head:      {status.head}")
    click.echo(f"up to date: {'yes' if status.up_to_date else 'no'}")
    if status.initialised:
        factory = make_session_factory(app.engine)
        with session_scope(factory) as session:
            counts = table_row_counts(session)
        click.echo("tables:")
        for name, count in counts.items():
            click.echo(f"  {name:<22} {count:>9}")


# --------------------------------------------------------------------------- seed
@cli.command()
@click.option("--users", "n_users", default=60, show_default=True, type=click.IntRange(6, 5000))
@click.option("--seed", "rng_seed", default=42, show_default=True, type=int)
@click.option(
    "--fraud-multiplier",
    default=1.0,
    show_default=True,
    type=click.FloatRange(0.1, 3.0),
    help="Scale the share of fraud scenarios (prevalence experiments).",
)
@click.option(
    "--days",
    default=90,
    show_default=True,
    type=click.IntRange(30, 730),
    help="Length of the activity window.",
)
@click.option(
    "--reference-time",
    type=click.DateTime(["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"]),
    default=None,
    help="End of the synthetic timeline (UTC). Default: today 00:00.",
)
@click.option(
    "--live-days",
    type=click.IntRange(1, 60),
    default=None,
    help="Stage 8: hold out the last N days as a live stream (not ingested).",
)
@click.option(
    "--live-output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="JSON-lines file for the held-out live events (with arrival times).",
)
@click.option("--late-fraction", type=click.FloatRange(0, 1), default=0.02, show_default=True)
@pass_app
def seed(
    app: AppContext,
    n_users: int,
    rng_seed: int,
    fraud_multiplier: float,
    days: int,
    reference_time: datetime | None,
    live_days: int | None,
    live_output: Path | None,
    late_fraction: float,
) -> None:
    """Load deterministic synthetic demo data through the ingestion pipeline."""
    if app.settings.environment in {Environment.STAGING, Environment.PRODUCTION}:
        raise click.ClickException(f"refusing to seed synthetic data in {app.settings.environment}")
    app.require_migrated()
    from fraud_ai.data.seed import seed_synthetic_data
    from fraud_ai.security.keys import build_pseudonymiser

    ref = reference_time or datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    ref = ref.replace(tzinfo=UTC) if ref.tzinfo is None else ref
    factory = make_session_factory(app.engine)
    if (live_days is None) != (live_output is None):
        raise click.UsageError("--live-days and --live-output go together")
    if live_days is not None and live_output is not None:
        from fraud_ai.data.seed import seed_with_live_holdout

        try:
            with session_scope(factory) as session:
                holdout = seed_with_live_holdout(
                    session,
                    build_pseudonymiser(app.settings),
                    n_users=n_users,
                    seed=rng_seed,
                    reference_time=ref,
                    activity_days=days,
                    live_days=live_days,
                    fraud_multiplier=fraud_multiplier,
                    late_fraction=late_fraction,
                    store_raw_ip=app.settings.store_raw_ip,
                )
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        live_output.parent.mkdir(parents=True, exist_ok=True)
        live_output.write_text("".join(json.dumps(e) + "\n" for e in holdout.events))
        click.echo(
            f"seeded {holdout.history.users} users, {holdout.history.events} history events "
            f"before {holdout.cutoff.isoformat()}"
        )
        click.echo(
            f"live stream: {len(holdout.events)} SYNTHETIC events ({holdout.late_events} late) "
            f"-> {live_output}"
        )
        return
    try:
        with session_scope(factory) as session:
            summary = seed_synthetic_data(
                session,
                build_pseudonymiser(app.settings),
                n_users=n_users,
                seed=rng_seed,
                reference_time=ref,
                activity_days=days,
                store_raw_ip=app.settings.store_raw_ip,
                fraud_multiplier=fraud_multiplier,
            )
    except FraudAIError as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(
        f"seeded {summary.users} users, {summary.events} events, "
        f"{summary.transactions} transactions in {summary.elapsed_seconds}s"
    )
    click.echo(f"labels: {summary.fraud_labels} fraud, {summary.legitimate_labels} legitimate")
    for name, count in summary.scenario_counts.items():
        click.echo(f"  {name:<22} {count:>5} users")


# --------------------------------------------------------------------------- demo-data
@cli.group("demo-data")
def demo_data() -> None:
    """Inspect synthetic demonstration data."""


@demo_data.command("stats")
@pass_app
def demo_data_stats(app: AppContext) -> None:
    """Per-scenario statistics of the synthetic dataset."""
    app.require_migrated()
    factory = make_session_factory(app.engine)
    with session_scope(factory) as session:
        scenario = User.synthetic_scenario
        users = dict(
            session.execute(
                select(scenario, func.count()).where(scenario.is_not(None)).group_by(scenario)
            ).all()
        )
        if not users:
            click.echo("no synthetic data found; run `fraud-ai seed`")
            return
        txn_rows = session.execute(
            select(
                scenario,
                func.count(Transaction.transaction_id),
                func.coalesce(func.avg(Transaction.amount_minor), 0),
            )
            .join(Transaction, Transaction.user_id == User.user_id)
            .group_by(scenario)
        ).all()
        # Synthetic data is GBP-only, so minor units / 100 gives major units.
        txns = {s: (n, float(avg) / 100) for s, n, avg in txn_rows}
        fraud = dict(
            session.execute(
                select(scenario, func.count())
                .join(FraudLabel, FraudLabel.user_id == User.user_id)
                .where(FraudLabel.label == LabelValue.FRAUD)
                .group_by(scenario)
            ).all()
        )
        logins = {
            s: (int(n), int(f or 0))
            for s, n, f in session.execute(
                select(
                    scenario,
                    func.count(),
                    func.sum(case((LoginEvent.outcome == LoginOutcome.FAILURE, 1), else_=0)),
                )
                .join(LoginEvent, LoginEvent.user_id == User.user_id)
                .group_by(scenario)
            ).all()
        }
        vpn = dict(
            session.execute(
                select(scenario, func.count())
                .join(NetworkEvent, NetworkEvent.user_id == User.user_id)
                .where(NetworkEvent.is_known_vpn.is_(True))
                .group_by(scenario)
            ).all()
        )
        anonymous_failures = session.scalar(
            select(func.count()).select_from(LoginEvent).where(LoginEvent.user_id.is_(None))
        )
        event_types = session.execute(
            select(EventRecord.event_type, func.count())
            .group_by(EventRecord.event_type)
            .order_by(func.count().desc())
        ).all()

    header = (
        f"{'scenario':<22}{'users':>7}{'txns':>8}{'avg amt':>10}{'logins':>8}"
        f"{'failed':>8}{'vpn obs':>9}{'fraud lbl':>10}"
    )
    click.echo(header)
    click.echo("-" * len(header))
    for s in sorted(users, key=str):
        n_txn, avg = txns.get(s, (0, 0.0))
        n_login, n_fail = logins.get(s, (0, 0))
        click.echo(
            f"{s:<22}{users[s]:>7}{n_txn:>8}{avg:>10.2f}{n_login:>8}{n_fail:>8}"
            f"{vpn.get(s, 0):>9}{fraud.get(s, 0):>10}"
        )
    click.echo(f"\nlogin failures against unknown accounts: {anonymous_failures}")
    click.echo("events by type:")
    for event_type, count in event_types:
        click.echo(f"  {event_type.value:<22} {count:>8}")


# --------------------------------------------------------------------------- ingest-event
def _iter_json_events(stream: TextIO) -> Iterator[tuple[int, dict[str, Any]]]:
    text = stream.read()
    stripped = text.lstrip()
    if stripped.startswith("["):
        for i, item in enumerate(json.loads(stripped), 1):
            yield i, item
        return
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip():
            yield i, json.loads(line)


@cli.command("ingest-event")
@click.argument("source", type=click.File("r"), default="-")
@click.option("--stop-on-error", is_flag=True, help="Abort at the first rejected event.")
@pass_app
def ingest_event(app: AppContext, source: TextIO, stop_on_error: bool) -> None:
    """Validate and ingest events from a JSON array or JSON-lines file (``-`` for stdin)."""
    app.require_migrated()
    from fraud_ai.ingestion.processor import EventProcessor
    from fraud_ai.security.keys import build_pseudonymiser

    factory = make_session_factory(app.engine)
    stored = duplicates = rejected = 0
    try:
        items = list(_iter_json_events(source))
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"invalid JSON: {exc.msg} (line {exc.lineno})") from None
    with session_scope(factory) as session:
        processor = EventProcessor(
            session, build_pseudonymiser(app.settings), store_raw_ip=app.settings.store_raw_ip
        )
        for position, item in items:
            try:
                result = processor.process(parse_event(item))
            except FraudAIError as exc:
                rejected += 1
                log.warning("event #%d rejected: %s", position, exc)
                click.echo(f"#{position}: rejected - {exc}", err=True)
                if stop_on_error:
                    break
                continue
            if result.duplicate:
                duplicates += 1
            else:
                stored += 1
    click.echo(f"stored {stored}, duplicates {duplicates}, rejected {rejected}")
    if rejected:
        sys.exit(1)


# --------------------------------------------------------------------------- features
_DT_FORMATS = ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]


def _utc(value: datetime | None) -> datetime | None:
    """Command-line timestamps are interpreted as UTC."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise click.BadParameter(f"not a UUID: {value}") from None


@cli.group()
def features() -> None:
    """Feature engineering: catalogue, extraction, snapshots, validation."""


@features.command("catalog")
@click.option("--version", "feature_version", default=None, help="Feature version.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json", "markdown"]),
    default="table",
    show_default=True,
)
def features_catalog(feature_version: str | None, fmt: str) -> None:
    """List every feature with its type, category and missing-value semantics."""
    from fraud_ai.features.catalog import catalog_json, catalog_markdown
    from fraud_ai.features.definitions import get_feature_set

    try:
        fs = get_feature_set(feature_version)
    except KeyError as exc:
        raise click.ClickException(str(exc)) from None
    if fmt == "json":
        click.echo(catalog_json(fs.version))
        return
    if fmt == "markdown":
        click.echo(catalog_markdown(fs.version))
        return
    click.echo(
        f"{fs.version}  ({len(fs.definitions)} features, fingerprint {fs.fingerprint()[:16]})"
    )
    for d in fs.definitions:
        applies = "both" if len(d.applies_to) == 2 else next(iter(d.applies_to)).value
        click.echo(
            f"  {d.category.value:<15} {d.name:<42} {d.dtype.value:<12} "
            f"{'nullable' if d.nullable else 'required':<9} {applies}"
        )


@features.command("show")
@click.argument("event_id")
@click.option(
    "--as-of",
    "as_of",
    type=click.DateTime(_DT_FORMATS),
    default=None,
    help="Point in time (UTC). Default: the event's own timestamp.",
)
@click.option("--version", "feature_version", default=None)
@click.option(
    "--format", "fmt", type=click.Choice(["table", "json"]), default="table", show_default=True
)
@pass_app
def features_show(
    app: AppContext, event_id: str, as_of: datetime | None, feature_version: str | None, fmt: str
) -> None:
    """Compute (without storing) the feature vector for one event."""
    app.require_migrated()
    from fraud_ai.features.definitions import get_feature_set
    from fraud_ai.features.extractor import extract_features

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            vector = extract_features(session, _parse_uuid(event_id), _utc(as_of), feature_version)
        except (FraudAIError, KeyError) as exc:
            raise click.ClickException(str(exc)) from None
    if fmt == "json":
        click.echo(
            json.dumps(
                {
                    "event_id": str(vector.event_id),
                    "as_of_timestamp": vector.as_of_timestamp.isoformat(),
                    "feature_hash": vector.feature_hash,
                    **vector.canonical_payload(),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    click.echo(
        f"event {vector.event_id} ({vector.event_kind.value}) as of "
        f"{vector.as_of_timestamp.isoformat()}"
    )
    click.echo(f"version {vector.feature_version}  hash {vector.feature_hash}")
    for d in get_feature_set(vector.feature_version).definitions:
        value = vector.get(d.name)
        shown = f"<{vector.missing[d.name].value}>" if value is None else json.dumps(value)
        click.echo(f"  {d.category.value:<15} {d.name:<42} {shown}")


def _event_ids_for(
    session: Any,
    ids: tuple[str, ...],
    start: datetime | None,
    end: datetime | None,
    kind: str | None,
) -> list[uuid.UUID]:
    from fraud_ai.features.batch import scorable_event_ids
    from fraud_ai.features.definitions import EventKind

    if ids:
        return [_parse_uuid(i) for i in ids]
    if start is None or end is None:
        raise click.UsageError("give EVENT_ID arguments or both --start and --end")
    kinds = [EventKind(kind)] if kind else list(EventKind)
    return scorable_event_ids(session, start, end, kinds)


@features.command("snapshot")
@click.argument("event_ids", nargs=-1)
@click.option("--start", type=click.DateTime(_DT_FORMATS), default=None)
@click.option("--end", type=click.DateTime(_DT_FORMATS), default=None)
@click.option("--kind", type=click.Choice(["login", "transaction"]), default=None)
@click.option("--version", "feature_version", default=None)
@pass_app
def features_snapshot(
    app: AppContext,
    event_ids: tuple[str, ...],
    start: datetime | None,
    end: datetime | None,
    kind: str | None,
    feature_version: str | None,
) -> None:
    """Compute and persist point-in-time snapshots (idempotent; drift is an error)."""
    app.require_migrated()
    from fraud_ai.features.batch import iter_vectors
    from fraud_ai.features.snapshot import find_snapshot, persist_snapshot

    created = existing = 0
    with session_scope(make_session_factory(app.engine)) as session:
        ids = _event_ids_for(session, event_ids, _utc(start), _utc(end), kind)
        try:
            for vector in iter_vectors(session, ids, feature_version):
                if (
                    find_snapshot(
                        session, vector.event_id, vector.feature_version, vector.as_of_timestamp
                    )
                    is not None
                ):
                    existing += 1
                persist_snapshot(session, vector)
            created = len(ids) - existing
        except (FraudAIError, KeyError) as exc:
            raise click.ClickException(str(exc)) from None
    click.echo(f"snapshots: {created} created, {existing} already present (identical)")


@features.command("validate")
@click.option("--version", "feature_version", default=None)
@click.option("--limit", type=click.IntRange(1), default=None, help="Check at most N.")
@pass_app
def features_validate(app: AppContext, feature_version: str | None, limit: int | None) -> None:
    """Re-verify persisted snapshots: stored hash integrity and exact recomputation."""
    app.require_migrated()
    from fraud_ai.database.models import FeatureSnapshot
    from fraud_ai.features.definitions import get_feature_set
    from fraud_ai.features.snapshot import verify_snapshots

    version = get_feature_set(feature_version).version
    with session_scope(make_session_factory(app.engine)) as session:
        query = (
            select(FeatureSnapshot)
            .where(FeatureSnapshot.feature_version == version)
            .order_by(FeatureSnapshot.as_of_timestamp, FeatureSnapshot.event_id)
        )
        if limit:
            query = query.limit(limit)
        checks = verify_snapshots(session, session.scalars(query))
    failures = [c for c in checks if not c.ok]
    for check in failures:
        click.echo(f"FAIL {check.event_id}: {check.problem}", err=True)
    click.echo(
        f"validated {len(checks)} snapshots ({version}): {len(checks) - len(failures)} ok, "
        f"{len(failures)} failed"
    )
    if failures:
        sys.exit(1)


# --------------------------------------------------------------------------- dataset
@cli.group()
def dataset() -> None:
    """Training-dataset construction (features and labels; no training)."""


@dataset.command("build")
@click.option("--start", type=click.DateTime(_DT_FORMATS), required=True)
@click.option("--end", type=click.DateTime(_DT_FORMATS), required=True)
@click.option(
    "--label-cutoff",
    type=click.DateTime(_DT_FORMATS),
    required=True,
    help="Labels known after this moment are ignored (UTC).",
)
@click.option("--output", type=click.Path(file_okay=False, path_type=Path), required=True)
@click.option("--maturity-days", type=click.FloatRange(0), default=30, show_default=True)
@click.option(
    "--implicit-negatives/--explicit-labels-only",
    default=False,
    show_default=True,
    help="Treat mature, unlabelled events as legitimate.",
)
@click.option("--kind", type=click.Choice(["login", "transaction"]), default=None)
@click.option("--use-snapshots", is_flag=True, help="Reuse persisted point-in-time snapshots.")
@click.option("--persist-snapshots", is_flag=True, help="Store computed vectors as snapshots.")
@click.option("--version", "feature_version", default=None)
@pass_app
def dataset_build(
    app: AppContext,
    start: datetime,
    end: datetime,
    label_cutoff: datetime,
    output: Path,
    maturity_days: float,
    implicit_negatives: bool,
    kind: str | None,
    use_snapshots: bool,
    persist_snapshots: bool,
    feature_version: str | None,
) -> None:
    """Write features.jsonl, labels.jsonl, excluded.jsonl and manifest.json."""
    app.require_migrated()
    from datetime import timedelta

    from fraud_ai.datasets.builder import TrainingDatasetBuilder
    from fraud_ai.datasets.labels import LabelAvailabilityPolicy
    from fraud_ai.features.definitions import EventKind

    cutoff = _utc(label_cutoff)
    assert cutoff is not None
    policy = LabelAvailabilityPolicy(
        label_cutoff=cutoff,
        maturity=timedelta(days=maturity_days),
        implicit_negatives=implicit_negatives,
    )
    kinds = [EventKind(kind)] if kind else list(EventKind)
    with session_scope(make_session_factory(app.engine)) as session:
        try:
            built = TrainingDatasetBuilder(session, policy, feature_version).build(
                _utc(start) or start,
                _utc(end) or end,
                kinds=kinds,
                use_snapshots=use_snapshots,
                persist_snapshots=persist_snapshots,
            )
        except (FraudAIError, KeyError) as exc:
            raise click.ClickException(str(exc)) from None
    paths = built.write(output)
    manifest = built.manifest()
    click.echo(
        f"dataset: {manifest['examples']} examples ({manifest['positives']} positive, "
        f"{manifest['negatives']} negative), feature version {built.feature_version}"
    )
    for status, count in manifest["label_status_counts"].items():
        click.echo(f"  {status:<22} {count:>7}")
    click.echo(f"written to {paths['manifest.json'].parent}")


# --------------------------------------------------------------------------- models (Stage 3)
_KIND_CHOICES = {
    "transaction": ("transaction",),
    "login": ("login",),
    "all": ("login", "transaction"),
}


def _training_options(func: Any) -> Any:
    return _training_options_with()(func)


def _training_options_with(
    threshold: float = 0.5, threshold_help: str = "Evaluation threshold (not a decision)."
) -> Callable[[Any], Any]:
    def decorate(func: Any) -> Any:
        return _apply_training_options(func, threshold, threshold_help)

    return decorate


def _apply_training_options(func: Any, threshold: float, threshold_help: str) -> Any:
    options = [
        click.option(
            "--start",
            type=click.DateTime(_DT_FORMATS),
            default=None,
            help="First event (UTC). Default: earliest event.",
        ),
        click.option(
            "--end",
            type=click.DateTime(_DT_FORMATS),
            default=None,
            help="Last event (UTC). Default: label cutoff minus maturity.",
        ),
        click.option(
            "--label-cutoff",
            type=click.DateTime(_DT_FORMATS),
            default=None,
            help="Labels known after this are ignored. Default: latest event.",
        ),
        click.option("--maturity-days", type=click.FloatRange(0), default=30, show_default=True),
        click.option(
            "--implicit-negatives/--explicit-labels-only", default=False, show_default=True
        ),
        click.option(
            "--kind",
            type=click.Choice(sorted(_KIND_CHOICES)),
            default="transaction",
            show_default=True,
            help="Which scored events to train on.",
        ),
        click.option("--train-fraction", type=float, default=0.70, show_default=True),
        click.option("--validation-fraction", type=float, default=0.15, show_default=True),
        click.option(
            "--train-end",
            type=click.DateTime(_DT_FORMATS),
            default=None,
            help="Date split: training events before this (UTC).",
        ),
        click.option(
            "--validation-end",
            type=click.DateTime(_DT_FORMATS),
            default=None,
            help="Date split: validation events before this, test after.",
        ),
        click.option("--seed", type=int, default=42, show_default=True),
        click.option(
            "--imbalance",
            type=click.Choice(["class_weight", "oversample", "none"]),
            default="class_weight",
            show_default=True,
        ),
        click.option(
            "--threshold",
            type=click.FloatRange(0, 1),
            default=threshold,
            show_default=True,
            help=threshold_help,
        ),
        click.option("--version", "model_version", default="1.0.0", show_default=True),
        click.option(
            "--persist-snapshots",
            is_flag=True,
            help="Store the training vectors as feature snapshots.",
        ),
        click.option(
            "--report",
            type=click.Path(dir_okay=False, path_type=Path),
            default=None,
            help="Also write a JSON report.",
        ),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def _training_config(opts: dict[str, Any], hyperparameters: dict[str, Any] | None = None) -> Any:
    from datetime import timedelta

    from fraud_ai.features.definitions import EventKind
    from fraud_ai.models.splits import SplitConfig
    from fraud_ai.models.training import TrainingConfig

    split = SplitConfig(
        opts["train_fraction"],
        opts["validation_fraction"],
        _utc(opts["train_end"]),
        _utc(opts["validation_end"]),
    )
    return TrainingConfig(
        start=_utc(opts["start"]),
        end=_utc(opts["end"]),
        label_cutoff=_utc(opts["label_cutoff"]),
        maturity=timedelta(days=opts["maturity_days"]),
        implicit_negatives=opts["implicit_negatives"],
        kinds=tuple(EventKind(k) for k in _KIND_CHOICES[opts["kind"]]),
        split=split,
        seed=opts["seed"],
        imbalance=opts["imbalance"],
        threshold=opts["threshold"],
        version=opts["model_version"],
        persist_snapshots=opts["persist_snapshots"],
        hyperparameters=hyperparameters or {},
    )


def _run_train(
    app: AppContext,
    kinds: list[str],
    hyperparameters: dict[str, Any] | None = None,
    **opts: Any,
) -> None:
    app.require_migrated()
    from fraud_ai.models.report import SYNTHETIC_NOTE, comparison_table
    from fraud_ai.models.training import run_training

    try:
        config = _training_config(opts, hyperparameters)
        with session_scope(make_session_factory(app.engine)) as session:
            run = run_training(session, kinds, config, app.settings.model_directory)
            summary = run.prepared.summary()
            registered = [r.registered for r in run.results if r.registered is not None]
            table = comparison_table(registered)
            report = {
                "dataset": summary,
                "models": [
                    {
                        "model": r.model_id,
                        "metrics": r.metrics,
                        "warnings": r.warnings,
                        "timings": r.timings,
                        "explanation": r.explanation,
                        "artifact": str(r.artifact_path),
                        "artifact_sha256": r.artifact_sha256,
                    }
                    for r in run.results
                ],
                "note": SYNTHETIC_NOTE,
            }
    except FraudAIError as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(
        f"dataset {summary['dataset_fingerprint'][:16]}: {summary['examples']} examples, "
        f"{summary['positives']} fraud ({100 * summary['prevalence']:.2f}%)"
    )
    for name, part in summary["splits"].items():
        click.echo(
            f"  {name:<11}{part['rows']:>7} rows {part['positives']:>5} fraud  "
            f"{part['start'][:19]} .. {part['end'][:19]}"
        )
    for r in run.results:
        for warning in r.warnings:
            click.echo(f"WARNING {r.model_id}: {warning}")
    click.echo("")
    click.echo(table)
    if opts["report"]:
        opts["report"].write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
        click.echo(f"report written to {opts['report']}")


@cli.group()
def train() -> None:
    """Train fraud models on a time-ordered split (no decisions are made)."""


def _train_command(name: str, kinds: list[str], help_text: str) -> None:
    @train.command(name, help=help_text)
    @_training_options
    @pass_app
    def _command(app: AppContext, /, **opts: Any) -> None:
        _run_train(app, kinds, **opts)


_train_command("logistic", ["logistic"], "Train logistic regression.")
_train_command("random-forest", ["random-forest"], "Train a random forest.")
_train_command("gradient-boosting", ["gradient-boosting"], "Train histogram gradient boosting.")
_train_command(
    "all",
    ["logistic", "random-forest", "gradient-boosting"],
    "Train all three baselines on the same split.",
)


def _int_list(value: str) -> list[int]:
    try:
        sizes = [int(v) for v in value.split(",") if v.strip()]
    except ValueError:
        raise click.BadParameter("expected comma-separated integers, e.g. 128,64,32") from None
    if not sizes or min(sizes) < 1:
        raise click.BadParameter("layer sizes must be positive integers")
    return sizes


def _neural_options(func: Any) -> Any:
    options = [
        click.option(
            "--hidden", default="128,64,32", show_default=True, help="Hidden layer sizes."
        ),
        click.option(
            "--activation", type=click.Choice(["relu", "gelu"]), default="relu", show_default=True
        ),
        click.option(
            "--normalization",
            type=click.Choice(["layernorm", "batchnorm", "none"]),
            default="layernorm",
            show_default=True,
        ),
        click.option("--dropout", type=click.FloatRange(0, 0.95), default=0.3, show_default=True),
        click.option("--batch-size", type=click.IntRange(1), default=256, show_default=True),
        click.option(
            "--learning-rate",
            type=click.FloatRange(min=0, min_open=True),
            default=1e-3,
            show_default=True,
        ),
        click.option("--weight-decay", type=click.FloatRange(0), default=1e-4, show_default=True),
        click.option("--max-epochs", type=click.IntRange(1), default=60, show_default=True),
        click.option("--patience", type=click.IntRange(1), default=8, show_default=True),
        click.option(
            "--loss",
            type=click.Choice(["weighted_bce", "focal"]),
            default="weighted_bce",
            show_default=True,
        ),
        click.option("--focal-gamma", type=click.FloatRange(0), default=2.0, show_default=True),
        click.option(
            "--device",
            type=click.Choice(["auto", "cpu", "cuda"]),
            default="cpu",
            show_default=True,
            help="auto = CUDA when available.",
        ),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def _neural_hyperparameters(opts: dict[str, Any]) -> dict[str, Any]:
    return {
        "hidden_sizes": _int_list(opts.pop("hidden")),
        **{
            k: opts.pop(k)
            for k in (
                "activation",
                "normalization",
                "dropout",
                "batch_size",
                "learning_rate",
                "weight_decay",
                "max_epochs",
                "patience",
                "loss",
                "focal_gamma",
                "device",
            )
        },
    }


def _sequence_options(func: Any) -> Any:
    options = [
        click.option(
            "--max-events",
            type=click.IntRange(1, 512),
            default=16,
            show_default=True,
            help="History window: the last N events before the scored event.",
        ),
        click.option(
            "--max-age-days",
            type=click.FloatRange(min=0, min_open=True),
            default=None,
            help="Optionally drop window events older than this.",
        ),
        click.option(
            "--lookback-days",
            type=click.FloatRange(min=0, min_open=True),
            default=365.0,
            show_default=True,
            help="History read to decide whether devices/networks were known.",
        ),
        click.option("--hidden-size", type=click.IntRange(1), default=64, show_default=True),
        click.option(
            "--layers",
            type=click.IntRange(1, 8),
            default=None,
            help="Default: 1 (GRU/hybrid), 2 (Transformer).",
        ),
        click.option("--heads", type=click.IntRange(1), default=4, show_default=True),
        click.option("--dropout", type=click.FloatRange(0, 0.95), default=0.2, show_default=True),
        click.option("--batch-size", type=click.IntRange(1), default=256, show_default=True),
        click.option(
            "--learning-rate",
            type=click.FloatRange(min=0, min_open=True),
            default=1e-3,
            show_default=True,
        ),
        click.option("--weight-decay", type=click.FloatRange(0), default=1e-4, show_default=True),
        click.option("--max-epochs", type=click.IntRange(1), default=40, show_default=True),
        click.option("--patience", type=click.IntRange(1), default=6, show_default=True),
        click.option(
            "--loss",
            type=click.Choice(["weighted_bce", "focal"]),
            default="weighted_bce",
            show_default=True,
        ),
        click.option(
            "--device", type=click.Choice(["auto", "cpu", "cuda"]), default="cpu", show_default=True
        ),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def _train_sequence(app: AppContext, kind: str, opts: dict[str, Any]) -> None:
    from dataclasses import replace as dc_replace

    from fraud_ai.sequences.definition import SequenceDefinition

    try:
        definition = SequenceDefinition(
            max_events=opts.pop("max_events"),
            max_age_days=opts.pop("max_age_days"),
            lookback_days=opts.pop("lookback_days"),
        )
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from None
    layers = opts.pop("layers") or (2 if kind == "transformer" else 1)
    hyperparameters = {
        "layers": layers,
        **{
            k: opts.pop(k)
            for k in (
                "hidden_size",
                "heads",
                "dropout",
                "batch_size",
                "learning_rate",
                "weight_decay",
                "max_epochs",
                "patience",
                "loss",
                "device",
            )
        },
    }
    app.require_migrated()
    from fraud_ai.models.report import comparison_table
    from fraud_ai.models.training import run_training

    try:
        config = dc_replace(_training_config(opts, {kind: hyperparameters}), sequence=definition)
        with session_scope(make_session_factory(app.engine)) as session:
            run = run_training(session, [kind], config, app.settings.model_directory)
            table = comparison_table([r.registered for r in run.results if r.registered])
            result = run.results[0]
            summary = result.model.manifest()
    except FraudAIError as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(
        f"sequence {definition.version} fingerprint {definition.fingerprint()[:16]}  "
        f"window {definition.max_events} events + the scored event"
    )
    click.echo(
        f"{result.model_id}: {summary['parameter_count']} parameters, best epoch "
        f"{summary['training']['best_epoch']}/{summary['training']['epochs_completed']}"
    )
    for warning in result.warnings:
        click.echo(f"WARNING {result.model_id}: {warning}")
    click.echo(table)


def _sequence_train_command(name: str, kind: str, help_text: str) -> None:
    @train.command(name, help=help_text)
    @_training_options
    @_sequence_options
    @pass_app
    def _command(app: AppContext, /, **opts: Any) -> None:
        _train_sequence(app, kind, opts)


_sequence_train_command("gru", "gru", "Train the GRU sequence model (user event history).")
_sequence_train_command(
    "transformer", "transformer", "Train the small causal Transformer sequence model."
)
_sequence_train_command(
    "hybrid", "hybrid-gru", "Train the hybrid model: GRU sequence encoder + static features."
)


@train.command("neural-network")
@_training_options
@_neural_options
@pass_app
def train_neural(app: AppContext, /, **opts: Any) -> None:
    """Train the feed-forward neural network (PyTorch) on the same split as the baselines.

    Early stopping uses validation PR-AUC; the test split is only evaluated."""
    hyperparameters = _neural_hyperparameters(opts)
    _run_train(app, ["neural-network"], {"neural-network": hyperparameters}, **opts)


@cli.group()
def models() -> None:
    """Inspect registered model versions."""


@models.command("list")
@pass_app
def models_list(app: AppContext) -> None:
    """All registered model versions."""
    app.require_migrated()
    from fraud_ai.models.registry import list_model_versions

    with session_scope(make_session_factory(app.engine)) as session:
        rows = list_model_versions(session)
        if not rows:
            click.echo("no models registered; run `fraud-ai train all`")
            return
        for m in rows:
            pr = (m.metrics or {}).get("test", {}).get("pr_auc")
            shown = "n/a" if pr is None else f"{pr:.3f}"
            click.echo(
                f"{m.model_name + '-' + m.model_version:<34}"
                f"{'active' if m.active else '':<8}{m.feature_version:<24}"
                f"{m.training_dataset_version:<26}test PR-AUC {shown}"
            )


@models.command("show")
@click.argument("model_ref")
@pass_app
def models_show(app: AppContext, model_ref: str) -> None:
    """Reproducibility record, metrics, warnings and inspection of one model."""
    app.require_migrated()
    from fraud_ai.models.registry import resolve_model
    from fraud_ai.models.report import model_details, threshold_table

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            m = resolve_model(session, model_ref)
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        click.echo(model_details(m))
        rows = (m.metrics or {}).get("threshold_analysis", {}).get("test")
        if rows:
            click.echo("\ntest threshold analysis (evaluation only):")
            click.echo(threshold_table(rows))


@models.command("activate")
@click.argument("model_ref")
@pass_app
def models_activate(app: AppContext, model_ref: str) -> None:
    """Mark a version active for its model name (deactivates the previous one)."""
    app.require_migrated()
    from fraud_ai.models.registry import activate_model_version, parse_model_ref

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            name, version = parse_model_ref(model_ref)
            activate_model_version(session, name, version)
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
    click.echo(f"{model_ref} is now active")


@cli.group("evaluate")
def evaluate() -> None:
    """Evaluation, calibration, error analysis and robustness (analysis only)."""


@evaluate.command("reproduce")
@click.argument("model_ref")
@pass_app
def evaluate_model(app: AppContext, model_ref: str) -> None:
    """Re-evaluate a model on its recorded dataset and split, and check reproducibility."""
    app.require_migrated()
    from fraud_ai.models.registry import resolve_model
    from fraud_ai.models.report import SYNTHETIC_NOTE, threshold_table
    from fraud_ai.models.training import reevaluate

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            result = reevaluate(session, resolve_model(session, model_ref))
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
    click.echo(
        f"{model_ref}: dataset {'unchanged' if result.dataset_matches else 'CHANGED'}, "
        f"metrics {'reproduced exactly' if result.reproduced else 'DIFFER from training'}"
    )
    for split in ("train", "validation", "test"):
        m = result.metrics[split]
        pr = "n/a" if m["pr_auc"] is None else f"{m['pr_auc']:.3f}"
        click.echo(f"  {split:<11} n={m['n']:<6} fraud={m['positives']:<5} PR-AUC={pr}")
    click.echo("test threshold analysis:")
    click.echo(threshold_table(result.metrics["threshold_analysis"]["test"]))
    click.echo(SYNTHETIC_NOTE)
    if not result.reproduced:
        sys.exit(1)


# --------------------------------------------------------------------------- evaluate (Stage 4)
def _eval_options(func: Any) -> Any:
    options = [
        click.option(
            "--bootstrap",
            "iterations",
            type=click.IntRange(50, 100000),
            default=1000,
            show_default=True,
            help="Bootstrap iterations.",
        ),
        click.option(
            "--level",
            type=click.FloatRange(0.5, 0.999),
            default=0.95,
            show_default=True,
            help="Confidence level.",
        ),
        click.option(
            "--seed", type=int, default=0, show_default=True, help="Bootstrap random seed."
        ),
        click.option(
            "--threshold",
            type=click.FloatRange(0, 1),
            default=None,
            help="Evaluation threshold (default: the model's recorded threshold).",
        ),
        click.option(
            "--output-dir",
            type=click.Path(file_okay=False, path_type=Path),
            default=None,
            help="Default: EVALUATION_DIRECTORY.",
        ),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def _settings_from(opts: dict[str, Any], **extra: Any) -> Any:
    from fraud_ai.evaluation.reports import EvaluationSettings

    return EvaluationSettings(
        iterations=opts["iterations"],
        level=opts["level"],
        seed=opts["seed"],
        threshold=opts["threshold"],
        **extra,
    )


def _out_dir(app: AppContext, opts: dict[str, Any], name: str) -> Path:
    base = opts.get("output_dir") or app.settings.evaluation_directory
    return Path(base) / name


def _with_context(
    app: AppContext, refs: list[str], body: Any, *, allow_anomaly: bool = False
) -> None:
    app.require_migrated()
    from fraud_ai.evaluation.context import build_context

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            ctx = build_context(session, refs, allow_anomaly=allow_anomaly)
            body(session, ctx)
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None


def _ci(entry: dict[str, Any]) -> str:
    if entry.get("estimate") is None:
        return "n/a"
    if entry.get("lower") is None:
        return f"{entry['estimate']:.3f}"
    return f"{entry['estimate']:.3f} [{entry['lower']:.3f}, {entry['upper']:.3f}]"


def _print_confidence(report: dict[str, Any]) -> None:
    for split in ("validation", "test"):
        part = report[split]
        click.echo(
            f"{split}: n={part['n']} fraud={part['fraud']} "
            f"({int(100 * report['level'])}% bootstrap CI, {report['iterations']} "
            f"iterations, seed {report['seed']}, threshold {report['threshold']})"
        )
        for name, entry in part["metrics"].items():
            click.echo(f"  {name:<9} {_ci(entry)}")


@evaluate.command("confidence")
@click.argument("model_ref")
@_eval_options
@pass_app
def evaluate_confidence(app: AppContext, /, model_ref: str, **opts: Any) -> None:
    """Bootstrap confidence intervals for PR-AUC, ROC-AUC, precision, recall, F1, FPR, FNR."""
    from fraud_ai.evaluation import reports

    def body(session: Any, ctx: Any) -> None:
        report = reports.confidence(ctx, ctx.model(model_ref), _settings_from(opts))
        path = reports.write_report(_out_dir(app, opts, model_ref), "confidence", report)
        _print_confidence(report)
        click.echo(f"written {path}")

    _with_context(app, [model_ref], body)


@evaluate.command("walk-forward")
@click.argument("model_ref")
@click.option("--period-days", type=click.IntRange(7, 365), default=30, show_default=True)
@click.option("--initial-periods", type=click.IntRange(1, 24), default=3, show_default=True)
@click.option("--max-folds", type=click.IntRange(1, 60), default=12, show_default=True)
@_eval_options
@pass_app
def evaluate_walk_forward(
    app: AppContext,
    /,
    model_ref: str,
    period_days: int,
    initial_periods: int,
    max_folds: int,
    **opts: Any,
) -> None:
    """Expanding-window retrain/evaluate folds with as-of labels (no future leakage)."""
    from fraud_ai.evaluation import reports
    from fraud_ai.evaluation.walk_forward import WalkForwardConfig

    config = WalkForwardConfig(
        period_days, initial_periods, max_folds, bootstrap_iterations=min(opts["iterations"], 500)
    )

    def body(session: Any, ctx: Any) -> None:
        report = reports.walk_forward_report(
            ctx, ctx.model(model_ref), _settings_from(opts, walk_forward=config)
        )
        path = reports.write_report(_out_dir(app, opts, model_ref), "walk_forward", report)
        click.echo(
            f"{'fold':<6}{'train':>8}{'fraud':>7}{'test':>7}{'fraud':>7}"
            f"{'PR-AUC':>9}{'recall':>8}{'FPR':>8}  test period"
        )
        for f in report["folds"]:
            if "test_metrics" not in f:
                click.echo(f"{f['fold']:<6}skipped: {f['skipped']}")
                continue
            m = f["test_metrics"]
            pr = "n/a" if m["pr_auc"] is None else f"{m['pr_auc']:.3f}"
            rec = "n/a" if m["recall"] is None else f"{m['recall']:.3f}"
            fpr = "n/a" if m["fpr"] is None else f"{m['fpr']:.4f}"
            click.echo(
                f"{f['fold']:<6}{f['train']['rows']:>8}{f['train']['fraud']:>7}"
                f"{f['test']['rows']:>7}{f['test']['fraud']:>7}{pr:>9}{rec:>8}{fpr:>8}"
                f"  {f['test']['start'][:10]}..{f['test']['end'][:10]}"
            )
        click.echo(f"PR-AUC across folds: {report['stability']['pr_auc']}")
        click.echo(f"written {path}")

    _with_context(app, [model_ref], body)


@evaluate.command("calibration")
@click.argument("model_ref")
@click.option(
    "--persist/--no-persist",
    default=True,
    show_default=True,
    help="Store the fitted calibrators with the model version.",
)
@_eval_options
@pass_app
def evaluate_calibration(app: AppContext, /, model_ref: str, persist: bool, **opts: Any) -> None:
    """Uncalibrated vs sigmoid vs isotonic (fitted on validation only, reported on test)."""
    from fraud_ai.evaluation import reports

    def body(session: Any, ctx: Any) -> None:
        model = ctx.model(model_ref)
        report = reports.calibration(ctx, model, _settings_from(opts))
        if persist:
            reports.persist_calibrations(session, ctx, model, report)
        path = reports.write_report(_out_dir(app, opts, model_ref), "calibration", report)
        click.echo(f"{'method':<14}{'Brier':>9}{'log loss':>10}{'ECE':>8}{'PR-AUC':>9}  (test)")
        for method, r in report["methods"].items():
            if "test" not in r:
                click.echo(f"{method:<14}{r.get('error')}")
                continue
            t = r["test"]
            pr = "n/a" if t["pr_auc"] is None else f"{t['pr_auc']:.3f}"
            ece = "n/a" if t["ece"] is None else f"{t['ece']:.4f}"
            click.echo(f"{method:<14}{t['brier']:>9.5f}{t['log_loss']:>10.4f}{ece:>8}{pr:>9}")
        click.echo("reliability (test, uncalibrated): bucket  n  mean predicted  fraud rate")
        for b in report["methods"]["uncalibrated"]["test"]["reliability"]:
            if b["count"]:
                click.echo(
                    f"  {b['lower']:.1f}-{b['upper']:.1f} {b['count']:>6} "
                    f"{b['mean_predicted']:>8.3f} {b['fraud_rate']:>8.3f}"
                )
        click.echo(f"written {path}{' (calibrators persisted)' if persist else ''}")

    _with_context(app, [model_ref], body)


@evaluate.command("scenarios")
@click.argument("model_ref")
@_eval_options
@pass_app
def evaluate_scenarios(app: AppContext, /, model_ref: str, **opts: Any) -> None:
    """Per-scenario metrics and operational-cohort false-positive checks."""
    from fraud_ai.evaluation import reports

    def body(session: Any, ctx: Any) -> None:
        report = reports.scenarios(ctx, ctx.model(model_ref), _settings_from(opts))
        path = reports.write_report(_out_dir(app, opts, model_ref), "scenarios", report)

        def f(v: Any, d: int = 3) -> str:
            return "n/a" if v is None else f"{v:.{d}f}"

        click.echo(
            f"{'segment':<28}{'n':>6}{'fraud':>6}{'recall':>8}{'FPR':>8}{'prec':>7}"
            f"{'PR-AUC':>8}  notes"
        )
        for seg in report["scenarios"]["segments"]:
            click.echo(
                f"{seg['segment']:<28}{seg['n']:>6}{seg.get('fraud', 0):>6}"
                f"{f(seg.get('recall')):>8}{f(seg.get('fpr'), 4):>8}"
                f"{f(seg.get('precision')):>7}{f(seg.get('pr_auc')):>8}  "
                f"{'; '.join(seg.get('notes', []))}"
            )
        cohorts = report["cohorts"]
        click.echo(
            f"\noperational cohorts (legitimate events; global FPR {cohorts['global_fpr']:.4f}):"
        )
        for c in cohorts["cohorts"]:
            flag = "FLAG " if c["flagged_higher_fpr"] else ""
            click.echo(
                f"  {flag}{c['cohort']:<24} n={c['legitimate_events']:<6} "
                f"FPR={f(c['fpr'], 4)} CI={c['fpr_interval_95']}"
            )
        click.echo(f"written {path}")

    _with_context(app, [model_ref], body)


@evaluate.command("errors")
@click.argument("model_ref")
@click.option("--limit", type=click.IntRange(0, 10000), default=50, show_default=True)
@_eval_options
@pass_app
def evaluate_errors(app: AppContext, /, model_ref: str, limit: int, **opts: Any) -> None:
    """False-positive and false-negative analysis (pseudonymised, no raw identifiers)."""
    from fraud_ai.evaluation import reports

    def body(session: Any, ctx: Any) -> None:
        report = reports.errors(ctx, ctx.model(model_ref), _settings_from(opts, error_limit=limit))
        path = reports.write_report(_out_dir(app, opts, model_ref), "errors", report)
        fps, fns = report["false_positives"], report["false_negatives"]
        click.echo(f"false positives: {fps['count']} by scenario {fps['by_scenario']}")
        for trait, t in fps["traits"].items():
            lift = "n/a" if t["lift"] is None else f"{t['lift']:.1f}x"
            click.echo(f"  {trait:<22} {t['false_positives_with_trait']:>4} FPs  lift {lift}")
        click.echo(f"false negatives: {fns['count']} by fraud type {fns['by_fraud_type']}")
        for ex in fns["examples"][:5]:
            click.echo(
                f"  {ex['ref']} p={ex['probability']:.3f} {ex['fraud_type']} "
                f"device_seen_before={ex['context']['device_seen_before']} "
                f"new_address={ex['context']['new_address']}"
            )
        click.echo(f"written {path}")

    _with_context(app, [model_ref], body)


@evaluate.command("costs")
@click.argument("model_ref")
@click.option("--fraud-loss", type=click.FloatRange(0), default=500.0, show_default=True)
@click.option("--review-cost", type=click.FloatRange(0), default=5.0, show_default=True)
@click.option("--step-up-cost", type=click.FloatRange(0), default=1.0, show_default=True)
@click.option(
    "--friction",
    type=click.FloatRange(0),
    default=10.0,
    show_default=True,
    help="Cost of inconveniencing a legitimate customer.",
)
@click.option(
    "--loss-mode", type=click.Choice(["fixed", "amount"]), default="fixed", show_default=True
)
@click.option(
    "--bands",
    default="0.3,0.7",
    show_default=True,
    help="Conceptual low/review/high band boundaries.",
)
@_eval_options
@pass_app
def evaluate_costs(
    app: AppContext,
    /,
    model_ref: str,
    fraud_loss: float,
    review_cost: float,
    step_up_cost: float,
    friction: float,
    loss_mode: str,
    bands: str,
    **opts: Any,
) -> None:
    """Expected cost per threshold and risk-band analysis (decision support only)."""
    from fraud_ai.evaluation import reports
    from fraud_ai.evaluation.costs import CostConfig

    try:
        low, high = (float(x) for x in bands.split(","))
        if not 0 < low < high < 1:
            raise ValueError("bands must satisfy 0 < low < high < 1")
        config = CostConfig(
            fraud_loss, review_cost, step_up_cost, friction, fraud_loss_mode=loss_mode
        )
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from None

    def body(session: Any, ctx: Any) -> None:
        settings = _settings_from(opts, costs=config, bands=(low, high))
        model = ctx.model(model_ref)
        report = reports.costs(ctx, model, settings)
        bands_report = reports.thresholds(ctx, model, settings)
        path = reports.write_report(_out_dir(app, opts, model_ref), "costs", report)
        reports.write_report(_out_dir(app, opts, model_ref), "thresholds", bands_report)
        curve = report["manual_review"]
        click.echo(f"{'thr':>6}{'caught':>8}{'missed':>8}{'FP':>6}{'flagged':>9}{'total cost':>13}")
        for r in curve["rows"]:
            label = r["label"] or f"{r['threshold']:.2f}"
            click.echo(
                f"{label:>6}{r['fraud_caught']:>8}{r['fraud_missed']:>8}"
                f"{r['false_positives']:>6}{r['flagged']:>9}{r['total_cost']:>13.2f}"
            )
        click.echo(
            f"lowest-cost threshold in this experiment: {curve['lowest_cost_threshold']} "
            "(NOT applied - decision support only)"
        )
        for b in bands_report["bands"]["bands"]:
            click.echo(
                f"  band {b['band']:<10} {b['range']} population "
                f"{100 * (b['population_share'] or 0):.1f}%  fraud {b['fraud']} "
                f"({100 * (b['share_of_all_fraud'] or 0):.0f}% of all)  "
                f"legitimate {b['legitimate_in_band']}"
            )
        click.echo(f"written {path}")

    _with_context(app, [model_ref], body)


def _default_comparison_refs(app: AppContext) -> list[str]:
    from collections import Counter

    from fraud_ai.models.registry import list_model_versions

    with session_scope(make_session_factory(app.engine)) as session:
        rows = list_model_versions(session)
        if not rows:
            raise click.ClickException("no models registered")
        from fraud_ai.models.factory import is_anomaly_model

        rows = [r for r in rows if not is_anomaly_model(r.model_name)]
        if not rows:
            raise click.ClickException("no fraud models registered")
        counts = Counter(r.dataset_fingerprint for r in rows)
        latest = max(rows, key=lambda r: r.training_timestamp).dataset_fingerprint
        best = max(counts, key=lambda fp: (counts[fp], fp == latest))
        return [f"{r.model_name}-{r.model_version}" for r in rows if r.dataset_fingerprint == best]


@evaluate.command("compare")
@click.argument("model_refs", nargs=-1)
@_eval_options
@pass_app
def evaluate_compare(app: AppContext, /, model_refs: tuple[str, ...], **opts: Any) -> None:
    """Paired tests, agreement and ensemble research on identical examples."""
    from fraud_ai.evaluation import reports

    refs = list(model_refs) or _default_comparison_refs(app)
    if len(refs) < 2:
        raise click.ClickException("need at least two models trained on the same dataset")

    def body(session: Any, ctx: Any) -> None:
        report = reports.compare(ctx, _settings_from(opts))
        path = reports.write_report(
            _out_dir(app, opts, f"comparisons/{ctx.fingerprint[:16]}"), "compare", report
        )
        for name, part in report["confidence"].items():
            click.echo(f"{name:<34} PR-AUC {_ci(part['metrics']['pr_auc'])}")
        for pair in report["pairwise"]:
            d = pair["pr_auc_difference"]
            click.echo(
                f"{pair['a']} - {pair['b']}: {_ci(d)}  McNemar p="
                f"{pair['mcnemar']['p_value']:.3f}  -> {pair['conclusion']}"
            )
        click.echo("agreement groups (test):")
        for g in report["agreement"]["groups"]:
            click.echo(
                f"  {g['group']:<44} {g['events']:>6} events  fraud rate {g['fraud_rate']:.3f}"
            )
        ens = report["ensembles"]
        click.echo(f"ensembles vs {ens['reference_model']} (chosen on validation):")
        for name, e in ens["ensembles"].items():
            click.echo(
                f"  {name:<24} PR-AUC {_ci(e['pr_auc'])}  difference "
                f"{_ci(e['vs_reference_pr_auc_difference'])}  appears useful: "
                f"{e['appears_useful']}"
            )
        click.echo(f"written {path}")

    _with_context(app, refs, body)


@evaluate.command("drift-baseline")
@click.option(
    "--model", "model_ref", required=True, help="Model whose training split defines the reference."
)
@_eval_options
@pass_app
def evaluate_drift_baseline(app: AppContext, /, model_ref: str, **opts: Any) -> None:
    """Reference distributions (PSI / Jensen-Shannon) from the model's training data."""
    from fraud_ai.evaluation import reports

    def body(session: Any, ctx: Any) -> None:
        report = reports.drift_baseline(ctx, _settings_from(opts), ctx.model(model_ref))
        path = reports.write_report(_out_dir(app, opts, model_ref), "drift_baseline", report)
        click.echo(f"reference: training split ({report['baseline']['rows']} rows)")
        click.echo("test period vs baseline:")
        for name, r in report["test_period_vs_baseline"]["features"].items():
            click.echo(f"  {name:<32} PSI {r['psi']:.4f}  JS {r['js_distance']:.4f}  {r['status']}")
        click.echo(f"written {path}")

    _with_context(app, [model_ref], body)


@evaluate.command("report")
@click.argument("model_ref")
@_eval_options
@pass_app
def evaluate_report(app: AppContext, /, model_ref: str, **opts: Any) -> None:
    """Write every per-model report (summary, confidence, thresholds, calibration, scenarios,
    errors, costs, walk-forward, drift baseline)."""
    from fraud_ai.evaluation import reports

    def body(session: Any, ctx: Any) -> None:
        paths = reports.full_model_report(
            ctx, ctx.model(model_ref), _settings_from(opts), _out_dir(app, opts, model_ref), session
        )
        for name, path in sorted(paths.items()):
            click.echo(f"{name:<16} {path}")

    _with_context(app, [model_ref], body)


@cli.command("compare-models")
@click.option(
    "--dataset",
    "dataset_prefix",
    default=None,
    help="Only models trained on this dataset fingerprint (prefix).",
)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@pass_app
def compare_models(app: AppContext, dataset_prefix: str | None, fmt: str) -> None:
    """Compare registered models (warns when they were trained on different datasets)."""
    app.require_migrated()
    from fraud_ai.models.registry import list_model_versions
    from fraud_ai.models.report import comparison_rows, comparison_table

    with session_scope(make_session_factory(app.engine)) as session:
        rows = [
            m
            for m in list_model_versions(session)
            if dataset_prefix is None or (m.dataset_fingerprint or "").startswith(dataset_prefix)
        ]
        if not rows:
            raise click.ClickException("no matching models")
        if fmt == "json":
            click.echo(json.dumps(comparison_rows(rows), indent=2, default=str))
        else:
            click.echo(comparison_table(rows))


@cli.command("score")
@click.argument("event_id")
@click.option("--model", "model_ref", required=True, help="e.g. gradient-boosting-1.0.0")
@click.option(
    "--threshold",
    type=click.FloatRange(0, 1),
    default=None,
    help="Default: the threshold recorded with the model.",
)
@pass_app
def score(app: AppContext, event_id: str, model_ref: str, threshold: float | None) -> None:
    """Score one event and store the prediction (no decision is taken)."""
    app.require_migrated()
    from fraud_ai.models.registry import resolve_model
    from fraud_ai.models.scoring import score_event

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            result = score_event(
                session,
                _parse_uuid(event_id),
                resolve_model(session, model_ref),
                threshold=threshold,
            )
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        p = result.prediction
        click.echo(f"{'existing' if result.existing else 'new'} prediction {p.prediction_id}")
        click.echo(f"  model        {p.model_name}-{p.model_version} ({p.feature_version})")
        click.echo(f"  snapshot     {result.snapshot_id} (as of the event time)")
        click.echo(f"  probability  {p.fraud_probability:.6f}")
        click.echo(
            f"  threshold    {p.threshold}  predicted_class {p.predicted_class} "
            "(evaluation only - no decision)"
        )


# --------------------------------------------------------------------------- system-status
@cli.command("system-status")
@pass_app
def system_status(app: AppContext) -> None:
    """Report configuration and the health of each platform component."""
    s = app.settings
    click.echo(
        f"fraud-ai {__version__}  environment={s.environment.value}  log_level={s.log_level}"
    )
    click.echo(f"database        {s.safe_database_url}")
    try:
        status = mig.schema_status(app.engine, s.resolved_database_url)
        state = (
            "up to date"
            if status.up_to_date
            else f"migration pending ({status.current or 'empty'} -> {status.head})"
        )
        click.echo(f"  schema        {state}")
    except SQLAlchemyError as exc:
        status = None
        click.echo(f"  schema        UNREACHABLE ({exc.__class__.__name__})")

    def _exists(path: Path) -> str:
        return "exists" if path.exists() else "missing"

    click.echo(f"data directory  {s.data_directory} ({_exists(s.data_directory)})")
    click.echo(f"model directory {s.model_directory} ({_exists(s.model_directory)})")
    key_state = "configured" if s.pseudonymisation_key else "development key file"
    click.echo(f"pseudonymisation key  {key_state}")
    click.echo(f"raw IP storage  {'enabled' if s.store_raw_ip else 'disabled'}")
    if status is not None and status.up_to_date:
        from fraud_ai.models.registry import list_model_versions

        with session_scope(make_session_factory(app.engine)) as session:
            versions = list_model_versions(session)
            active = [f"{v.model_name}:{v.model_version}" for v in versions if v.active]
            click.echo(
                f"model registry  {len(versions)} versions, active: {', '.join(active) or 'none'}"
            )
    from fraud_ai.features.definitions import DEFAULT_FEATURE_VERSION, get_feature_set

    fs = get_feature_set(DEFAULT_FEATURE_VERSION)
    click.echo(f"feature engine  {fs.version} ({len(fs.definitions)} features)")
    if status is not None and status.up_to_date:
        from fraud_ai.database.models import FeatureSnapshot

        with session_scope(make_session_factory(app.engine)) as session:
            snapshots = session.scalar(select(func.count()).select_from(FeatureSnapshot))
        click.echo(f"  snapshots     {snapshots}")
    if status is not None and status.up_to_date:
        from fraud_ai.risk.registry import active_deployment

        with session_scope(make_session_factory(app.engine)) as session:
            try:
                deployed = active_deployment(session)
                policy_state = (
                    f"{deployed.policy.policy_version} (deployment #{deployed.deployment.sequence})"
                    if deployed
                    else "none active (decisions fall back to MANUAL_REVIEW)"
                )
            except FraudAIError as exc:
                policy_state = f"UNTRUSTED ({exc})"
        click.echo(f"risk policy     {policy_state}")
    if s.local_llm_runtime:
        llm_state = f"{s.local_llm_runtime} {s.local_llm_model or ''}".rstrip()
        llm_state += " (explanations only; see `fraud-ai llm status`)"
    else:
        llm_state = "not configured (explanations only; reference template available)"
    click.echo(f"local LLM       {llm_state}")
    if status is not None and status.up_to_date:
        from fraud_ai.database.models import Investigation

        with session_scope(make_session_factory(app.engine)) as session:
            stored = session.scalar(select(func.count()).select_from(Investigation))
        click.echo(f"  investigations {stored}")


# --------------------------------------------------------------------------- sequence (Stage 6)
@cli.group()
def sequence() -> None:
    """Point-in-time user event sequences and sequence-model analysis."""


def _definition_from(max_events: int, max_age_days: float | None, lookback_days: float) -> Any:
    from fraud_ai.sequences.definition import SequenceDefinition

    try:
        return SequenceDefinition(
            max_events=max_events, max_age_days=max_age_days, lookback_days=lookback_days
        )
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from None


def _window_options(func: Any) -> Any:
    for option in reversed(
        [
            click.option(
                "--max-events", type=click.IntRange(1, 512), default=16, show_default=True
            ),
            click.option(
                "--max-age-days", type=click.FloatRange(min=0, min_open=True), default=None
            ),
            click.option(
                "--lookback-days",
                type=click.FloatRange(min=0, min_open=True),
                default=365.0,
                show_default=True,
            ),
        ]
    ):
        func = option(func)
    return func


def _build_one(app: AppContext, event_id: str, definition: Any) -> Any:
    app.require_migrated()
    from fraud_ai.sequences.extraction import build_sequence

    try:
        target = uuid.UUID(event_id)
    except ValueError:
        raise click.BadParameter(f"{event_id!r} is not an event id") from None
    with session_scope(make_session_factory(app.engine)) as session:
        try:
            return build_sequence(session, target, definition)
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None


@sequence.command("build")
@click.argument("event_id")
@_window_options
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
@pass_app
def sequence_build(
    app: AppContext,
    event_id: str,
    max_events: int,
    max_age_days: float | None,
    lookback_days: float,
    output: Path | None,
) -> None:
    """Build the point-in-time sequence of one event (JSON; deterministic)."""
    definition = _definition_from(max_events, max_age_days, lookback_days)
    batch = _build_one(app, event_id, definition)
    payload = {
        "definition": definition.to_dict(),
        "sequence_digest": batch.digest(),
        "length": int(batch.lengths[0]),
        "positions": batch.decode(0),
        "note": "Only events strictly before the scored event; the last position is the "
        "scored event itself. No identifiers are included.",
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    if output:
        output.write_text(text + "\n")
        click.echo(f"written {output}")
    else:
        click.echo(text)


@sequence.command("inspect")
@click.argument("event_id")
@_window_options
@pass_app
def sequence_inspect(
    app: AppContext,
    event_id: str,
    max_events: int,
    max_age_days: float | None,
    lookback_days: float,
) -> None:
    """Readable view of one event's sequence (types, gaps, known flags, changes)."""
    definition = _definition_from(max_events, max_age_days, lookback_days)
    batch = _build_one(app, event_id, definition)
    click.echo(
        f"{definition.version}  fingerprint {definition.fingerprint()[:16]}  "
        f"length {int(batch.lengths[0])}/{definition.length}"
    )
    click.echo(
        f"{'#':>3} {'event':<24}{'h before':>9}{'gap min':>9} {'network':<12}"
        f"{'dev?':>5}{'net?':>5}{'addr?':>6}{'amount':>9}  flags"
    )
    import math

    for i, p in enumerate(batch.decode(0)):
        flags = [
            name
            for name in (
                "device_changed",
                "asn_changed",
                "country_changed",
                "vpn",
                "proxy_or_tor",
                "is_security_event",
                "is_label_event",
                "is_target",
            )
            if p[name]
        ]
        amount = f"{math.expm1(p['log_amount']):.2f}" if p["has_amount"] else ""
        addr = ("yes" if p["address_known"] else "no") if p["has_address"] else "-"
        click.echo(
            f"{i:>3} {p['event_type']:<24}{math.expm1(p['log_hours_before_target']):>9.1f}"
            f"{math.expm1(p['log_minutes_since_previous']):>9.0f} {p['network_type']:<12}"
            f"{'yes' if p['device_known'] else 'no':>5}"
            f"{'yes' if p['network_known'] else 'no':>5}{addr:>6}{amount:>9}  "
            f"{','.join(flags)}"
        )


def _fraud_refs_with(app: AppContext, base: str) -> list[str]:
    from fraud_ai.models.factory import is_anomaly_model
    from fraud_ai.models.registry import list_model_versions, resolve_model

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            record = resolve_model(session, base)
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        return [
            f"{m.model_name}-{m.model_version}"
            for m in list_model_versions(session)
            if m.dataset_fingerprint == record.dataset_fingerprint
            and not is_anomaly_model(m.model_name)
        ]


@sequence.command("compare")
@click.argument("model_refs", nargs=-1)
@click.option("--base", "base_ref", default="gradient-boosting-1.0.0", show_default=True)
@_eval_options
@pass_app
def sequence_compare(
    app: AppContext, /, model_refs: tuple[str, ...], base_ref: str, **opts: Any
) -> None:
    """Which fraud each sequence model catches that BASE misses (and vice versa)."""
    import numpy as np

    from fraud_ai.evaluation import reports
    from fraud_ai.evaluation.complementarity import complementarity

    refs = list(model_refs) or _fraud_refs_with(app, base_ref)
    refs = [base_ref, *[r for r in refs if r != base_ref]]

    def body(session: Any, ctx: Any) -> None:
        base = ctx.model(base_ref)
        others = [m for m in ctx.models if m.model_id != base_ref]
        if not others:
            raise EvaluationFailed("no other model to compare with")
        y = ctx.labels("test")
        caught = {m.model_id: (m.scores["test"] >= m.threshold) & (y == 1) for m in ctx.models}
        missed_by_all = int(((y == 1) & ~np.logical_or.reduce(list(caught.values()))).sum())
        result = {
            "base": base.model_id,
            "fraud_events": int(y.sum()),
            "missed_by_all_models": missed_by_all,
            "comparisons": {},
        }
        click.echo(f"test fraud {int(y.sum())}; missed by every model: {missed_by_all}")
        click.echo(
            f"{'model':<30}{'both':>6}{'only base':>11}{'only it':>9}{'neither':>9}"
            f"{'new FP':>8}  combined PR-AUC vs base"
        )
        for other in others:
            comp = complementarity(
                ctx, base, other, iterations=opts["iterations"], seed=opts["seed"]
            )
            result["comparisons"][other.model_id] = comp
            o = comp["fraud_detection_overlap"]
            avg = (
                comp["combinations"].get("average_probability")
                or comp["combinations"]["rank_average"]
            )
            click.echo(
                f"{other.model_id:<30}{o['caught_by_both']['count']:>6}"
                f"{o[f'caught_only_by_{base.model_id}']['count']:>11}"
                f"{o[f'caught_only_by_{other.model_id}']['count']:>9}"
                f"{o['missed_by_both']['count']:>9}{o['legitimate_flagged_only_by_other']:>8}"
                f"  {_ci(avg['vs_base_pr_auc_difference'])}"
            )
        path = reports.write_report(
            _out_dir(app, opts, f"comparisons/{ctx.fingerprint[:16]}"),
            "sequence_compare",
            ctx.header("sequence_compare", settings=_settings_from(opts).to_dict(), **result),
        )
        click.echo(f"written {path}")

    _with_context(app, refs, body)


@sequence.command("stealth-report")
@click.argument("model_refs", nargs=-1)
@click.option(
    "--base",
    "base_ref",
    default="gradient-boosting-1.0.0",
    show_default=True,
    help="Used to find the models trained on the same dataset.",
)
@click.option("--output-dir", type=click.Path(file_okay=False, path_type=Path), default=None)
@pass_app
def sequence_stealth_report(
    app: AppContext, model_refs: tuple[str, ...], base_ref: str, output_dir: Path | None
) -> None:
    """Stealthy / temporal takeover cases: every model's probability and prior behaviour."""
    from fraud_ai.evaluation import reports
    from fraud_ai.evaluation.stealth import stealth_report

    refs = list(model_refs) or _fraud_refs_with(app, base_ref)

    def body(session: Any, ctx: Any) -> None:
        report = stealth_report(ctx)
        path = reports.write_report(
            _out_dir(app, {"output_dir": output_dir}, f"comparisons/{ctx.fingerprint[:16]}"),
            "stealth_report",
            ctx.header("stealth_report", **report),
        )
        click.echo(
            f"stealthy / temporal takeover cases in test: {report['cases']} {report['by_scenario']}"
        )
        for name, r in report["recall_by_model"].items():
            click.echo(f"  {name:<32} recall {'n/a' if r is None else f'{r:.2f}'}")
        click.echo(
            f"caught only by sequence models: {report['caught_only_by_sequence_models']}"
            f"; missed by all: {report['missed_by_all']}"
        )
        click.echo(f"written {path}")

    _with_context(app, refs, body)


# --------------------------------------------------------------------------- neural (Stage 5)
@cli.group()
def neural() -> None:
    """Neural-network experiments and inspection (PyTorch)."""


def _load_neural(session: Any, model_ref: str) -> tuple[Any, Any]:
    from fraud_ai.models.neural import NeuralNetworkModel
    from fraud_ai.models.registry import resolve_model
    from fraud_ai.models.scoring import load_registered_model

    record = resolve_model(session, model_ref)
    loaded = load_registered_model(record)
    if not isinstance(loaded, NeuralNetworkModel):
        raise click.ClickException(f"{model_ref} is not a neural-network model")
    return record, loaded


@neural.command("experiments")
@_training_options
@click.option("--quick", is_flag=True, help="Tiny 2-configuration grid (smoke test).")
@click.option("--max-epochs", type=click.IntRange(1), default=60, show_default=True)
@click.option("--patience", type=click.IntRange(1), default=8, show_default=True)
@click.option("--no-focal", is_flag=True, help="Skip the focal-loss comparison.")
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Default: EVALUATION_DIRECTORY/neural_experiments/<dataset>.",
)
@pass_app
def neural_experiments(
    app: AppContext,
    /,
    quick: bool,
    max_epochs: int,
    patience: int,
    no_focal: bool,
    output_dir: Path | None,
    **opts: Any,
) -> None:
    """Small hyperparameter grid, selected on validation PR-AUC (test split untouched)."""
    app.require_migrated()
    from fraud_ai.evaluation.reports import write_report
    from fraud_ai.models.experiments import ExperimentGrid, run_experiments
    from fraud_ai.models.training import prepare_data

    base = {"max_epochs": max_epochs, "patience": patience}
    grid = (
        ExperimentGrid(
            hidden_sizes=((16,), (32, 16)),
            dropout=(0.1,),
            learning_rate=(1e-3,),
            weight_decay=(0.0,),
            base=base,
            compare_focal_loss=not no_focal,
        )
        if quick
        else ExperimentGrid(base=base, compare_focal_loss=not no_focal)
    )

    def progress(i: int, n: int, r: dict[str, Any]) -> None:
        pr = r["validation_pr_auc"]
        click.echo(
            f"[{i:>2}/{n}] hidden={r['hyperparameters']['hidden_sizes']} "
            f"dropout={r['hyperparameters']['dropout']} "
            f"lr={r['hyperparameters']['learning_rate']} "
            f"wd={r['hyperparameters']['weight_decay']}  val PR-AUC "
            f"{'n/a' if pr is None else f'{pr:.4f}'}  epoch {r['best_epoch']}/"
            f"{r['epochs_completed']}  {r['train_seconds']:.1f}s"
        )

    try:
        config = _training_config(opts)
        with session_scope(make_session_factory(app.engine)) as session:
            prepared = prepare_data(session, config)
            result = run_experiments(
                prepared, grid, seed=config.seed, imbalance=config.imbalance, progress=progress
            )
    except FraudAIError as exc:
        raise click.ClickException(str(exc)) from None
    directory = output_dir or (
        Path(app.settings.evaluation_directory)
        / "neural_experiments"
        / result["dataset_fingerprint"][:16]
    )
    path = write_report(directory, "experiments", result)
    sel = result["selected"]
    click.echo(
        f"selected (validation PR-AUC {sel['validation_pr_auc']}): "
        f"{json.dumps(sel['hyperparameters'], sort_keys=True)}"
    )
    if loss := result["loss_experiment"]:
        click.echo(
            f"focal vs weighted BCE (validation PR-AUC difference): "
            f"{loss['difference_validation_pr_auc']}"
        )
    click.echo("test split not used; nothing registered. SYNTHETIC data.")
    click.echo(f"written {path}")


@neural.command("training-history")
@click.argument("model_ref")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@pass_app
def neural_training_history(app: AppContext, model_ref: str, fmt: str) -> None:
    """Per-epoch losses, PR-AUC and learning rate; marks the restored (best) epoch."""
    app.require_migrated()
    with session_scope(make_session_factory(app.engine)) as session:
        try:
            _, model = _load_neural(session, model_ref)
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
    if fmt == "json":
        click.echo(
            json.dumps(
                {"history": model.history, "summary": model.training_summary}, indent=2, default=str
            )
        )
        return

    def f(v: Any, d: int = 4) -> str:
        return "n/a" if v is None else f"{v:.{d}f}"

    best = model.training_summary.get("best_epoch")
    click.echo(
        f"{'epoch':>5}{'train loss':>12}{'val loss':>10}{'train PR':>10}"
        f"{'val PR':>9}{'val ROC':>9}{'lr':>10}"
    )
    for h in model.history:
        mark = "  <- restored" if h["epoch"] == best else ""
        click.echo(
            f"{h['epoch']:>5}{f(h['train_loss']):>12}{f(h['validation_loss']):>10}"
            f"{f(h['train_pr_auc']):>10}{f(h['validation_pr_auc']):>9}"
            f"{f(h['validation_roc_auc']):>9}{h['learning_rate']:>10.1e}{mark}"
        )
    summary = model.training_summary
    click.echo(
        f"selection: {summary.get('selection_metric')} on "
        f"{summary.get('validation_source')}; best epoch {best} of "
        f"{summary.get('epochs_completed')}"
    )
    for flag in summary.get("overfitting_flags", []):
        click.echo(f"WARNING: {flag}")


@neural.command("inspect")
@click.argument("model_ref")
@pass_app
def neural_inspect(app: AppContext, model_ref: str) -> None:
    """Architecture, parameter count, configuration, training summary and importance."""
    app.require_migrated()
    with session_scope(make_session_factory(app.engine)) as session:
        try:
            record, model = _load_neural(session, model_ref)
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        explanation = (record.metrics or {}).get("explanation", {})
        manifest = model.manifest()
    click.echo(
        f"{model.model_id}  parameters {manifest['parameter_count']}  "
        f"inputs {manifest['output_columns']}  optimiser {manifest['optimizer']}"
    )
    for layer in manifest["architecture"]:
        click.echo(f"  {layer}")
    click.echo(f"hyperparameters {json.dumps(manifest['hyperparameters'], sort_keys=True)}")
    t = manifest["training"]
    click.echo(
        f"loss {t.get('loss')} (pos_weight {t.get('pos_weight', 0):.1f})  best epoch "
        f"{t.get('best_epoch')}/{t.get('epochs_completed')}  selection "
        f"{t.get('selection_metric')}"
    )
    click.echo(f"environment {json.dumps(manifest['environment'], sort_keys=True)}")
    for flag in t.get("overfitting_flags", []):
        click.echo(f"WARNING: {flag}")
    if explanation:
        click.echo(f"inspection ({explanation.get('method')}) - not used by any decision:")
        for item in explanation.get("top_features", [])[:12]:
            click.echo(f"  {item['feature']:<42} {item['importance']:+.4f}")
    click.echo(
        "A neural network is not inherently interpretable; permutation importance "
        "describes reliance on this (SYNTHETIC) data, not causes."
    )


# --------------------------------------------------------------------------- anomaly (Stage 5)
@cli.group()
def anomaly() -> None:
    """EXPERIMENTAL autoencoder anomaly scores (unusual behaviour - not fraud probability)."""


@anomaly.command("train-autoencoder")
@_training_options_with(0.95, "Anomaly-score threshold used for evaluation (not a decision).")
@click.option("--hidden", default="64,32", show_default=True, help="Encoder layer sizes.")
@click.option("--bottleneck", type=click.IntRange(1), default=8, show_default=True)
@click.option("--dropout", type=click.FloatRange(0, 0.95), default=0.0, show_default=True)
@click.option("--batch-size", type=click.IntRange(1), default=256, show_default=True)
@click.option(
    "--learning-rate", type=click.FloatRange(min=0, min_open=True), default=1e-3, show_default=True
)
@click.option("--weight-decay", type=click.FloatRange(0), default=1e-5, show_default=True)
@click.option("--max-epochs", type=click.IntRange(1), default=80, show_default=True)
@click.option("--patience", type=click.IntRange(1), default=8, show_default=True)
@click.option(
    "--device", type=click.Choice(["auto", "cpu", "cuda"]), default="cpu", show_default=True
)
@pass_app
def anomaly_train(app: AppContext, /, **opts: Any) -> None:
    """Train on legitimate training rows only; outputs an anomaly score, never a decision."""
    hyperparameters = {
        "hidden_sizes": _int_list(opts.pop("hidden")),
        **{
            k: opts.pop(k)
            for k in (
                "bottleneck",
                "dropout",
                "batch_size",
                "learning_rate",
                "weight_decay",
                "max_epochs",
                "patience",
                "device",
            )
        },
    }
    _run_train(app, ["autoencoder"], {"autoencoder": hyperparameters}, **opts)
    click.echo(
        "The anomaly score is NOT a fraud probability; it cannot be used with `fraud-ai score`."
    )


def _anomaly_ref(ref: str) -> str:
    return ref if ref.startswith("autoencoder") else f"autoencoder-{ref}"


@anomaly.command("evaluate")
@click.argument("version")
@click.option(
    "--compare-with",
    "compare_ref",
    default=None,
    help="A fraud model on the same dataset: where does the anomaly score help it?",
)
@_eval_options
@pass_app
def anomaly_evaluate(
    app: AppContext, /, version: str, compare_ref: str | None, **opts: Any
) -> None:
    """Anomaly-score distributions, PR-AUC, FPR at anomaly thresholds, scenarios, shift."""
    from fraud_ai.evaluation import reports
    from fraud_ai.evaluation.anomaly_report import anomaly_evaluation
    from fraud_ai.evaluation.complementarity import complementarity
    from fraud_ai.models.factory import is_anomaly_model

    ref = _anomaly_ref(version)
    refs = [ref] + ([compare_ref] if compare_ref else [])

    def body(session: Any, ctx: Any) -> None:
        model = ctx.model(ref)
        if not is_anomaly_model(model.record.model_name):
            raise EvaluationFailed(f"{ref} is not an anomaly model")
        report = anomaly_evaluation(ctx, model, iterations=opts["iterations"], seed=opts["seed"])
        if compare_ref:
            base = ctx.model(compare_ref)
            if is_anomaly_model(base.record.model_name):
                raise EvaluationFailed("--compare-with must be a fraud model")
            report["versus_fraud_model"] = complementarity(
                ctx, base, model, iterations=opts["iterations"], seed=opts["seed"]
            )
        body_report = ctx.header("anomaly", model=model.model_id, **report)
        path = reports.write_report(_out_dir(app, opts, ref), "anomaly", body_report)
        d = report["distributions"]
        click.echo("anomaly score (NOT a fraud probability) - test split:")
        for cls in ("fraud", "legitimate"):
            x = d[cls]
            if x["n"]:
                click.echo(
                    f"  {cls:<11} n={x['n']:<6} median {x['p50']:.3f}  p90 "
                    f"{x['p90']:.3f}  mean {x['mean']:.3f}"
                )
        click.echo(
            f"  PR-AUC {_ci(report['ranking']['pr_auc'])}  ROC-AUC "
            f"{_ci(report['ranking']['roc_auc'])}  prevalence "
            f"{report['ranking']['prevalence']:.4f}"
        )
        for f in report["flagging"]:
            rec = "n/a" if f["recall"] is None else f"{f['recall']:.3f}"
            fpr = "n/a" if f["fpr"] is None else f"{f['fpr']:.4f}"
            click.echo(
                f"  >= {f['threshold']:.2f}: flags {100 * f['flagged_share']:.1f}%  "
                f"recall {rec}  FPR {fpr}"
            )
        if compare_ref:
            m = report["versus_fraud_model"]["base_misses_and_false_alarms"]
            click.echo(
                f"  {compare_ref} missed {m['base_false_negatives']} fraud; anomaly >= "
                f"threshold on {m['caught_by_other']} of them"
            )
        click.echo(f"written {path}")

    _with_context(app, refs, body, allow_anomaly=True)


class EvaluationFailed(FraudAIError):
    pass


@evaluate.command("complementarity")
@click.argument("base_ref")
@click.argument("other_ref")
@click.option(
    "--anomaly",
    "anomaly_ref",
    default=None,
    help="Optional autoencoder version/ref to include as a separate signal.",
)
@_eval_options
@pass_app
def evaluate_complementarity(
    app: AppContext, /, base_ref: str, other_ref: str, anomaly_ref: str | None, **opts: Any
) -> None:
    """Does OTHER add signal where BASE fails? Disagreement groups, misses, combinations."""
    from fraud_ai.evaluation import reports
    from fraud_ai.evaluation.complementarity import complementarity
    from fraud_ai.models.factory import is_anomaly_model

    refs = [base_ref, other_ref] + ([_anomaly_ref(anomaly_ref)] if anomaly_ref else [])

    def body(session: Any, ctx: Any) -> None:
        base, other = ctx.model(base_ref), ctx.model(other_ref)
        for m in (base, other):
            if is_anomaly_model(m.record.model_name):
                raise EvaluationFailed(f"{m.model_id} is an anomaly model; pass it as --anomaly")
        extra = ctx.model(_anomaly_ref(anomaly_ref)) if anomaly_ref else None
        report = complementarity(
            ctx, base, other, anomaly=extra, iterations=opts["iterations"], seed=opts["seed"]
        )
        path = reports.write_report(
            _out_dir(app, opts, f"comparisons/{ctx.fingerprint[:16]}"),
            f"complementarity_{base.model_id}_vs_{other.model_id}",
            ctx.header("complementarity", settings=_settings_from(opts).to_dict(), **report),
        )
        for name, g in report["disagreement"]["groups"].items():
            rate = "n/a" if g["fraud_rate"] is None else f"{g['fraud_rate']:.3f}"
            click.echo(f"  {name:<64} {g['events']:>6} events  fraud {g['fraud']:>4}  rate {rate}")
        m = report["base_misses_and_false_alarms"]
        click.echo(
            f"{base.model_id} false negatives {m['base_false_negatives']}: caught by "
            f"{other.model_id} {m['caught_by_other']}; false positives "
            f"{m['base_false_positives']}: cleared {m['cleared_by_other']}"
        )
        for name, c in report["combinations"].items():
            click.echo(
                f"  {name:<28} PR-AUC {_ci(c['pr_auc'])}  vs base "
                f"{_ci(c['vs_base_pr_auc_difference'])}  adds signal: "
                f"{c['adds_signal']}"
            )
        click.echo(f"written {path}")

    _with_context(app, refs, body, allow_anomaly=anomaly_ref is not None)


# --------------------------------------------------------------------------- llm (Stage 7)
def _generation_settings(s: Settings) -> Any:
    from fraud_ai.llm.service import GenerationSettings

    return GenerationSettings(
        temperature=s.local_llm_temperature,
        top_p=s.local_llm_top_p,
        seed=s.local_llm_seed,
        max_tokens=s.local_llm_max_tokens,
        context_window=s.local_llm_context_window,
    )


def _llm_client(s: Settings, runtime: str | None = None, model: str | None = None) -> Any:
    """The configured local runtime (or an explicit override). Never a remote service."""
    from fraud_ai.llm.runtime import LLMRuntimeError, make_client

    runtime = runtime or s.local_llm_runtime
    if runtime is None:
        raise click.ClickException(
            "no local LLM runtime configured: set LOCAL_LLM_RUNTIME (ollama, llamacpp-server, "
            "llamacpp-process) or pass --runtime reference for the built-in template "
            "(not an LLM)"
        )
    try:
        return make_client(
            runtime,
            model=model or s.local_llm_model,
            endpoint=s.local_llm_endpoint,
            timeout=s.local_llm_timeout,
            binary=s.local_llm_binary,
            model_path=str(s.local_llm_model_path) if s.local_llm_model_path else None,
        )
    except LLMRuntimeError as exc:
        raise click.ClickException(str(exc)) from None


def _runtime_spec(spec: str) -> tuple[str, str | None]:
    runtime, _, model = spec.partition(":")
    return runtime, model or None


_RUNTIME_OPTION = click.option(
    "--runtime",
    "runtime_spec",
    default=None,
    help="RUNTIME[:MODEL], e.g. ollama:qwen2.5:7b or reference. Default: LOCAL_LLM_RUNTIME.",
)


@cli.group()
def llm() -> None:
    """Local, offline analyst assistant: runtime status, models and benchmarks."""


@llm.command("status")
@_RUNTIME_OPTION
@pass_app
def llm_status(app: AppContext, runtime_spec: str | None) -> None:
    """Show the local LLM configuration and whether the runtime is reachable."""
    from fraud_ai.llm.evidence import EVIDENCE_SCHEMA_VERSION
    from fraud_ai.llm.prompt import PROMPT_VERSION
    from fraud_ai.llm.runtime import DEFAULT_ENDPOINTS
    from fraud_ai.llm.schema import EXPLANATION_SCHEMA_VERSION

    s = app.settings
    runtime, model = _runtime_spec(runtime_spec) if runtime_spec else (s.local_llm_runtime, None)
    click.echo(f"runtime           {runtime or 'not configured'}")
    click.echo(f"model             {model or s.local_llm_model or '-'}")
    endpoint = s.local_llm_endpoint or DEFAULT_ENDPOINTS.get(runtime or "", "-")
    click.echo(f"endpoint          {endpoint} (local only)")
    click.echo(f"timeout           {s.local_llm_timeout}s")
    g = _generation_settings(s)
    click.echo(
        f"generation        temperature={g.temperature} top_p={g.top_p} seed={g.seed} "
        f"max_tokens={g.max_tokens} context_window={g.context_window}"
    )
    click.echo(
        f"versions          prompt {PROMPT_VERSION}  evidence {EVIDENCE_SCHEMA_VERSION}  "
        f"explanation {EXPLANATION_SCHEMA_VERSION}"
    )
    if runtime is None:
        click.echo("health            not configured (the reference template is always available)")
        return
    try:
        client = _llm_client(s, runtime, model)
    except click.ClickException as exc:
        click.echo(f"health            MISCONFIGURED: {exc.message}")
        return
    health = client.health()
    state = "available" if health.available else "UNAVAILABLE"
    click.echo(f"health            {state}: {health.detail}")
    if health.available:
        from fraud_ai.llm.runtime import LLMRuntimeError

        try:
            installed = client.list_models()
        except LLMRuntimeError as exc:
            click.echo(f"model installed   unknown ({exc.kind})")
            return
        click.echo(f"model installed   {'yes' if client.model in installed else 'NO'}")


@llm.command("models")
@_RUNTIME_OPTION
@pass_app
def llm_models(app: AppContext, runtime_spec: str | None) -> None:
    """List the models the local runtime has installed (nothing is downloaded)."""
    from fraud_ai.llm.runtime import LLMRuntimeError

    runtime, model = _runtime_spec(runtime_spec) if runtime_spec else (None, None)
    client = _llm_client(app.settings, runtime, model)
    try:
        names = client.list_models()
    except LLMRuntimeError as exc:
        raise click.ClickException(f"{exc.kind}: {exc}") from None
    if not names:
        click.echo("no models installed")
    for name in names:
        click.echo(name)


def _score_for_benchmark(session: Any, model_refs: list[str], latest: int, labelled: int) -> int:
    """Store predictions (normal scoring, outside the LLM pipeline) for the latest
    transactions and for the latest fraud-labelled transactions, so the benchmark has
    cases of every type. Labels only choose which events to explain."""
    from sqlalchemy import or_

    from fraud_ai.models.registry import resolve_model
    from fraud_ai.models.scoring import load_registered_model, score_event

    models = [resolve_model(session, ref) for ref in model_refs]
    loaded = [load_registered_model(m) for m in models]
    ids = list(
        session.scalars(
            select(Transaction.event_id).order_by(Transaction.occurred_at.desc()).limit(latest)
        )
    )
    if labelled:
        ids += session.scalars(
            select(Transaction.event_id)
            .join(
                FraudLabel,
                or_(
                    FraudLabel.transaction_id == Transaction.transaction_id,
                    FraudLabel.event_id == Transaction.event_id,
                ),
            )
            .where(FraudLabel.label == LabelValue.FRAUD)
            .order_by(Transaction.occurred_at.desc())
            .distinct()
            .limit(labelled)
        ).all()
    unique = list(dict.fromkeys(ids))
    for event_id in unique:
        for model, fitted in zip(models, loaded, strict=True):
            score_event(session, event_id, model, loaded=fitted)
    return len(unique)


@llm.command("benchmark")
@click.option(
    "--model",
    "model_refs",
    multiple=True,
    required=True,
    help="Fraud models whose stored predictions form the evidence (repeatable).",
)
@click.option(
    "--runtime",
    "runtime_specs",
    multiple=True,
    help="RUNTIME[:MODEL] to compare (repeatable). Default: reference + LOCAL_LLM_RUNTIME.",
)
@click.option("--per-case", type=click.IntRange(1, 20), default=1, show_default=True)
@click.option("--max-candidates", type=click.IntRange(1), default=2000, show_default=True)
@click.option(
    "--score-latest",
    type=click.IntRange(0),
    default=0,
    show_default=True,
    help="First store predictions for the latest N transactions (normal scoring).",
)
@click.option(
    "--score-labelled",
    type=click.IntRange(0),
    default=0,
    show_default=True,
    help="Also store predictions for the latest N fraud-labelled transactions.",
)
@click.option("--output", type=click.Path(path_type=Path), default=None)
@pass_app
def llm_benchmark(
    app: AppContext,
    model_refs: tuple[str, ...],
    runtime_specs: tuple[str, ...],
    per_case: int,
    max_candidates: int,
    score_latest: int,
    score_labelled: int,
    output: Path | None,
) -> None:
    """Compare local models on explanation faithfulness, format, privacy and latency.

    This measures the explanation layer only; it is not a fraud-detection metric."""
    app.require_migrated()
    from fraud_ai.llm.builder import event_ref
    from fraud_ai.llm.evaluation import CASE_TYPES, benchmark, select_cases
    from fraud_ai.llm.prompt import PROMPT_VERSION

    s = app.settings
    specs = list(runtime_specs) or ["reference"] + (
        [s.local_llm_runtime] if s.local_llm_runtime not in (None, "reference") else []
    )
    clients = [_llm_client(s, *_runtime_spec(spec)) for spec in specs]
    with session_scope(make_session_factory(app.engine)) as session:
        try:
            if score_latest or score_labelled:
                scored = _score_for_benchmark(
                    session, list(model_refs), score_latest, score_labelled
                )
                click.echo(f"stored predictions for {scored} transactions")
                session.commit()
            selection = select_cases(
                session, list(model_refs), per_case=per_case, max_candidates=max_candidates
            )
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        if not selection.cases:
            raise click.ClickException(
                "no evaluation cases: no event has stored predictions from every model "
                "(score events first, e.g. --score-latest 500 --score-labelled 100)"
            )
        click.echo(
            f"{len(selection.cases)} cases from {selection.candidates_examined} candidate events"
        )
        if selection.missing:
            click.echo(f"no matching event for: {', '.join(selection.missing)}")
        reports = benchmark(selection.cases, clients, _generation_settings(s))
    columns = (
        ("valid", "valid_rate"),
        ("schema", "schema_compliance"),
        ("bad-cite", "invalid_citation_rate"),
        ("unsupported", "unsupported_claim_rate"),
        ("privacy", "privacy_violation_rate"),
        ("action", "forbidden_action_rate"),
        ("coverage", "evidence_coverage_mean"),
        ("latency-s", "latency_mean_seconds"),
        ("chars", "response_chars_mean"),
    )
    click.echo(f"{'runtime/model':<44}" + "".join(f"{h:>12}" for h, _ in columns))
    payload = []
    for r in reports:
        row = r.to_dict()
        for outcome in row["cases"]:  # pseudonymous refs only, never raw event ids
            outcome["event_ref"] = event_ref(uuid.UUID(outcome.pop("event_id")))
        payload.append(row)
        name = f"{r.runtime}/{r.model}"[:43]
        if not r.available:
            click.echo(f"{name:<44}  UNAVAILABLE: {r.detail}")
            continue
        metrics = row["metrics"]
        cells = "".join(
            f"{'-' if metrics[k] is None else format(metrics[k], '.3f'):>12}" for _, k in columns
        )
        click.echo(f"{name:<44}{cells}")
    target = output or (
        Path(s.evaluation_directory)
        / "llm"
        / f"benchmark_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "kind": "llm_explanation_benchmark",
                "note": "explanation quality and safety on synthetic cases; not a fraud metric",
                "prompt_version": PROMPT_VERSION,
                "fraud_models": list(model_refs),
                "case_types": list(CASE_TYPES),
                "missing_case_types": selection.missing,
                "generation": _generation_settings(s).request("", "").parameters(),
                "reports": payload,
            },
            indent=2,
            sort_keys=True,
        )
    )
    click.echo(f"written {target}")


class _InvestigateGroup(click.Group):
    """``investigate <event-id>`` runs an investigation; ``show``/``validate`` inspect one."""

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = ["event", *args]
        return super().resolve_command(ctx, args)


@cli.group(cls=_InvestigateGroup)
def investigate() -> None:
    """Explain one event for an analyst with the local LLM (decision support only).

    \b
    fraud-ai investigate <event-id> [--model REF ...] [--runtime R[:M]] [--score-missing]
    fraud-ai investigate show <investigation-id>
    fraud-ai investigate validate <investigation-id>

    The event is never rescored and nothing is decided: no score, label, threshold, rule
    or decision changes. Only validated, cited explanations are stored, as a new version.
    """


@investigate.command("event", hidden=True)
@click.argument("event_id")
@click.option("--model", "model_refs", multiple=True, help="Fraud model refs (default: all).")
@_RUNTIME_OPTION
@click.option(
    "--score-missing",
    is_flag=True,
    help="Store missing predictions for --model first (normal scoring, before the pipeline).",
)
@click.option("--json", "as_json", is_flag=True)
@pass_app
def investigate_event(
    app: AppContext,
    event_id: str,
    model_refs: tuple[str, ...],
    runtime_spec: str | None,
    score_missing: bool,
    as_json: bool,
) -> None:
    app.require_migrated()
    from fraud_ai.llm.service import investigate as run_investigation

    runtime, model = _runtime_spec(runtime_spec) if runtime_spec else (None, None)
    client = _llm_client(app.settings, runtime, model)
    eid = _parse_uuid(event_id)
    if score_missing and not model_refs:
        raise click.BadParameter("--score-missing needs --model", param_hint="--score-missing")
    with session_scope(make_session_factory(app.engine)) as session:
        try:
            if score_missing:
                from fraud_ai.models.registry import resolve_model
                from fraud_ai.models.scoring import score_event

                for ref in model_refs:
                    score_event(session, eid, resolve_model(session, ref))
            result = run_investigation(
                session,
                eid,
                client,
                settings=_generation_settings(app.settings),
                model_refs=list(model_refs) or None,
            )
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        if as_json:
            click.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        if not result.ok:
            if not as_json:
                click.echo(f"investigation FAILED: {result.failure}", err=True)
                for error in result.errors[:20]:
                    click.echo(f"  {error}", err=True)
                click.echo("nothing was stored", err=True)
            session.rollback()
            raise SystemExit(2)
        row = result.investigation
        assert row is not None
        if not as_json:
            click.echo(
                f"investigation {row.investigation_id} (version {row.explanation_version}, "
                f"{row.llm_runtime}/{row.llm_model}, {row.prompt_version})"
            )
            click.echo(row.explanation_text)


def _investigation(session: Any, investigation_id: str) -> Any:
    from fraud_ai.llm.service import load_investigation

    try:
        return load_investigation(session, _parse_uuid(investigation_id))
    except FraudAIError as exc:
        raise click.ClickException(str(exc)) from None


@investigate.command("show")
@click.argument("investigation_id")
@click.option("--json", "as_json", is_flag=True)
@click.option("--evidence", is_flag=True, help="Also print the evidence packet.")
@pass_app
def investigate_show(app: AppContext, investigation_id: str, as_json: bool, evidence: bool) -> None:
    """Show a stored investigation and its provenance."""
    app.require_migrated()
    with session_scope(make_session_factory(app.engine)) as session:
        row = _investigation(session, investigation_id)
        meta = {
            "investigation_id": str(row.investigation_id),
            "event_id": str(row.event_id),
            "explanation_version": row.explanation_version,
            "created_at": row.created_at.isoformat(),
            "llm_runtime": row.llm_runtime,
            "llm_model": row.llm_model,
            "llm_model_version": row.llm_model_version,
            "prompt_version": row.prompt_version,
            "evidence_schema_version": row.evidence_schema_version,
            "explanation_schema_version": row.explanation_schema_version,
            "evidence_packet_sha256": row.evidence_packet_sha256,
            "generation_parameters": row.generation_parameters,
            "validation": row.validation,
            "latency_seconds": row.latency_seconds,
        }
        if as_json:
            payload = meta | {"explanation": row.explanation_json}
            if evidence:
                payload["evidence_packet"] = row.evidence_packet
            click.echo(json.dumps(payload, indent=2, sort_keys=True))
            return
        for key, value in meta.items():
            if isinstance(value, dict):
                value = json.dumps(value, sort_keys=True)
            click.echo(f"{key:<27} {value}")
        click.echo("")
        click.echo(row.explanation_text)
        if evidence:
            click.echo("")
            for item in row.evidence_packet["evidence"]:
                click.echo(f"  {item['id']:<5} {item['section']}.{item['name']} = {item['value']}")
            for lim in row.evidence_packet["limitations"]:
                click.echo(f"  {lim['id']:<5} {lim['text']}")


@investigate.command("validate")
@click.argument("investigation_id")
@click.option(
    "--no-compare-current",
    is_flag=True,
    help="Skip rebuilding today's evidence to detect changes since generation.",
)
@pass_app
def investigate_validate(app: AppContext, investigation_id: str, no_compare_current: bool) -> None:
    """Re-run every check on a stored investigation (read-only)."""
    app.require_migrated()
    from fraud_ai.llm.service import revalidate

    with session_scope(make_session_factory(app.engine)) as session:
        row = _investigation(session, investigation_id)
        report = revalidate(session, row.investigation_id, compare_current=not no_compare_current)
    click.echo(f"valid                 {'yes' if report.valid else 'NO'}")
    click.echo(f"packet hash matches   {report.packet_hash_matches}")
    click.echo(f"packet privacy clean  {report.packet_privacy_clean}")
    click.echo(f"text matches JSON     {report.text_matches_json}")
    click.echo(f"output validation     {report.output_validation['failure'] or 'passed'}")
    if report.evidence_current is not None:
        click.echo(f"evidence current      {report.evidence_current}")
    for note in report.notes:
        click.echo(f"  - {note}")
    if not report.valid:
        raise SystemExit(2)


# --------------------------------------------------------------------------- realtime (Stage 8)
def _service(app: AppContext, *, replay: bool) -> Any:
    from fraud_ai.realtime.service import FraudScoringService
    from fraud_ai.security.keys import build_pseudonymiser

    return FraudScoringService(
        make_session_factory(app.engine),
        build_pseudonymiser(app.settings),
        store_raw_ip=app.settings.store_raw_ip,
        replay=replay,
    )


def _read_events(path: Path) -> list[Any]:
    text = sys.stdin.read() if str(path) == "-" else path.read_text()
    text = text.strip()
    if not text:
        raise click.ClickException("no events in the input")
    if text.startswith("["):
        data = json.loads(text)
        return list(data)
    if text.startswith("{") and "\n" not in text:
        return [json.loads(text)]
    events = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                raise click.ClickException(f"line {n} is not valid JSON") from None
    return events


def _outcome_line(outcome: Any) -> str:
    d = outcome.to_dict()
    decision = d["decision"] or "-"
    codes = ",".join(d["reason_codes"]) or "-"
    return (
        f"{d['event_ref'] or '-':<20} {d['status']:<13} {decision:<23} "
        f"{d['risk_level'] or '-':<9} {d['latency_ms'].get('total', 0):>8.1f} ms  {codes}"
    )


@cli.group()
def realtime() -> None:
    """Real-time scoring: contract -> ingest -> features -> models -> rules -> policy."""


@realtime.command("score")
@click.argument("event_file", type=click.Path(path_type=Path, allow_dash=True))
@click.option("--json", "as_json", is_flag=True)
@pass_app
def realtime_score(app: AppContext, event_file: Path, as_json: bool) -> None:
    """Score live events (JSON object, array or JSON lines; '-' reads stdin).

    Arrival time is the service clock; decisions are policy outputs, nothing is executed.
    """
    app.require_migrated()
    service = _service(app, replay=False)
    outcomes = [service.score_event(e) for e in _read_events(event_file)]
    if as_json:
        click.echo(json.dumps([o.to_dict() for o in outcomes], indent=2, sort_keys=True))
        return
    for outcome in outcomes:
        click.echo(_outcome_line(outcome))


@realtime.command("replay")
@click.argument("event_file", type=click.Path(path_type=Path, allow_dash=True))
@click.option("--verbose", is_flag=True, help="One line per event.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default=None)
@pass_app
def realtime_replay(app: AppContext, event_file: Path, verbose: bool, output: Path | None) -> None:
    """Replay recorded events in ARRIVAL order (each may carry `arrival_time`)."""
    app.require_migrated()
    service = _service(app, replay=True)
    events = _read_events(event_file)
    keyed = sorted(
        enumerate(events),
        key=lambda x: (
            (str(x[1].get("arrival_time") or x[1].get("timestamp") or ""), x[0])
            if isinstance(x[1], dict)
            else ("", x[0])
        ),
    )
    outcomes = []
    for _, event in keyed:
        outcome = service.score_event(event)
        outcomes.append(outcome)
        if verbose:
            click.echo(_outcome_line(outcome))
    from collections import Counter

    statuses = Counter(o.status for o in outcomes)
    decisions = Counter(o.decision.value for o in outcomes if o.decision and o.status != "rejected")
    metrics = service.metrics.snapshot()
    click.echo(f"replayed {len(outcomes)} events: {dict(sorted(statuses.items()))}")
    click.echo(f"decisions: {dict(sorted(decisions.items()))}")
    if metrics["fallbacks"]:
        click.echo(f"failures/fallbacks: {metrics['fallbacks']}")
    total = metrics["latency_ms"].get("total", {})
    click.echo(
        f"latency total p50 {total.get('p50')} ms  p95 {total.get('p95')} ms  "
        f"p99 {total.get('p99')} ms  (all events, incl. non-decision)"
    )
    click.echo(f"model cache: {service.cache.stats.to_dict()}")
    if output is not None:
        output.write_text(
            json.dumps(
                {"outcomes": [o.to_dict() for o in outcomes], "metrics": metrics},
                indent=2,
                sort_keys=True,
            )
        )
        click.echo(f"written {output}")


@realtime.command("reassess")
@click.argument("event_id")
@pass_app
def realtime_reassess(app: AppContext, event_id: str) -> None:
    """Issue a NEW assessment version with today's evidence; the original is preserved."""
    app.require_migrated()
    service = _service(app, replay=False)
    try:
        outcome = service.reassess(_parse_uuid(event_id))
    except FraudAIError as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(
        f"assessment version {outcome.assessment_version}: {outcome.decision} "
        f"({outcome.risk_level}) {','.join(outcome.reason_codes)}"
    )


# --------------------------------------------------------------------------- policy
@cli.group()
def policy() -> None:
    """Versioned, immutable risk policies (bands, rules, fallbacks, model set)."""


def _policy_costs(opts: dict[str, Any]) -> Any:
    from fraud_ai.risk.offline import PolicyCostConfig

    return PolicyCostConfig(
        fraud_loss=opts["fraud_loss"],
        manual_review_cost=opts["review_cost"],
        step_up_cost=opts["step_up_cost"],
        false_positive_friction=opts["friction"],
        step_up_fraud_stop_rate=opts["step_up_stop_rate"],
    )


def _cost_options(func: Any) -> Any:
    for option in reversed(
        [
            click.option(
                "--fraud-loss", type=click.FloatRange(0), default=500.0, show_default=True
            ),
            click.option("--review-cost", type=click.FloatRange(0), default=5.0, show_default=True),
            click.option(
                "--step-up-cost", type=click.FloatRange(0), default=1.0, show_default=True
            ),
            click.option("--friction", type=click.FloatRange(0), default=10.0, show_default=True),
            click.option(
                "--step-up-stop-rate",
                type=click.FloatRange(0, 1),
                default=0.5,
                show_default=True,
                help="ASSUMED share of fraud a step-up would stop (not measurable here).",
            ),
        ]
    ):
        func = option(func)
    return func


@policy.command("propose")
@click.argument("version")
@click.option("--primary", required=True, help="Primary classifier, e.g. gradient-boosting-1.0.0")
@click.option("--secondary", default=None)
@click.option("--sequence", "sequence_ref", default=None)
@click.option("--anomaly", default=None)
@click.option("--monitor-recall", type=click.FloatRange(0.5, 1.0), default=0.95, show_default=True)
@click.option("--block-precision", type=click.FloatRange(0.5, 1.0), default=0.95, show_default=True)
@click.option("--description", default="")
@_cost_options
@pass_app
def policy_propose(
    app: AppContext,
    /,
    version: str,
    primary: str,
    secondary: str | None,
    sequence_ref: str | None,
    anomaly: str | None,
    monitor_recall: float,
    block_precision: float,
    description: str,
    **opts: Any,
) -> None:
    """Derive EXPERIMENTAL bands from Stage 4 cost analysis (validation split) and store a
    new, INACTIVE policy version. Activation is a separate, explicit step."""
    app.require_migrated()
    from fraud_ai.evaluation.costs import CostConfig
    from fraud_ai.risk.offline import propose_policy
    from fraud_ai.risk.registry import create_policy

    costs = CostConfig(
        fraud_loss=opts["fraud_loss"],
        manual_review_cost=opts["review_cost"],
        step_up_cost=opts["step_up_cost"],
        false_positive_friction=opts["friction"],
    )
    with session_scope(make_session_factory(app.engine)) as session:
        try:
            proposal = propose_policy(
                session,
                version,
                primary=primary,
                secondary=secondary,
                sequence=sequence_ref,
                anomaly=anomaly,
                costs=costs,
                monitor_recall=monitor_recall,
                block_precision=block_precision,
                description=description,
            )
            create_policy(session, proposal.definition, derivation=proposal.derivation)
        except (FraudAIError, ValueError) as exc:
            raise click.ClickException(str(exc)) from None
        click.echo(f"stored {version} (INACTIVE; synthetic-derived experimental defaults)")
        for band in proposal.definition.bands:
            click.echo(f"  >= {band.lower:<5} {band.risk_level:<9} {band.decision.value}")
        click.echo(f"  sha256 {proposal.definition.sha256()}")


@policy.command("list")
@pass_app
def policy_list(app: AppContext) -> None:
    """All stored policy versions and which one is active."""
    app.require_migrated()
    from fraud_ai.risk.registry import deployment_history, list_policies

    with session_scope(make_session_factory(app.engine)) as session:
        history = deployment_history(session)
        active = history[0].policy_version if history else None
        rows = list_policies(session)
        if not rows:
            click.echo("no policies; create one with `fraud-ai policy propose`")
        for row in rows:
            flag = "ACTIVE" if row.policy_version == active else ""
            origin = "synthetic-derived" if row.synthetic_derived else ""
            click.echo(
                f"{row.policy_version:<24} {row.created_at:%Y-%m-%d %H:%M}  {flag:<6} {origin}"
            )


@policy.command("show")
@click.argument("version")
@click.option("--json", "as_json", is_flag=True)
@pass_app
def policy_show(app: AppContext, version: str, as_json: bool) -> None:
    """A policy's full definition (verified against its hash)."""
    app.require_migrated()
    from fraud_ai.risk.registry import get_policy_record, verified_definition

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            row = get_policy_record(session, version)
            definition = verified_definition(row)
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        if as_json:
            payload = {
                "definition": definition.model_dump(mode="json"),
                "sha256": row.definition_sha256,
                "derivation": {k: v for k, v in row.derivation.items() if k != "baselines"},
            }
            click.echo(json.dumps(payload, indent=2, sort_keys=True))
            return
        click.echo(f"{definition.policy_version}  sha256 {row.definition_sha256}")
        click.echo(f"  synthetic-derived: {definition.synthetic_derived}")
        for role, slot in definition.slots().items():
            cal = slot.calibration.method if slot.calibration else "none"
            click.echo(f"  {role:<10} {slot.ref:<28} threshold {slot.threshold}  calibration {cal}")
        click.echo(f"  rules      {definition.rules_version}")
        click.echo(f"  decides on {', '.join(definition.decision_event_kinds)} events")
        click.echo("  bands (calibrated primary score):")
        for band in definition.bands:
            click.echo(f"    >= {band.lower:<5} {band.risk_level:<9} {band.decision.value}")
        click.echo("  rule severity -> minimum decision:")
        for severity, decision in definition.severity_minimum.items():
            click.echo(f"    {severity.value:<8} {decision.value}")
        click.echo("  fallbacks:")
        for failure, decision in sorted(definition.fallbacks.items()):
            click.echo(f"    {failure.value:<30} {decision.value}")


def _write_policy_report(app: AppContext, name: str, report: dict[str, Any]) -> Path:
    directory = Path(app.settings.evaluation_directory) / "policies"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    return path


@policy.command("simulate")
@click.argument("version")
@click.option(
    "--split", type=click.Choice(["validation", "test"]), default="test", show_default=True
)
@_cost_options
@pass_app
def policy_simulate(app: AppContext, /, version: str, split: str, **opts: Any) -> None:
    """Run a policy over historical labelled events; stored decisions are NOT changed."""
    app.require_migrated()
    from fraud_ai.risk.offline import simulate
    from fraud_ai.risk.registry import load_policy

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            report = simulate(
                session, load_policy(session, version), split=split, costs=_policy_costs(opts)
            )
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        session.rollback()  # simulation is read-only
    click.echo(f"{version} on {report['events']} {split} events ({report['fraud_events']} fraud)")
    for decision, count in report["decision_distribution"].items():
        click.echo(f"  {decision:<24} {count:>6}")
    click.echo(
        f"fraud caught (review/block) {report['fraud_caught']}  challenged (step-up) "
        f"{report['fraud_challenged_step_up']}  missed {report['fraud_missed']}"
    )
    click.echo(
        f"false positives {report['false_positive_volume']}  estimated cost "
        f"{report['estimated_cost']:.1f} (assumed costs; SYNTHETIC)"
    )
    click.echo(f"written {_write_policy_report(app, f'{version}_simulation_{split}', report)}")


@policy.command("compare")
@click.argument("version_a")
@click.argument("version_b")
@click.option(
    "--split", type=click.Choice(["validation", "test"]), default="test", show_default=True
)
@click.option("--iterations", type=click.IntRange(10), default=1000, show_default=True)
@_cost_options
@pass_app
def policy_compare(
    app: AppContext, /, version_a: str, version_b: str, split: str, iterations: int, **opts: Any
) -> None:
    """Compare two policies on exactly the same historical events (never activates)."""
    app.require_migrated()
    from fraud_ai.risk.offline import compare_policies
    from fraud_ai.risk.registry import load_policy

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            report = compare_policies(
                session,
                load_policy(session, version_a),
                load_policy(session, version_b),
                split=split,
                costs=_policy_costs(opts),
                iterations=iterations,
            )
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        session.rollback()
    click.echo(
        f"{report['same_events']} identical {split} events; decisions differ on "
        f"{report['decisions_differ']}"
    )
    for side in ("a", "b"):
        r = report[side]
        click.echo(
            f"  {report['policy_' + side]:<24} caught {r['fraud_caught']:>4}  step-up "
            f"{r['step_up_volume']:>5}  review {r['manual_review_volume']:>5}  block "
            f"{r['temporary_block_volume']:>4}  FP {r['false_positive_volume']:>5}  cost "
            f"{r['estimated_cost']:.1f}"
        )
    diff = report["cost_difference_a_minus_b"]
    click.echo(
        f"cost A-B {diff['estimate']:.1f} [{diff['lower_95']:.1f}, {diff['upper_95']:.1f}] "
        "(bootstrap 95%; assumed costs; SYNTHETIC)"
    )
    click.echo(report["note"])
    path = _write_policy_report(app, f"compare_{version_a}_vs_{version_b}_{split}", report)
    click.echo(f"written {path}")


# --------------------------------------------------------------------------- deployment
@cli.group()
def deployment() -> None:
    """The active policy and shadow configuration (append-only history)."""


@deployment.command("show")
@click.option("--history", "show_history", is_flag=True)
@pass_app
def deployment_show(app: AppContext, show_history: bool) -> None:
    """The active deployment (and optionally every earlier one)."""
    app.require_migrated()
    from fraud_ai.risk.registry import active_deployment, deployment_history

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            active = active_deployment(session)
        except FraudAIError as exc:
            raise click.ClickException(f"active deployment is not trustworthy: {exc}") from None
        if active is None:
            click.echo("no active deployment: every decision falls back to MANUAL_REVIEW")
        else:
            d = active.deployment
            click.echo(f"deployment #{d.sequence} activated {d.activated_at:%Y-%m-%d %H:%M:%S}")
            click.echo(f"  policy          {d.policy_version}")
            for role, slot in active.policy.slots().items():
                click.echo(f"  {role:<15} {slot.ref}")
            click.echo(f"  shadow models   {', '.join(d.shadow_models) or '-'}")
            click.echo(f"  shadow policies {', '.join(d.shadow_policies) or '-'}")
            if d.note:
                click.echo(f"  note            {d.note}")
        if show_history:
            for row in deployment_history(session):
                click.echo(
                    f"  #{row.sequence:<3} {row.activated_at:%Y-%m-%d %H:%M} {row.policy_version}"
                )


@deployment.command("activate")
@click.argument("policy_version")
@click.option("--shadow-model", "shadow_models", multiple=True)
@click.option("--shadow-policy", "shadow_policies", multiple=True)
@click.option("--note", default=None)
@click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
@pass_app
def deployment_activate(
    app: AppContext,
    policy_version: str,
    shadow_models: tuple[str, ...],
    shadow_policies: tuple[str, ...],
    note: str | None,
    yes: bool,
) -> None:
    """Explicitly activate a policy (validated first). Never happens implicitly."""
    app.require_migrated()
    from fraud_ai.risk.registry import activate

    if not yes:
        click.confirm(
            f"Activate {policy_version} for all newly scored events? (synthetic-derived "
            "policies are experimental)",
            abort=True,
        )
    with session_scope(make_session_factory(app.engine)) as session:
        try:
            row = activate(
                session,
                policy_version,
                shadow_models=list(shadow_models),
                shadow_policies=list(shadow_policies),
                note=note,
            )
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        click.echo(f"deployment #{row.sequence}: {policy_version} is active")


# --------------------------------------------------------------------------- review
@cli.group()
def review() -> None:
    """Manual-review queue (resolutions never rewrite the original assessment)."""


@review.command("list")
@click.option(
    "--status",
    type=click.Choice(["open", "needs_more_information", "resolved", "all"]),
    default="open",
    show_default=True,
)
@click.option("--limit", type=click.IntRange(1, 1000), default=50, show_default=True)
@pass_app
def review_list(app: AppContext, status: str, limit: int) -> None:
    """Queue entries, most urgent first."""
    app.require_migrated()
    from fraud_ai.core.enums import ReviewStatus
    from fraud_ai.realtime.review import list_reviews

    with session_scope(make_session_factory(app.engine)) as session:
        items = list_reviews(
            session, status=None if status == "all" else ReviewStatus(status), limit=limit
        )
        if not items:
            click.echo("review queue is empty")
        for item in items:
            click.echo(
                f"{item.review_id}  p{item.priority}  {item.status.value:<22} "
                f"{item.created_at:%Y-%m-%d %H:%M}  {','.join(item.reason_codes)}"
            )


@review.command("show")
@click.argument("review_id")
@pass_app
def review_show(app: AppContext, review_id: str) -> None:
    """A queue entry with its (unchanged) assessment and outcomes."""
    app.require_migrated()
    from fraud_ai.realtime.review import get_review

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            detail = get_review(session, _parse_uuid(review_id))
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        item, a = detail.item, detail.assessment
        click.echo(f"review {item.review_id}  priority {item.priority}  status {item.status.value}")
        click.echo(f"  event        {a.event_id}")
        click.echo(
            f"  assessment   {a.assessment_id} v{a.assessment_version}  {a.decision.value}  "
            f"risk {a.risk_level}  policy {a.policy_version}"
        )
        click.echo(f"  reasons      {', '.join(a.reason_codes)}")
        if a.calibrated_score is not None:
            click.echo(f"  score        {a.calibrated_score:.4f} (calibrated {a.primary_model})")
        matched = [r for r in a.triggered_rules.get("results", []) if r["matched"]]
        for r in matched:
            click.echo(f"  rule         {r['rule_id']} {r['reason_code']} ({r['severity']})")
        for f in a.failures:
            click.echo(f"  failure      {f['category']}")
        click.echo(f"  action       {json.dumps(a.action, sort_keys=True)}")
        for outcome in detail.outcomes:
            click.echo(
                f"  outcome      {outcome.created_at:%Y-%m-%d %H:%M}  {outcome.resolution.value}"
                + (f"  note: {outcome.note}" if outcome.note else "")
            )
        click.echo(f"  (explain with: fraud-ai investigate {a.event_id})")


@review.command("resolve")
@click.argument("review_id")
@click.option(
    "--outcome",
    type=click.Choice(["legitimate", "fraud", "needs_more_information"]),
    required=True,
)
@click.option("--note", default=None, help="Short note without personal data.")
@pass_app
def review_resolve(app: AppContext, review_id: str, outcome: str, note: str | None) -> None:
    """Record a review outcome (the assessment itself is never modified)."""
    app.require_migrated()
    from fraud_ai.core.enums import ReviewResolution
    from fraud_ai.realtime.review import resolve

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            row = resolve(session, _parse_uuid(review_id), ReviewResolution(outcome), note=note)
        except FraudAIError as exc:
            raise click.ClickException(str(exc)) from None
        click.echo(f"recorded outcome {row.resolution.value} for review {review_id}")


# --------------------------------------------------------------------------- monitoring
@cli.group()
def monitoring() -> None:
    """Operational metrics, drift warnings and shadow evaluation (warnings only)."""


def _since(hours: float | None) -> datetime | None:
    from datetime import timedelta

    return datetime.now(UTC) - timedelta(hours=hours) if hours else None


@monitoring.command("summary")
@click.option("--since-hours", type=click.FloatRange(min=0, min_open=True), default=None)
@click.option("--json", "as_json", is_flag=True)
@click.option("--drift/--no-drift", "with_drift", default=True, show_default=True)
@pass_app
def monitoring_summary(
    app: AppContext, since_hours: float | None, as_json: bool, with_drift: bool
) -> None:
    """Decisions, fallbacks, latency percentiles, review queue, shadow and drift."""
    app.require_migrated()
    from fraud_ai.realtime import monitoring as mon

    since = _since(since_hours)
    with session_scope(make_session_factory(app.engine)) as session:
        report = {"summary": mon.summary(session, since=since)}
        if with_drift:
            try:
                report["drift"] = mon.drift(session, since=since)
            except FraudAIError as exc:
                report["drift"] = {"status": "unavailable", "error": str(exc), "warnings": []}
        report["shadow"] = mon.shadow_report(session, since=since)
    if as_json:
        click.echo(json.dumps(report, indent=2, sort_keys=True, default=str))
        return
    s = report["summary"]
    click.echo(f"events ingested {s['events_ingested']}  assessments {s['assessments']}")
    click.echo(
        f"fallbacks {s['assessments_with_fallback']}  late events {s['late_events']}  "
        f"review queue {s['review_queue']}"
    )
    for decision, count in s["decisions"].items():
        click.echo(f"  {decision:<24} {count:>6}")
    for category, count in s["fallbacks_by_category"].items():
        click.echo(f"  failure {category:<30} {count:>5}")
    click.echo("latency (ms):")
    for stage, p in s["latency_ms"].items():
        click.echo(f"  {stage:<22} p50 {p['p50']:>8}  p95 {p['p95']:>8}  p99 {p['p99']:>8}")
    rate = s["shadow_disagreement_rate"]
    click.echo(
        f"shadow comparisons {s['shadow_comparisons']}  disagreement rate "
        f"{'-' if rate is None else f'{rate:.3f}'}"
    )
    if with_drift:
        warnings = report["drift"].get("warnings", [])
        click.echo(f"drift warnings ({len(warnings)}):" if warnings else "drift: no warnings")
        for w in warnings:
            click.echo(f"  WARNING {w}")


@monitoring.command("shadow")
@click.option("--since-hours", type=click.FloatRange(min=0, min_open=True), default=None)
@pass_app
def monitoring_shadow(app: AppContext, since_hours: float | None) -> None:
    """Shadow models/policies vs the active system (labels known now)."""
    app.require_migrated()
    from fraud_ai.realtime.monitoring import shadow_report

    with session_scope(make_session_factory(app.engine)) as session:
        report = shadow_report(session, since=_since(since_hours))
    click.echo(f"{report['assessments_with_shadow']} assessments with shadow results")
    for kind in ("models", "policies"):
        for name, r in report[kind].items():
            rate = r["agreement_rate"]
            only = r.get("fraud_only_shadow", r.get("fraud_caught_only_shadow"))
            click.echo(
                f"  {name:<28} agreement {'-' if rate is None else f'{rate:.3f}'}  "
                f"disagreements {r['disagreements']}  fraud only shadow {only}  "
                f"FP only shadow {r['false_positives_only_shadow']}  "
                f"latency p50 {r['latency_ms']['p50']} ms"
            )
    click.echo(report["note"])


def main() -> None:  # pragma: no cover
    cli(prog_name="fraud-ai")


if __name__ == "__main__":  # pragma: no cover
    main()
