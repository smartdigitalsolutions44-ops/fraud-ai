"""``fraud-ai`` command-line entry point.

Only commands with real functionality exist. Future commands (score, train, evaluate,
investigate) will be added by the stages that implement them.
"""

from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Iterator
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
    type=click.FloatRange(0.1, 4.0),
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
@pass_app
def seed(
    app: AppContext,
    n_users: int,
    rng_seed: int,
    fraud_multiplier: float,
    days: int,
    reference_time: datetime | None,
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
            default=0.5,
            show_default=True,
            help="Evaluation threshold (not a decision).",
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


def _run_train(app: AppContext, kinds: list[str], **opts: Any) -> None:
    app.require_migrated()
    from datetime import timedelta

    from fraud_ai.features.definitions import EventKind
    from fraud_ai.models.report import SYNTHETIC_NOTE, comparison_table
    from fraud_ai.models.splits import SplitConfig
    from fraud_ai.models.training import TrainingConfig, run_training

    try:
        split = SplitConfig(
            opts["train_fraction"],
            opts["validation_fraction"],
            _utc(opts["train_end"]),
            _utc(opts["validation_end"]),
        )
        config = TrainingConfig(
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
        )
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
    """Train baseline models on a time-ordered split (no decisions are made)."""


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


def _with_context(app: AppContext, refs: list[str], body: Any) -> None:
    app.require_migrated()
    from fraud_ai.evaluation.context import build_context

    with session_scope(make_session_factory(app.engine)) as session:
        try:
            ctx = build_context(session, refs)
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
    llm_state = f"configured: {s.local_llm_endpoint}" if s.local_llm_endpoint else "not configured"
    click.echo(f"local LLM       {llm_state} (Stage 7)")


def main() -> None:  # pragma: no cover
    cli(prog_name="fraud-ai")


if __name__ == "__main__":  # pragma: no cover
    main()
