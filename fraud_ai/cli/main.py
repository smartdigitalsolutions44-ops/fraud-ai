"""``fraud-ai`` command-line entry point.

Only commands with real functionality exist. Future commands (score, train, evaluate,
investigate) will be added by the stages that implement them.
"""

from __future__ import annotations

import json
import sys
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
    app: AppContext, n_users: int, rng_seed: int, days: int, reference_time: datetime | None
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
    click.echo("feature engine  not implemented (Stage 2)")
    llm_state = f"configured: {s.local_llm_endpoint}" if s.local_llm_endpoint else "not configured"
    click.echo(f"local LLM       {llm_state} (Stage 7)")


def main() -> None:  # pragma: no cover
    cli(prog_name="fraud-ai")


if __name__ == "__main__":  # pragma: no cover
    main()
