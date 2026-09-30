"""``fraud-ai demo``: the deterministic portfolio demo (Stage 12). SYNTHETIC data only.

    DEMO_MODE=true fraud-ai demo reset     # (re)create the demo world (guarded)
    DEMO_MODE=true fraud-ai demo start     # reset if needed, then serve on 127.0.0.1:8080
    fraud-ai demo run                      # the walkthrough, against the running service

The demo runs the DEVELOPMENT profile on SQLite with in-memory shared state. It keeps
the security logic of staging: signed v2 requests only, signed models required, operator
authentication for reviewers and admins, two-person activation, audit anchors. What
differs from staging is printed by `demo start` and listed in DEMO.md.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from fraud_ai.cli.main import AppContext, cli, pass_app

DEFAULT_ROOT = Path("data/demo")
DIFFERENCES = (
    "SQLite instead of PostgreSQL (one process), in-memory shared state instead of Redis",
    "local key files instead of Vault (KMS); a file anchor store instead of Object Lock",
    "the DEVELOPMENT FAKE payment provider (not 3-D Secure)",
    "plain HTTP on 127.0.0.1 (no TLS proxy)",
    "the reference LLM template unless LOCAL_LLM_RUNTIME points at a real local model",
)


@cli.group()
def demo() -> None:
    """Deterministic portfolio demo world and walkthrough (SYNTHETIC data only)."""


def _root(root: Path | None) -> Path:
    return (root or Path(os.environ.get("DEMO_ROOT", DEFAULT_ROOT))).resolve()


def _guard(app: AppContext, root: Path) -> None:
    from fraud_ai.demo.guard import DemoGuardError, check_target

    settings = app.settings
    expected = f"sqlite:///{root / 'fraud_ai_demo.db'}"
    if settings.database_url and settings.resolved_database_url != expected:
        raise click.ClickException(
            f"DATABASE_URL points elsewhere ({settings.safe_database_url}); the demo only "
            f"uses {expected}. Unset DATABASE_URL (or point it there)."
        )
    from fraud_ai.database.engine import create_db_engine

    target = settings.model_copy(update={"database_url": expected})
    engine = create_db_engine(expected)
    try:
        check_target(target, engine)
    except DemoGuardError as exc:
        raise click.ClickException(str(exc)) from None
    finally:
        engine.dispose()


@demo.command("reset")
@click.option("--root", type=click.Path(path_type=Path, file_okay=False), default=None)
@click.option("--users", type=click.IntRange(200, 2000), default=360, show_default=True)
@pass_app
def demo_reset(app: AppContext, root: Path | None, users: int) -> None:
    """(Re)create the demo world. Refused unless DEMO_MODE=true, the development profile,
    a *_demo.db database, and (if it exists) the demo marker as its first audit event."""
    from fraud_ai.demo.world import build_world

    directory = _root(root)
    _guard(app, directory)
    document = build_world(directory, users=users, echo=click.echo)
    for case in document["cases"]:
        note = " (relaxed match)" if case.get("relaxed_match") else ""
        click.echo(
            f"  {case['label']:<22} {case['expected_decision']:<24} ({case['scenario']}){note}"
        )
    click.echo(
        f"catalogue: {directory / 'catalogue.json'}; configuration: {directory / 'demo.env'}"
    )


@demo.command("start")
@click.option("--root", type=click.Path(path_type=Path, file_okay=False), default=None)
@click.option("--reset", "force_reset", is_flag=True, help="Rebuild the world first.")
@click.option("--port", type=click.IntRange(1, 65535), default=8080, show_default=True)
@pass_app
def demo_start(app: AppContext, root: Path | None, force_reset: bool, port: int) -> None:
    """Interview mode: build the demo world if needed, print what differs from staging and
    the demo credentials, then serve on 127.0.0.1 (Ctrl+C stops it)."""
    from fraud_ai.demo.world import build_world, load_env

    directory = _root(root)
    if force_reset or not (directory / "catalogue.json").exists():
        _guard(app, directory)
        build_world(directory, echo=click.echo)
    env = load_env(directory)
    click.echo("fraud-ai DEMO (synthetic data). Same security logic as staging; different:")
    for line in DIFFERENCES:
        click.echo(f"  - {line}")
    creds = json.loads((directory / "demo-credentials.json").read_text())
    click.echo(f"API key (demo only): {creds['credential'].split('.')[0]}… (full value in "
               f"{directory / 'demo-credentials.json'})")  # fmt: skip
    click.echo(f"in another terminal: fraud-ai demo run --base-url http://127.0.0.1:{port}")
    merged = {**os.environ, **env, "SERVICE_PORT": str(port), "SERVICE_HOST": "127.0.0.1"}
    os.execve(  # noqa: S606  # nosec B606 - our own CLI with the demo environment
        sys.executable, [sys.executable, "-m", "fraud_ai", "service", "run"], merged
    )


@demo.command("run")
@click.option("--root", type=click.Path(path_type=Path, file_okay=False), default=None)
@click.option("--base-url", default="http://127.0.0.1:8080", show_default=True)
def demo_run(root: Path | None, base_url: str) -> None:
    """The DEMO.md walkthrough against the running demo service."""
    from fraud_ai.demo.walkthrough import run

    directory = _root(root)
    if not (directory / "catalogue.json").exists():
        raise click.ClickException("no demo world: run `DEMO_MODE=true fraud-ai demo reset`")
    results = run(directory, base_url, echo=click.echo)
    (directory / "walkthrough.json").write_text(json.dumps(results, indent=2) + "\n")
