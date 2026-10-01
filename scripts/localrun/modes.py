"""What each start mode runs, with which environment.

* **Demo**: the synthetic demo world (SQLite file ``*_demo.db``, in-memory shared state;
  Redis is NOT USED). Built only by the existing guarded ``fraud-ai demo reset``. The
  service runs with the demo world's own ``demo.env`` (request signatures v2, signed
  models, operator authentication on). The console runs its production build in DEMO MODE.
* **Dev**: PostgreSQL and Redis in Docker (``compose.local.yml``), the development profile,
  a small synthetic world bootstrapped once, signed models, and the console dev server.
  Nothing is in DEMO MODE: resolutions need a signed operator assertion, as in production.
* **StagingLike**: the existing ``deploy/staging`` stack, unchanged (see :mod:`localrun.cli`).

No mode changes a security setting behind the user's back: the environment is exactly what
is listed here, plus ``LOCAL_LLM_*`` from ``sentinel.local.env`` when set.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from localrun import config as cfg
from localrun.paths import CONSOLE, REPO, Runtime, python

DEMO, DEV, STAGING = "demo", "dev", "staging"
MODES = {"demo": DEMO, "dev": DEV, "staginglike": STAGING, "staging": STAGING}
COMPOSE_PROJECT = "sentinel-local"
COMPOSE_FILE = REPO / "compose.local.yml"
# Variables that would silently redirect a mode to another database or state store.
_SCRUB = ("DATABASE_URL", "STATE_BACKEND", "REDIS_URL", "DEMO_MODE", "ENVIRONMENT")
DEV_SCOPES = (
    "assessment:read",
    "review:read",
    "review:write",
    "policy:read",
    "investigation:write",
    "metrics:read",
    "analyst:read",
    "score:write",
)


class ModeError(Exception):
    """The mode cannot start (the message says what to do)."""


def parse_mode(raw: str) -> str:
    try:
        return MODES[raw.strip().lower()]
    except KeyError:
        raise ModeError(f"unknown mode {raw!r}: use Demo, Dev or StagingLike") from None


@dataclass
class Proc:
    name: str
    command: list[str]
    env: dict[str, str]
    cwd: Path
    port: int
    port_setting: str
    health_path: str

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@dataclass
class Plan:
    mode: str
    api: Proc
    console: Proc
    database: str
    redis: str  # a URL without credentials, or "NOT USED"
    demo_root: Path | None = None
    credentials: Path | None = None
    notes: list[str] = field(default_factory=list)


def base_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _SCRUB}
    env["PYTHONUNBUFFERED"] = "1"
    return env


def node() -> str:
    found = shutil.which("node")
    if not found:
        raise ModeError("Node.js is not on PATH: install Node 22 LTS, then run setup-local")
    return found


def console_command(console_mode: str, port: int) -> list[str]:
    entry = CONSOLE / "node_modules" / "next" / "dist" / "bin" / "next"
    return [node(), str(entry), console_mode, "-p", str(port), "-H", "127.0.0.1"]


def load_demo_env(root: Path) -> dict[str, str]:
    return cfg.parse_env((root / "demo.env").read_text(encoding="utf-8"))


def demo_plan(settings: cfg.Settings, rt: Runtime, console_mode: str = "start") -> Plan:
    root = settings.demo_root
    if not (root / "catalogue.json").exists():
        raise ModeError(f"no demo world in {root}")
    api_port = settings.port("SENTINEL_API_PORT")
    console_port = settings.port("SENTINEL_CONSOLE_PORT")
    api_env = {
        **base_env(),
        **load_demo_env(root),
        **settings.llm(),
        "DEMO_MODE": "true",
        "SERVICE_HOST": "127.0.0.1",
        "SERVICE_PORT": str(api_port),
    }
    api = Proc(
        "api",
        [python(), "-m", "fraud_ai", "service", "run"],
        api_env,
        REPO,
        api_port,
        "SENTINEL_API_PORT",
        "/v1/ready",
    )
    console_env = {
        **base_env(),
        "FRAUD_API_BASE_URL": f"http://127.0.0.1:{api_port}",
        "FRAUD_API_CREDENTIAL_FILE": str(rt.run / "credential"),
        "FRAUD_API_SIGNING_SECRET_FILE": str(rt.run / "signing-secret"),
        "SENTINEL_ENVIRONMENT": "demo",
        "SENTINEL_DEMO_MODE": "true",
        "SENTINEL_DEMO_ROOT": str(root),
        "SENTINEL_OPERATOR_ID": "rita",
        "SENTINEL_OPERATOR_KEY_FILE": str(root / "keys" / "operator-rita.pem"),
        "NEXT_TELEMETRY_DISABLED": "1",
    }
    console = Proc(
        "console",
        console_command(console_mode, console_port),
        console_env,
        CONSOLE,
        console_port,
        "SENTINEL_CONSOLE_PORT",
        "/api/session",
    )
    return Plan(
        DEMO,
        api,
        console,
        database=f"SQLite {root / 'fraud_ai_demo.db'}",
        redis="NOT USED",
        demo_root=root,
        credentials=root / "demo-credentials.json",
    )


def dev_service_env(settings: cfg.Settings, rt: Runtime) -> dict[str, str]:
    """The service environment for Dev mode (also used by the one-off bootstrap commands)."""
    secrets = cfg.dev_secrets(rt)
    pg = settings.port("SENTINEL_PG_PORT")
    redis = settings.port("SENTINEL_REDIS_PORT")
    public = rt.secrets / "keys" / "model.pub"
    env = {
        **base_env(),
        "ENVIRONMENT": "development",
        "DATABASE_URL": f"postgresql+psycopg://fraud_ai:{secrets['POSTGRES_PASSWORD']}"
        f"@127.0.0.1:{pg}/fraud_ai_dev",
        "STATE_BACKEND": "redis",
        "REDIS_URL": f"redis://:{secrets['REDIS_PASSWORD']}@127.0.0.1:{redis}/0",
        "MODEL_DIRECTORY": str(rt.dev / "models"),
        "PSEUDONYMISATION_KEY": secrets["PSEUDONYMISATION_KEY"],
        "SERVICE_SIGNING_MASTER_KEY": secrets["SERVICE_SIGNING_MASTER_KEY"],
        "PAYMENT_AUTH_WEBHOOK_SECRET": secrets["PAYMENT_AUTH_WEBHOOK_SECRET"],
        "PAYMENT_AUTH_PROVIDER": "fake",
        "SERVICE_REQUIRE_SIGNATURES": "true",
        "SIGNATURE_MIN_VERSION": "v2",
        "LOCAL_LLM_RUNTIME": "reference",
        **settings.llm(),
    }
    if public.exists():
        env["MODEL_SIGNATURES_REQUIRED"] = "true"
        env["MODEL_SIGNING_PUBLIC_KEYS"] = public.read_text(encoding="utf-8").strip()
    return env


def dev_plan(settings: cfg.Settings, rt: Runtime, console_mode: str = "dev") -> Plan:
    api_port = settings.port("SENTINEL_API_PORT")
    console_port = settings.port("SENTINEL_CONSOLE_PORT")
    credentials = rt.secrets / "dev-credentials.json"
    if not credentials.exists():
        raise ModeError("Dev mode is not bootstrapped (no console API key)")
    api_env = {
        **dev_service_env(settings, rt),
        "SERVICE_HOST": "127.0.0.1",
        "SERVICE_PORT": str(api_port),
    }
    api = Proc(
        "api",
        [python(), "-m", "fraud_ai", "service", "run"],
        api_env,
        REPO,
        api_port,
        "SENTINEL_API_PORT",
        "/v1/ready",
    )
    console_env = {
        **base_env(),
        "FRAUD_API_BASE_URL": f"http://127.0.0.1:{api_port}",
        "FRAUD_API_CREDENTIAL_FILE": str(rt.run / "credential"),
        "FRAUD_API_SIGNING_SECRET_FILE": str(rt.run / "signing-secret"),
        "SENTINEL_ENVIRONMENT": "development",
        "NEXT_TELEMETRY_DISABLED": "1",
    }
    console = Proc(
        "console",
        console_command(console_mode, console_port),
        console_env,
        CONSOLE,
        console_port,
        "SENTINEL_CONSOLE_PORT",
        "/api/session",
    )
    redis = settings.port("SENTINEL_REDIS_PORT")
    pg = settings.port("SENTINEL_PG_PORT")
    return Plan(
        DEV,
        api,
        console,
        database=f"PostgreSQL 127.0.0.1:{pg}/fraud_ai_dev (Docker)",
        redis=f"redis://127.0.0.1:{redis}/0 (Docker)",
        credentials=credentials,
    )


def plan_for(mode: str, settings: cfg.Settings, rt: Runtime, console_mode: str | None) -> Plan:
    if mode == DEMO:
        return demo_plan(settings, rt, console_mode or "start")
    if mode == DEV:
        return dev_plan(settings, rt, console_mode or "dev")
    raise ModeError("StagingLike is run by deploy/staging/stack.sh, not the supervisor")


def write_credentials(plan: Plan, rt: Runtime) -> None:
    """Copy the console's API key and signing secret into 0600 files for its server only."""
    assert plan.credentials is not None
    creds = json.loads(plan.credentials.read_text(encoding="utf-8"))
    for name, value in (
        ("credential", creds["credential"]),
        ("signing-secret", creds["signing_secret"]),
    ):
        target = rt.run / name
        target.unlink(missing_ok=True)
        cfg.write_private(target, value)
