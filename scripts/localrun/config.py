"""Local configuration (``sentinel.local.env``) and development secrets.

``sentinel.local.env`` holds ports and preferences only, never secrets. It is created once
from ``sentinel.local.env.example`` and never overwritten. Development secrets are generated
once into ``.runtime/secrets/dev.env`` (0600) and reused, so a second setup never changes a
password that an existing Docker volume was initialised with.
"""

from __future__ import annotations

import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

from localrun.paths import REPO, Runtime

EXAMPLE = REPO / "sentinel.local.env.example"
LOCAL = REPO / "sentinel.local.env"

DEFAULTS = {
    "SENTINEL_API_PORT": "8080",
    "SENTINEL_CONSOLE_PORT": "3000",
    "SENTINEL_PG_PORT": "55432",
    "SENTINEL_REDIS_PORT": "56379",
    "SENTINEL_OPEN_BROWSER": "true",
    "SENTINEL_DEMO_ROOT": "data/demo",
}
# Passed through to the service when set (optional local LLM; analyst assistance only).
LLM_KEYS = ("LOCAL_LLM_RUNTIME", "LOCAL_LLM_MODEL", "LOCAL_LLM_ENDPOINT", "LOCAL_LLM_TIMEOUT")
DEV_SECRET_KEYS = (
    "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
    "PSEUDONYMISATION_KEY",
    "SERVICE_SIGNING_MASTER_KEY",
    "PAYMENT_AUTH_WEBHOOK_SECRET",
)


class ConfigError(Exception):
    """The local configuration is unusable (the message says how to fix it)."""


def parse_env(text: str) -> dict[str, str]:
    """``KEY=VALUE`` lines; ``#`` comments and blank lines ignored; quotes stripped."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def ensure_local_file(local: Path = LOCAL, example: Path = EXAMPLE) -> bool:
    """Create ``sentinel.local.env`` from the example if missing. True when created."""
    if local.exists():
        return False
    shutil.copyfile(example, local)
    return True


@dataclass(frozen=True)
class Settings:
    values: dict[str, str]

    def get(self, key: str) -> str:
        return self.values.get(key, DEFAULTS.get(key, ""))

    def port(self, key: str) -> int:
        raw = self.get(key)
        try:
            port = int(raw)
        except ValueError:
            raise ConfigError(f"{key}={raw!r} in sentinel.local.env is not a port") from None
        if not 1024 <= port <= 65535:
            raise ConfigError(f"{key}={port} must be between 1024 and 65535")
        return port

    def flag(self, key: str) -> bool:
        return self.get(key).strip().lower() in {"1", "true", "yes", "on"}

    @property
    def demo_root(self) -> Path:
        root = Path(self.get("SENTINEL_DEMO_ROOT"))
        return (root if root.is_absolute() else REPO / root).resolve()

    def llm(self) -> dict[str, str]:
        return {key: self.values[key] for key in LLM_KEYS if self.values.get(key)}


def load(local: Path = LOCAL) -> Settings:
    """Defaults, then ``sentinel.local.env``, then ``SENTINEL_*`` environment overrides."""
    values = dict(DEFAULTS)
    if local.exists():
        values.update(parse_env(local.read_text(encoding="utf-8")))
    values.update({k: v for k, v in os.environ.items() if k.startswith("SENTINEL_")})
    for key in LLM_KEYS:
        if os.environ.get(key):
            values[key] = os.environ[key]
    return Settings(values)


def write_private(path: Path, text: str) -> None:
    """Create a 0600 file (refuses to overwrite: callers decide that explicitly)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def dev_secrets(rt: Runtime) -> dict[str, str]:
    """Development secrets: generated on first use, then always the same values.

    A key missing from an existing file is added; existing values are never replaced."""
    path = rt.secrets / "dev.env"
    existing = parse_env(path.read_text(encoding="utf-8")) if path.exists() else {}
    missing = [key for key in DEV_SECRET_KEYS if not existing.get(key)]
    if not missing:
        return existing
    values = {**existing, **{key: secrets.token_urlsafe(32) for key in missing}}
    lines = ["# SENTINEL Dev-mode secrets: generated once, local only, never committed"]
    lines += [f"{key}={values[key]}" for key in sorted(values)]
    tmp = path.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    write_private(tmp, "\n".join(lines) + "\n")
    os.replace(tmp, path)
    return values
