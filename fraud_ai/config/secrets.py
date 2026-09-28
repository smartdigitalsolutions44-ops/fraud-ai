"""Secret resolution (Stage 10).

Secrets reach :class:`~fraud_ai.config.settings.Settings` through a small provider chain:

1. **Environment variable**, for example ``PSEUDONYMISATION_KEY``.
2. **File reference**, ``PSEUDONYMISATION_KEY_FILE=/run/secrets/pseudonymisation_key``.
   This is the Docker/Kubernetes secrets convention: the value never appears in the
   environment, in ``docker inspect`` or in process listings. Trailing newlines are
   stripped. A file readable by group or others is accepted (Docker mounts secrets
   ``0444``) but logged as a warning.

Setting both the variable and its ``_FILE`` form is refused: which one wins would be
ambiguous.

**Cloud secret managers** (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) plug
in as another :class:`SecretsProvider` whose ``get(name)`` calls the vendor SDK. They are
deliberately not bundled: each needs its own credentials, SDK and IAM policy. The usual,
SDK-free integration is to let the platform mount the secret as a file (the CSI Secrets
Store driver, ECS/Fargate secrets, Cloud Run secret volumes) and use ``*_FILE``. See
HARDENING.md.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

#: Settings fields that are secrets (upper-case env names).
SECRET_NAMES = (
    "PSEUDONYMISATION_KEY",
    "SERVICE_SIGNING_MASTER_KEY",
    "SERVICE_SIGNING_PREVIOUS_KEY",
    "PAYMENT_AUTH_WEBHOOK_SECRET",
    "STRIPE_API_KEY",
    "REDIS_URL",
    "DATABASE_URL",
)
MAX_SECRET_BYTES = 16 * 1024


class SecretError(ValueError):
    pass


class SecretsProvider(Protocol):
    def get(self, name: str) -> str | None: ...


class EnvSecretsProvider:
    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._env = os.environ if environ is None else environ

    def get(self, name: str) -> str | None:
        return self._env.get(name) or self._env.get(name.lower()) or None


class FileSecretsProvider:
    """``<NAME>_FILE`` points at a file whose content is the secret."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._env = os.environ if environ is None else environ
        self.warnings: list[str] = []

    def get(self, name: str) -> str | None:
        ref = self._env.get(f"{name}_FILE") or self._env.get(f"{name.lower()}_file")
        if not ref:
            return None
        path = Path(ref)
        try:
            info = path.stat()
        except OSError:
            raise SecretError(f"{name}_FILE points at a missing or unreadable file") from None
        if not stat.S_ISREG(info.st_mode):
            raise SecretError(f"{name}_FILE must point at a regular file")
        if info.st_size > MAX_SECRET_BYTES:
            raise SecretError(f"{name}_FILE is larger than {MAX_SECRET_BYTES} bytes")
        if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            self.warnings.append(f"{name}_FILE is readable by group/others")
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
        if not value:
            raise SecretError(f"{name}_FILE is empty")
        return value


def resolve_file_secrets(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Secrets given as ``*_FILE`` references, keyed by lower-case settings field."""
    env = os.environ if environ is None else environ
    files = FileSecretsProvider(env)
    direct = EnvSecretsProvider(env)
    out: dict[str, str] = {}
    for name in SECRET_NAMES:
        from_file = files.get(name)
        if from_file is None:
            continue
        if direct.get(name) is not None:
            raise SecretError(f"both {name} and {name}_FILE are set; use exactly one")
        out[name.lower()] = from_file
    if files.warnings:
        from fraud_ai.utils.logging import get_logger

        for warning in files.warnings:
            get_logger("config").warning(warning)
    return out
