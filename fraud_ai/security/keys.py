"""Resolution of the pseudonymisation key.

Production/staging: the key must come from ``PSEUDONYMISATION_KEY`` (enforced by settings).
Development: if unset, a random key is generated once and persisted with 0600 permissions in
the data directory, so hashes stay stable across runs without any secret in source code.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from fraud_ai.config.settings import Environment, Settings
from fraud_ai.security.hashing import Pseudonymiser
from fraud_ai.utils.logging import get_logger

log = get_logger(__name__)

DEV_KEY_FILENAME = ".pseudonymisation_key"


class KeyConfigurationError(RuntimeError):
    pass


def resolve_pseudonymisation_key(settings: Settings) -> bytes:
    if settings.pseudonymisation_key is not None:
        return settings.pseudonymisation_key.get_secret_value().encode()
    if settings.environment not in {Environment.DEVELOPMENT, Environment.TEST}:
        raise KeyConfigurationError("PSEUDONYMISATION_KEY must be set")
    return _load_or_create_dev_key(settings.data_directory / DEV_KEY_FILENAME)


def _load_or_create_dev_key(path: Path) -> bytes:
    if path.exists():
        return path.read_text().strip().encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(key)
    log.warning("generated development pseudonymisation key at %s", path)
    return key.encode()


def build_pseudonymiser(settings: Settings) -> Pseudonymiser:
    return Pseudonymiser(resolve_pseudonymisation_key(settings))
