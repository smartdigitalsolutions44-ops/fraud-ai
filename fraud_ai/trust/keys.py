"""Ed25519 keys and signed statements, one key set per purpose (Stage 11).

Standard cryptography only: Ed25519 (RFC 8032) through ``cryptography``. Nothing here is
home-made except the framing of what gets signed.

**Purposes and key separation.** There are three purposes: ``model`` (model artefacts),
``audit`` (audit-chain anchors) and ``release`` (release manifests).

* **Distinct keys:** each purpose has its own key pair, and a trusted key set per purpose.
  Configuration refuses a public key that is trusted for more than one purpose
  (:func:`check_separation`).
* **Distinct messages:** every signed message starts with a purpose-specific context line
  (``fraud-ai/<purpose>/v1``). Even a misconfigured key cannot make a model signature
  verify as an audit anchor or a release.
* **Not the API signing key:** request signing (HMAC) keys are symmetric and separate by
  construction.

**Private keys are never stored in the repository or the database.** They live in files
(PEM, PKCS#8, unencrypted, mode 0600), given to the signing commands with ``--key`` or a
``*_PRIVATE_KEY_FILE`` setting. The service itself only ever holds *public* keys.

**Key ids** are ``ed25519:`` plus the first 16 hex characters of SHA-256 over the raw
32-byte public key.

**Statements** are JSON objects serialised canonically: sorted keys, no whitespace, ASCII.
A signature covers ``context + "\\n" + canonical_json(statement)``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from fraud_ai.core.exceptions import FraudAIError

PURPOSES = ("model", "audit", "release")
ALGORITHM = "ed25519"
MAX_KEY_FILE_BYTES = 4096


class TrustError(FraudAIError):
    """A key, signature or statement problem. Never an 'allow'."""


def context(purpose: str) -> bytes:
    if purpose not in PURPOSES:
        raise TrustError(f"unknown signing purpose {purpose!r}")
    return f"fraud-ai/{purpose}/v1".encode()


def canonical_json(statement: dict[str, Any]) -> bytes:
    return json.dumps(
        statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def message(purpose: str, statement: dict[str, Any]) -> bytes:
    return context(purpose) + b"\n" + canonical_json(statement)


def _raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(key: Ed25519PublicKey) -> str:
    return "ed25519:" + hashlib.sha256(_raw_public(key)).hexdigest()[:16]


def encode_public(key: Ed25519PublicKey) -> str:
    """The form used in ``*_PUBLIC_KEYS`` settings: base64url of the raw 32 bytes."""
    return base64.urlsafe_b64encode(_raw_public(key)).decode().rstrip("=")


def decode_public(text: str) -> Ed25519PublicKey:
    value = text.strip()
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError):
        raise TrustError("malformed public key (expected base64url of 32 bytes)") from None
    if len(raw) != 32:
        raise TrustError("malformed public key (expected base64url of 32 bytes)")
    return Ed25519PublicKey.from_public_bytes(raw)


def parse_public_keys(value: str | None) -> dict[str, Ed25519PublicKey]:
    """``"<key>,<key>"`` -> ``{key_id: key}`` (empty for None/blank)."""
    keys: dict[str, Ed25519PublicKey] = {}
    for part in (value or "").split(","):
        if part.strip():
            key = decode_public(part)
            keys[key_id(key)] = key
    return keys


def check_separation(sets: dict[str, dict[str, Ed25519PublicKey]]) -> None:
    """Refuse any public key trusted for more than one purpose."""
    seen: dict[str, str] = {}
    for purpose, keys in sets.items():
        for kid in keys:
            if kid in seen:
                raise TrustError(
                    f"key {kid} is trusted for both {seen[kid]} and {purpose} signatures; "
                    "each purpose needs its own key"
                )
            seen[kid] = purpose


@dataclass(frozen=True)
class KeyPair:
    private: Ed25519PrivateKey

    @property
    def public(self) -> Ed25519PublicKey:
        return self.private.public_key()

    @property
    def key_id(self) -> str:
        return key_id(self.public)


def generate() -> KeyPair:
    return KeyPair(Ed25519PrivateKey.generate())


def write_private_key(pair: KeyPair, path: Path) -> None:
    """Write a new PKCS#8 PEM with mode 0600; never overwrites an existing file."""
    pem = pair.private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)


def load_private_key(path: Path) -> KeyPair:
    """A private key file: a regular file (no symlink), at most 4 KiB, not readable by group
    or others, holding an Ed25519 PKCS#8 PEM."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise TrustError(f"cannot open private key file {path}: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise TrustError(f"{path} is not a regular file")
        if info.st_mode & 0o077:
            raise TrustError(f"{path} must not be readable by group or others (chmod 600)")
        data = handle.read(MAX_KEY_FILE_BYTES + 1)
    if len(data) > MAX_KEY_FILE_BYTES:
        raise TrustError(f"{path} is too large for a private key")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError):
        raise TrustError(f"{path} is not an unencrypted PKCS#8 PEM private key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise TrustError(f"{path} is not an Ed25519 key")
    return KeyPair(key)


@dataclass(frozen=True)
class Signature:
    """A detached signature over a statement."""

    purpose: str
    key_id: str
    algorithm: str
    value: str  # base64url

    def to_dict(self) -> dict[str, str]:
        return {
            "purpose": self.purpose,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "signature": self.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Signature:
        try:
            return cls(
                str(data["purpose"]),
                str(data["key_id"]),
                str(data["algorithm"]),
                str(data["signature"]),
            )
        except (KeyError, TypeError):
            raise TrustError("malformed signature record") from None


def sign(purpose: str, pair: KeyPair, statement: dict[str, Any]) -> Signature:
    raw = pair.private.sign(message(purpose, statement))
    return Signature(
        purpose, pair.key_id, ALGORITHM, base64.urlsafe_b64encode(raw).decode().rstrip("=")
    )


def verify(
    purpose: str,
    trusted: dict[str, Ed25519PublicKey],
    statement: dict[str, Any],
    signature: Signature,
) -> str:
    """Verify; return the key id. Raises :class:`TrustError` for anything else: wrong
    purpose, algorithm or key, an untrusted key, or a bad signature."""
    if signature.purpose != purpose:
        raise TrustError(f"a {signature.purpose} signature cannot be used as a {purpose} one")
    if signature.algorithm != ALGORITHM:
        raise TrustError(f"unsupported signature algorithm {signature.algorithm!r}")
    key = trusted.get(signature.key_id)
    if key is None:
        raise TrustError(f"signing key {signature.key_id} is not trusted for {purpose}")
    value = signature.value
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        key.verify(raw, message(purpose, statement))
    except (InvalidSignature, ValueError, TypeError):
        raise TrustError(f"{purpose} signature does not verify") from None
    return signature.key_id
