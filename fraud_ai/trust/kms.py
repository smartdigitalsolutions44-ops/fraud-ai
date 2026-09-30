"""Key-management providers for the trust-chain signing keys (Stage 12).

The model, audit and release keys sign statements (:mod:`fraud_ai.trust.keys`). Where the
private key lives is a **provider**, chosen with ``KEY_PROVIDER``:

* ``local`` (development): an Ed25519 PKCS#8 PEM file, 0600, given with ``--key`` or a
  ``*_PRIVATE_KEY_FILE`` setting.
* ``vault``: the HashiCorp Vault **transit** secrets engine. The key is created inside
  Vault (type ``ed25519``) and never leaves it; Vault signs the message and returns the
  signature. Every signature is verified locally against Vault's public key before it is
  used (:func:`fraud_ai.trust.keys.sign`).

Other KMS/HSM products (AWS KMS, Azure Key Vault, GCP KMS, a PKCS#11 HSM) plug in as another
:class:`KeyProvider`. The core code only sees :class:`~fraud_ai.trust.keys.Signer`; nothing
outside this module knows which vendor is in use. AWS KMS and Azure Key Vault do not offer
Ed25519 signing today. There the statement format would need an ECDSA P-256 variant; it is
not implemented, so those vendors are not claimed.

**Fail closed.** With ``KEY_PROVIDER=vault``:

* an unreachable Vault, a missing key, a wrong key type or a bad signature is an error.
  There is **never** a fallback to a local file;
* a local key file (``--key`` or a ``*_PRIVATE_KEY_FILE`` setting) is refused outright, so
  a leftover development key cannot be used by accident.

With ``KMS_REQUIRED=true`` (the default in production), ``KEY_PROVIDER=local`` is refused.

**Purpose separation.** Each purpose has its own Vault key (``VAULT_KEY_MODEL``,
``VAULT_KEY_AUDIT``, ``VAULT_KEY_RELEASE``; the image key ``VAULT_KEY_IMAGE`` is used by
cosign). Settings refuse two purposes naming the same key. The public keys still have to be
listed in the per-purpose trusted sets, which refuse overlaps. A Vault token should be
scoped by a Vault policy to the one ``sign`` path its job needs (see DEPLOYMENT.md).
"""

from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import quote, urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from fraud_ai.trust import keys as tk
from fraud_ai.trust.keys import Signer, TrustError

if TYPE_CHECKING:
    from fraud_ai.config.settings import Settings

PROVIDERS = ("local", "vault")
STATEMENT_PURPOSES = ("model", "audit", "release")
_SIGNATURE = re.compile(r"^vault:v(\d+):([A-Za-z0-9+/=]+)$")
_KEY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class KeyProviderError(TrustError):
    """A key-management failure. Signing stops; nothing falls back."""


class KeyProvider(Protocol):
    name: str

    def signer(self, purpose: str) -> Signer: ...

    def describe(self, purpose: str) -> str: ...


# --------------------------------------------------------------------------- local files
class LocalFileProvider:
    name = "local"

    def __init__(self, files: dict[str, Path | None]) -> None:
        self.files = files

    def signer(self, purpose: str) -> Signer:
        path = self.files.get(purpose)
        if path is None:
            raise KeyProviderError(
                f"no {purpose} signing key: give --key or set the {purpose} *_PRIVATE_KEY_FILE"
            )
        return tk.load_private_key(path)

    def describe(self, purpose: str) -> str:
        path = self.files.get(purpose)
        return f"file:{path}" if path else "file:<not configured>"


# --------------------------------------------------------------------------- Vault transit
class VaultClient:
    """The few transit-engine calls needed, over HTTPS (or HTTP inside an isolated
    network in staging; production settings require HTTPS). Every failure raises."""

    def __init__(
        self,
        addr: str,
        token: str,
        *,
        mount: str = "transit",
        ca_file: Path | None = None,
        timeout: float = 5.0,
        namespace: str | None = None,
    ) -> None:
        parsed = urlparse(addr)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise KeyProviderError("VAULT_ADDR must be an http(s) URL")
        if not token:
            raise KeyProviderError("VAULT_TOKEN (or VAULT_TOKEN_FILE) is not set")
        if not _KEY_NAME.match(mount):
            raise KeyProviderError("VAULT_TRANSIT_MOUNT is not a valid mount path")
        self.addr = addr.rstrip("/")
        self._token = token
        self.mount = mount
        self.timeout = timeout
        self.namespace = namespace
        self._context: ssl.SSLContext | None = None
        if parsed.scheme == "https":
            self._context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        url = f"{self.addr}/v1/{self.mount}/{path}"
        data = None if body is None else json.dumps(body).encode()
        headers = {"X-Vault-Token": self._token, "Content-Type": "application/json"}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        request = urllib.request.Request(url, data=data, method=method, headers=headers)  # noqa: S310
        try:
            with urllib.request.urlopen(  # noqa: S310  # nosec B310 - scheme checked above
                request, timeout=self.timeout, context=self._context
            ) as response:
                payload = response.read()
        except urllib.error.HTTPError as exc:
            # Vault error bodies carry messages, never the token; keep them short anyway.
            detail = exc.read(300).decode(errors="replace").replace("\n", " ")
            raise KeyProviderError(
                f"Vault refused {method} {self.mount}/{path}: HTTP {exc.code} {detail}"
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise KeyProviderError(f"Vault is unreachable at {self.addr}: {reason}") from None
        try:
            return json.loads(payload) if payload else {}
        except ValueError:
            raise KeyProviderError("Vault returned a non-JSON response") from None

    def read_key(self, name: str) -> dict[str, Any]:
        data = self._request("GET", f"keys/{quote(name, safe='')}").get("data")
        if not isinstance(data, dict):
            raise KeyProviderError(f"Vault key {name!r} has no data")
        return data

    def create_key(self, name: str, key_type: str = "ed25519") -> None:
        self._request("POST", f"keys/{quote(name, safe='')}", {"type": key_type})

    def rotate_key(self, name: str) -> None:
        self._request("POST", f"keys/{quote(name, safe='')}/rotate", {})

    def sign(self, name: str, data: bytes, version: int) -> tuple[int, bytes]:
        response = self._request(
            "POST",
            f"sign/{quote(name, safe='')}",
            {"input": base64.b64encode(data).decode(), "key_version": version},
        )
        value = (response.get("data") or {}).get("signature", "")
        match = _SIGNATURE.match(str(value))
        if match is None:
            raise KeyProviderError(f"Vault returned a malformed signature for {name!r}")
        return int(match.group(1)), base64.b64decode(match.group(2))


@dataclass
class VaultTransitSigner:
    """One Vault transit key version, pinned when the signer is created."""

    client: VaultClient
    key_name: str
    version: int
    public: Ed25519PublicKey

    @classmethod
    def open(cls, client: VaultClient, key_name: str) -> VaultTransitSigner:
        if not _KEY_NAME.match(key_name):
            raise KeyProviderError(f"invalid Vault key name {key_name!r}")
        data = client.read_key(key_name)
        if data.get("type") != "ed25519":
            raise KeyProviderError(
                f"Vault key {key_name!r} is {data.get('type')!r}, not ed25519; refusing it"
            )
        if data.get("exportable") or data.get("allow_plaintext_backup"):
            raise KeyProviderError(
                f"Vault key {key_name!r} is exportable; the private key must not leave Vault"
            )
        version = int(data.get("latest_version") or 0)
        entry = (data.get("keys") or {}).get(str(version)) or {}
        public = entry.get("public_key") if isinstance(entry, dict) else None
        if not version or not public:
            raise KeyProviderError(f"Vault key {key_name!r} has no public key")
        try:
            raw = base64.b64decode(public)
            key = Ed25519PublicKey.from_public_bytes(raw)
        except ValueError:
            raise KeyProviderError(f"Vault key {key_name!r} has a malformed public key") from None
        return cls(client, key_name, version, key)

    @property
    def key_id(self) -> str:
        return tk.key_id(self.public)

    def sign_raw(self, data: bytes) -> bytes:
        version, signature = self.client.sign(self.key_name, data, self.version)
        if version != self.version:
            raise KeyProviderError(
                f"Vault signed with version {version} of {self.key_name!r}, expected {self.version}"
            )
        return signature


class VaultTransitProvider:
    name = "vault"

    def __init__(self, client: VaultClient, key_names: dict[str, str]) -> None:
        self.client = client
        self.key_names = key_names

    def signer(self, purpose: str) -> Signer:
        name = self.key_names.get(purpose)
        if not name:
            raise KeyProviderError(f"no Vault key configured for {purpose}")
        return VaultTransitSigner.open(self.client, name)

    def describe(self, purpose: str) -> str:
        return f"vault:{self.client.addr}/{self.client.mount}/{self.key_names.get(purpose)}"


# --------------------------------------------------------------------------- selection
def _private_key_files(settings: Settings) -> dict[str, Path | None]:
    return {
        "model": settings.model_signing_private_key_file,
        "audit": settings.audit_anchor_private_key_file,
        "release": settings.release_signing_private_key_file,
    }


def provider_from_settings(settings: Settings) -> KeyProvider:
    if settings.key_provider == "vault":
        token = settings.vault_token.get_secret_value() if settings.vault_token else ""
        client = VaultClient(
            settings.vault_addr or "",
            token,
            mount=settings.vault_transit_mount,
            ca_file=settings.vault_cacert,
            timeout=settings.vault_timeout,
            namespace=settings.vault_namespace,
        )
        return VaultTransitProvider(client, settings.vault_key_names)
    if settings.kms_is_required:
        raise KeyProviderError(
            f"KMS_REQUIRED is on ({settings.environment.value}): local key files are refused; "
            "set KEY_PROVIDER=vault"
        )
    return LocalFileProvider(_private_key_files(settings))


def signer_for(settings: Settings, purpose: str, *, key_file: Path | None = None) -> Signer:
    """The signer for ``purpose`` under the configured provider (fail closed)."""
    if purpose not in STATEMENT_PURPOSES:
        raise KeyProviderError(f"unknown signing purpose {purpose!r}")
    if key_file is not None:
        if settings.key_provider != "local":
            raise KeyProviderError(
                f"KEY_PROVIDER={settings.key_provider}: refusing the local key file {key_file} "
                "(no fallback from the configured KMS to local keys)"
            )
        if settings.kms_is_required:
            raise KeyProviderError("KMS_REQUIRED is on: local key files are refused")
        return tk.load_private_key(key_file)
    return provider_from_settings(settings).signer(purpose)
