"""Stage 12 key management: the provider interface, Vault transit (against a local fake
server, and a real Vault when TEST_VAULT_ADDR is set), purpose separation and the
fail-closed rule (no fallback from a configured KMS to local key files)."""

from __future__ import annotations

import base64
import json
import os
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from fraud_ai.config.settings import Environment, Settings
from fraud_ai.trust import keys as tk
from fraud_ai.trust.kms import (
    KeyProviderError,
    LocalFileProvider,
    VaultClient,
    VaultTransitProvider,
    VaultTransitSigner,
    provider_from_settings,
    signer_for,
)

TOKEN = "hvs.test-token-0123456789abcdef"


class FakeVault:
    """The transit endpoints used: keys/<name> (GET, POST), keys/<name>/rotate, sign/<name>."""

    def __init__(self) -> None:
        self.keys: dict[str, dict[str, Any]] = {}
        self.fail_sign_with: bytes | None = None
        self.sign_version_override: int | None = None
        self.calls: list[str] = []

    def create(self, name: str, key_type: str = "ed25519", exportable: bool = False) -> None:
        self.keys[name] = {"type": key_type, "exportable": exportable, "versions": {}}
        self.rotate(name)

    def rotate(self, name: str) -> None:
        versions = self.keys[name]["versions"]
        versions[len(versions) + 1] = Ed25519PrivateKey.generate()

    def handler(self) -> type[BaseHTTPRequestHandler]:
        vault = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _reply(self, code: int, body: dict[str, Any]) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _route(self) -> tuple[str, str, str]:
                parts = self.path.split("/")  # /v1/transit/<op>/<name>[/rotate]
                vault.calls.append(f"{self.command} {self.path}")
                return parts[3], parts[4], parts[5] if len(parts) > 5 else ""

            def do_GET(self) -> None:
                if self.headers.get("X-Vault-Token") != TOKEN:
                    return self._reply(403, {"errors": ["permission denied"]})
                op, name, _ = self._route()
                key = vault.keys.get(name)
                if op != "keys" or key is None:
                    return self._reply(404, {"errors": []})
                raw = {
                    str(v): {
                        "public_key": base64.b64encode(
                            k.public_key().public_bytes(
                                serialization.Encoding.Raw, serialization.PublicFormat.Raw
                            )
                        ).decode()
                    }
                    for v, k in key["versions"].items()
                }
                self._reply(
                    200,
                    {
                        "data": {
                            "type": key["type"],
                            "exportable": key["exportable"],
                            "latest_version": max(key["versions"]),
                            "keys": raw,
                        }
                    },
                )

            def do_POST(self) -> None:
                if self.headers.get("X-Vault-Token") != TOKEN:
                    return self._reply(403, {"errors": ["permission denied"]})
                op, name, extra = self._route()
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
                if op == "keys" and extra == "rotate":
                    vault.rotate(name)
                    return self._reply(200, {})
                if op == "keys":
                    vault.create(name, body.get("type", "ed25519"))
                    return self._reply(200, {})
                if op == "sign":
                    key = vault.keys[name]
                    version = int(body["key_version"])
                    data = base64.b64decode(body["input"])
                    sig = vault.fail_sign_with or key["versions"][version].sign(data)
                    shown = vault.sign_version_override or version
                    return self._reply(
                        200,
                        {"data": {"signature": f"vault:v{shown}:{base64.b64encode(sig).decode()}"}},
                    )
                self._reply(404, {"errors": []})

        return Handler


@pytest.fixture
def vault() -> Iterator[tuple[FakeVault, str]]:
    fake = FakeVault()
    for purpose in ("model", "audit", "release"):
        fake.create(f"fraud-ai-{purpose}")
    server = ThreadingHTTPServer(("127.0.0.1", 0), fake.handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield fake, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def _vault_settings(addr: str, **kw: Any) -> Settings:
    values: dict[str, Any] = {
        "database_url": "sqlite:///x.db",
        "key_provider": "vault",
        "vault_addr": addr,
        "vault_token": TOKEN,
    }
    values.update(kw)
    return Settings(**values)


def test_vault_signer_signs_and_verifies(vault: tuple[FakeVault, str]) -> None:
    fake, addr = vault
    settings = _vault_settings(addr)
    signer = signer_for(settings, "audit")
    assert isinstance(signer, VaultTransitSigner) and signer.version == 1
    statement = {"chain": "x", "sequence": 1}
    sig = tk.sign("audit", signer, statement)
    assert tk.verify("audit", {signer.key_id: signer.public}, statement, sig) == signer.key_id
    # Purposes use different keys, so different key ids.
    ids = {signer_for(settings, p).key_id for p in ("model", "audit", "release")}
    assert len(ids) == 3
    assert any("/sign/fraud-ai-audit" in c for c in fake.calls)


def test_vault_failures_fail_closed(vault: tuple[FakeVault, str], tmp_path: Path) -> None:
    fake, addr = vault
    # A signature that is not from the key: refused by the local verification.
    fake.fail_sign_with = Ed25519PrivateKey.generate().sign(b"other")
    with pytest.raises(tk.TrustError, match="invalid signature"):
        tk.sign("model", signer_for(_vault_settings(addr), "model"), {"a": 1})
    fake.fail_sign_with = None
    fake.sign_version_override = 7
    with pytest.raises(KeyProviderError, match="version 7"):
        tk.sign("model", signer_for(_vault_settings(addr), "model"), {"a": 1})
    fake.sign_version_override = None
    # Wrong token, unknown key, wrong type, exportable key, unreachable Vault.
    with pytest.raises(KeyProviderError, match="HTTP 403"):
        signer_for(_vault_settings(addr, vault_token="hvs.wrong-token-000000000000"), "model")
    with pytest.raises(KeyProviderError, match="HTTP 404"):
        signer_for(_vault_settings(addr, vault_key_model="missing-key"), "model")
    fake.create("rsa-key", key_type="rsa-2048")
    with pytest.raises(KeyProviderError, match="not ed25519"):
        signer_for(_vault_settings(addr, vault_key_model="rsa-key"), "model")
    fake.create("exportable-key", exportable=True)
    with pytest.raises(KeyProviderError, match="exportable"):
        signer_for(_vault_settings(addr, vault_key_model="exportable-key"), "model")
    with pytest.raises(KeyProviderError, match="unreachable"):
        signer_for(_vault_settings("http://127.0.0.1:9", vault_timeout=1), "model")


def test_no_fallback_to_local_files(vault: tuple[FakeVault, str], tmp_path: Path) -> None:
    _, addr = vault
    key = tmp_path / "model.pem"
    tk.write_private_key(tk.generate(), key)
    with pytest.raises(KeyProviderError, match="no fallback"):
        signer_for(_vault_settings(addr), "model", key_file=key)
    with pytest.raises(ValidationError, match="never used as a fallback"):
        _vault_settings(addr, model_signing_private_key_file=key)
    # Vault down + a local key file present: still refused (it is a validation error to
    # even configure both), never silently used.
    with pytest.raises(KeyProviderError, match="unreachable"):
        signer_for(_vault_settings("http://127.0.0.1:9", vault_timeout=1), "model")


def test_kms_required_refuses_local_keys(tmp_path: Path) -> None:
    key = tmp_path / "audit.pem"
    tk.write_private_key(tk.generate(), key)
    local = Settings(database_url="sqlite:///x.db", audit_anchor_private_key_file=key)
    assert isinstance(provider_from_settings(local), LocalFileProvider)
    assert signer_for(local, "audit").key_id == tk.load_private_key(key).key_id
    strict = Settings(
        database_url="sqlite:///x.db", audit_anchor_private_key_file=key, kms_required=True
    )
    with pytest.raises(KeyProviderError, match="KMS_REQUIRED"):
        signer_for(strict, "audit")
    with pytest.raises(KeyProviderError, match="KMS_REQUIRED"):
        signer_for(strict, "audit", key_file=key)
    prod = Settings.model_construct(environment=Environment.PRODUCTION, kms_required=None)
    assert prod.kms_is_required
    with pytest.raises(KeyProviderError, match="no model signing key"):
        signer_for(Settings(database_url="sqlite:///x.db"), "model")
    with pytest.raises(KeyProviderError, match="unknown signing purpose"):
        signer_for(local, "image")


def test_purpose_separation_in_settings() -> None:
    with pytest.raises(ValidationError, match="different keys"):
        Settings(database_url="sqlite:///x.db", vault_key_audit="fraud-ai-model")
    with pytest.raises(ValidationError, match="different keys"):
        Settings(database_url="sqlite:///x.db", vault_key_image="fraud-ai-release")
    with pytest.raises(ValidationError, match="https VAULT_ADDR"):
        Settings(
            environment=Environment.PRODUCTION,
            database_url="postgresql+psycopg://u:p@db/x",
            pseudonymisation_key="k" * 40,
            key_provider="vault",
            vault_addr="http://vault:8200",
            vault_token=TOKEN,
        )
    # The service needs no Vault token (it only verifies); a signer without one fails.
    tokenless = Settings(
        database_url="sqlite:///x.db", key_provider="vault", vault_addr="http://v:8200"
    )
    with pytest.raises(KeyProviderError, match="VAULT_TOKEN"):
        signer_for(tokenless, "model")
    # One secret, one purpose: the API signing key may not double as anything else.
    shared = "s" * 20 + "0123456789abcdefXYZ"
    with pytest.raises(ValidationError, match="reuses the value"):
        Settings(
            database_url="sqlite:///x.db",
            service_signing_master_key=shared,
            payment_auth_webhook_secret=shared,
        )
    with pytest.raises(ValidationError, match="reuses the value"):
        Settings(
            database_url="sqlite:///x.db",
            service_signing_master_key=shared,
            key_provider="vault",
            vault_addr="http://v:8200",
            vault_token=shared,
        )


def test_key_rotation_through_the_cli(vault: tuple[FakeVault, str], sqlite_url: str) -> None:
    from click.testing import CliRunner

    from fraud_ai.cli.main import cli
    from fraud_ai.config.settings import get_settings

    _, addr = vault
    before = signer_for(_vault_settings(addr), "audit")
    env = {
        "DATABASE_URL": sqlite_url,
        "KEY_PROVIDER": "vault",
        "VAULT_ADDR": addr,
        "VAULT_TOKEN": TOKEN,
        "AUDIT_ANCHOR_PUBLIC_KEYS": tk.encode_public(before.public),
    }

    def run(*args: str) -> Any:
        get_settings.cache_clear()
        try:
            return CliRunner().invoke(cli, list(args), env=env)
        finally:
            get_settings.cache_clear()

    status = run("keys", "status")
    assert "audit" in status.output and before.key_id in status.output
    assert status.exit_code == 1  # model and release keys are not trusted yet
    rotated = run("keys", "rotate", "--purpose", "audit")
    assert rotated.exit_code == 0, rotated.output
    after = signer_for(_vault_settings(addr), "audit")
    assert after.key_id != before.key_id and after.key_id in rotated.output
    # The new version is not trusted until the operator adds it: signing refuses.
    from fraud_ai.database.engine import create_db_engine, make_session_factory
    from fraud_ai.trust.anchors import FileAnchorStore, create_anchor

    engine = create_db_engine(sqlite_url)
    with make_session_factory(engine)() as s, pytest.raises(tk.TrustError, match="not in"):
        create_anchor(s, FileAnchorStore(Path("anchors")), after, actor="t",
                      trusted={before.key_id: before.public})  # fmt: skip
    engine.dispose()
    assert "signing_key.rotated" in run("audit", "list").output


@pytest.mark.skipif(not os.environ.get("TEST_VAULT_ADDR"), reason="TEST_VAULT_ADDR not set")
def test_real_vault_transit() -> None:
    """Against a real Vault (the staging container): create, sign, verify, rotate."""
    import secrets

    addr = os.environ["TEST_VAULT_ADDR"]
    token = os.environ["TEST_VAULT_TOKEN"]
    client = VaultClient(addr, token)
    name = f"fraud-ai-test-{secrets.token_hex(4)}"
    client.create_key(name)
    provider = VaultTransitProvider(client, {"audit": name})
    signer = provider.signer("audit")
    sig = tk.sign("audit", signer, {"n": 1})
    assert tk.verify("audit", {signer.key_id: signer.public}, {"n": 1}, sig)
    client.rotate_key(name)
    assert provider.signer("audit").key_id != signer.key_id
