"""Stage 9 test helpers: a service harness and a TEST-ONLY software authenticator.

:class:`SoftAuthenticator` produces real WebAuthn responses: an EC P-256 key,
``"none"`` attestation, and ECDSA-SHA256 over ``authenticatorData || SHA-256(clientDataJSON)``.
The service verifies them with the unmodified py_webauthn library. It exists only to
exercise the ceremony in tests; real users use platform or roaming authenticators.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from fraud_ai.config.settings import Settings
from fraud_ai.database.engine import session_scope
from fraud_ai.service.app import build_container, create_app
from fraud_ai.service.dependencies import ServiceContainer
from fraud_ai.service.keys import create_key, signing_secret
from fraud_ai.service.signatures import sign, sign_v2

MASTER_KEY = "test-signing-master-key-0123456789abcdef"
WEBHOOK_SECRET = "test-payment-webhook-secret-0123456789ab"
RP_ID, ORIGIN = "localhost", "http://localhost:8080"
ALL_SCOPES = (
    "score:write",
    "score:replay",
    "signals:trusted",
    "assessment:read",
    "review:read",
    "review:write",
    "policy:read",
    "stepup:write",
    "webauthn:write",
    "investigation:write",
    "metrics:read",
    "analyst:read",
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Clock:
    def __init__(self, now: datetime | None = None) -> None:
        self.now = now or datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now


@dataclass
class SoftAuthenticator:
    """TEST-ONLY software passkey. Never use outside tests."""

    rp_id: str = RP_ID
    origin: str = ORIGIN
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    credential_id: bytes = field(default_factory=lambda: os.urandom(32))
    counter: int = 0

    def _client_data(self, kind: str, challenge: str, origin: str | None = None) -> bytes:
        return json.dumps(
            {
                "type": kind,
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()

    def register(self, options: dict[str, Any]) -> dict[str, Any]:
        numbers = self.key.public_key().public_numbers()
        cose = cbor2.dumps(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )
        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([0x45])  # UP | UV | AT
            + self.counter.to_bytes(4, "big")
            + bytes(16)  # AAGUID
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id
            + cose
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data("webauthn.create", options["challenge"])
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
        }

    def assertion(
        self,
        options: dict[str, Any],
        *,
        challenge: str | None = None,
        flags: int = 0x05,  # UP | UV
        counter: int | None = None,
        origin: str | None = None,
        tamper: bool = False,
    ) -> dict[str, Any]:
        self.counter = self.counter + 1 if counter is None else counter
        client_data = self._client_data(
            "webauthn.get", challenge or options["challenge"], origin=origin
        )
        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([flags])
            + self.counter.to_bytes(4, "big")
        )
        signature = self.key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        if tamper:
            signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(signature),
            },
            "clientExtensionResults": {},
        }


@dataclass
class Harness:
    app: FastAPI
    client: TestClient
    container: ServiceContainer
    clock: Clock
    settings: Settings

    def key(self, *scopes: str, name: str = "test") -> str:
        with session_scope(self.container.factory) as session:
            return create_key(session, name, list(scopes or ALL_SCOPES)).credential

    def auth(self, credential: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {credential}"}

    def signed(
        self,
        credential: str,
        body: bytes,
        *,
        timestamp: int | None = None,
        version: str = "v1",
        method: str = "POST",
        path: str = "/v1/score",
        master: str = MASTER_KEY,
    ) -> dict[str, str]:
        key_id = credential.split(".", 1)[0]
        ts = int(self.clock().timestamp()) if timestamp is None else timestamp
        secret = signing_secret(master, key_id)
        if version == "v2":
            bare, _, query = path.partition("?")
            signature = sign_v2(secret, method, bare, ts, body, query=query)
        else:
            signature = sign(secret, ts, body)
        return {"X-Fraud-Timestamp": str(ts), "X-Fraud-Signature": signature}

    def post(
        self,
        path: str,
        credential: str | None,
        payload: Any = None,
        *,
        sign_it: bool = False,
        headers: dict[str, str] | None = None,
        raw: bytes | None = None,
        sign_version: str = "v1",
    ) -> Any:
        body = raw if raw is not None else json.dumps(payload).encode()
        h = {"Content-Type": "application/json", **(headers or {})}
        if credential is not None:
            h.update(self.auth(credential))
            if sign_it:
                h.update(self.signed(credential, body, version=sign_version, path=path))
        return self.client.post(path, content=body, headers=h)

    def get(
        self,
        path: str,
        credential: str | None,
        *,
        sign_it: bool = False,
        sign_version: str = "v1",
        **kwargs: Any,
    ) -> Any:
        headers = self.auth(credential) if credential else {}
        if credential and sign_it:
            headers.update(
                self.signed(credential, b"", version=sign_version, method="GET", path=path)
            )
        headers.update(kwargs.pop("headers", {}))
        return self.client.get(path, headers=headers, **kwargs)

    def score(self, credential: str, event: dict[str, Any], **kwargs: Any) -> Any:
        if "arrival_time" in event:
            self.clock.now = datetime.fromisoformat(event["arrival_time"])
        return self.post("/v1/score", credential, event, **kwargs)

    def drive(
        self, credential: str, events: list[dict[str, Any]], decision: str, start: int = 0
    ) -> tuple[dict[str, Any], int]:
        """Score events in arrival order until one gets ``decision``."""
        for i in range(start, len(events)):
            response = self.score(credential, events[i])
            assert response.status_code in (200, 202), response.text
            body = response.json()
            if body.get("decision") == decision and body["status"] == "decided":
                return body, i + 1
        raise AssertionError(f"no {decision} in the stream")


def settings_for(url: str, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "database_url": url,
        "service_signing_master_key": MASTER_KEY,
        "rate_limit": "100000/minute",
        # Generous: a cold first scoring (model loads) on a busy CI machine must not flake.
        "service_request_timeout": 60,
        "rate_limit_burst": 10_000,
        "payment_auth_provider": "fake",
        "payment_auth_webhook_secret": WEBHOOK_SECRET,
        "webauthn_rp_id": RP_ID,
        "webauthn_origin": ORIGIN,
    }
    values.update(overrides)
    return Settings(**values)


def make_harness(
    url: str, *, engine: Engine | None = None, clock: Clock | None = None, **kwargs: Any
) -> Harness:
    container_kwargs = {
        k: kwargs.pop(k)
        for k in ("payment_provider", "llm_client", "limiter", "shared_state")
        if k in kwargs
    }
    settings = settings_for(url, **kwargs)
    clock = clock or Clock()
    container = build_container(settings, engine=engine, clock=clock, **container_kwargs)
    app = create_app(settings, container=container)
    client = TestClient(app, raise_server_exceptions=False)
    return Harness(app, client, container, clock, settings)
