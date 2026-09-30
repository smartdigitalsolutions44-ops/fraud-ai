"""Stage 12 pseudonym-scoped data export: one user only, an explicit column allow-list,
no secrets, keyed pseudonyms, internal model data, staff identities or other users."""

from __future__ import annotations

import json
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from sqlalchemy import func, select

from fraud_ai import audit
from fraud_ai.cli.main import cli
from fraud_ai.config.settings import get_settings
from fraud_ai.database.models import EventRecord, PaymentMethod, RiskAssessment, User
from fraud_ai.privacy.export import EXPORT, export_subject
from tests.operator_helpers import make_operators
from tests.realtime_world import World, open_world

SECRET_COLUMNS = {
    "token_reference",
    "fingerprint_hash",
    "address_hash",
    "device_hash",
    "ip_hash",
    "ip_address",
    "public_key",
    "credential_id",
    "sign_count",
    "credential_ref",
    "challenge_sha256",
    "token_ref_hash",
    "provider_reference",
    "model_scores",
    "ml_probability",
    "evidence_packet",
    "reviewer",
    "secret_sha256",
}


@pytest.fixture
def w(realtime_world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(realtime_world_dir, tmp_path)


def _busy_user(w: World) -> User:
    svc = w.service()
    w.replay_until(svc, decisions=8)
    with w.session() as s:
        user_id = s.scalar(
            select(RiskAssessment.user_id)
            .group_by(RiskAssessment.user_id)
            .order_by(func.count().desc())
            .limit(1)
        )
        user = s.get(User, user_id)
        assert user is not None
        s.expunge(user)
        return user


def _values(document: dict[str, Any]) -> list[Any]:
    out: list[Any] = []
    for rows in document["tables"].values():
        for row in rows:
            out.extend(row.values())
    return out


def _nested_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in _nested_keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in _nested_keys(v)}
    return set()


def test_nested_json_is_redacted() -> None:
    """Stage 12 staging finding: event metadata carried network.ip_hash, address_hash and
    token references past the column allow-list. Nested sensitive keys are now removed."""
    from fraud_ai.privacy.export import _plain

    count = [0]
    metadata = {
        "network": {"ip_hash": "ab" * 32, "asn": 64603, "is_known_vpn": False, "ip": "192.0.2.1"},
        "address_hash": "cd" * 32,
        "payment": {"token_reference": "tok_x", "card_brand": "visa", "fingerprint_hash": "e"},
        "items": [{"api_secret": "s", "sku": "A1"}],
        "device": {"os_family": "iOS"},
    }
    out = _plain(metadata, count)
    assert out == {
        "network": {"asn": 64603, "is_known_vpn": False},
        "payment": {"card_brand": "visa"},
        "items": [{"sku": "A1"}],
        "device": {"os_family": "iOS"},
    }
    assert count == [6]


def test_export_is_scoped_and_allow_listed(w: World) -> None:
    user = _busy_user(w)
    with w.session() as s:
        doc = export_subject(s, user.external_ref)
        others = {str(u) for u in s.scalars(select(User.user_id)) if u != user.user_id}
        own_events = {str(e) for e in s.scalars(select(EventRecord.event_id).where(
            EventRecord.user_id == user.user_id))}  # fmt: skip
        tokens = set(s.scalars(select(PaymentMethod.token_reference)))
    assert doc["found"] and doc["user_id"] == str(user.user_id)
    assert doc["tables"]["users"][0]["external_ref"] == user.external_ref
    assert doc["row_counts"]["events"] == len(own_events)
    assert "risk_assessments" in doc["tables"]
    for table, rows in doc["tables"].items():
        allowed = set(EXPORT[table][0])
        for row in rows:
            assert set(row) <= allowed, table
            assert not set(row) & SECRET_COLUMNS, table
    leaked = {k for k in _nested_keys(doc["tables"]) if k in SECRET_COLUMNS or k.endswith("_hash")}
    assert not leaked, leaked  # nested JSON included (events.metadata, details, values)
    values = {str(v) for v in _values(doc)}
    assert not values & others  # no other user's id anywhere
    assert not values & {t for t in tokens if t}  # no processor tokens
    for row in doc["tables"].get("events", []):
        assert row["event_id"] in own_events
    json.dumps(doc)  # plain JSON
    assert "keyed pseudonym" in json.dumps(doc["excluded"])
    with w.session() as s:
        assert export_subject(s, "nobody")["found"] is False
        assert export_subject(s, str(user.user_id))["user_id"] == str(user.user_id)


def _cli(env: dict[str, str], *args: str) -> Any:
    get_settings.cache_clear()
    try:
        return CliRunner().invoke(cli, list(args), env=env)
    finally:
        get_settings.cache_clear()


def test_export_cli_is_authenticated_audited_and_private(w: World, tmp_path: Path) -> None:
    user = _busy_user(w)
    ops = make_operators(tmp_path / "ops")
    env = {
        "DATABASE_URL": w.url,
        "OPERATOR_AUTH_REQUIRED": "true",
        "OPERATOR_REGISTRY_FILE": str(ops.registry),
    }
    out = tmp_path / "export.json"
    refused = _cli(env, "privacy", "export", user.external_ref, "--out", str(out))
    assert refused.exit_code != 0 and "OPERATOR_AUTH_REQUIRED" in refused.output
    reviewer = _cli({**env, "OPERATOR_ID": "rita"}, "privacy", "export", user.external_ref,
                    "--out", str(out), "--operator-key", str(ops.files["rita"]))  # fmt: skip
    assert reviewer.exit_code != 0 and "FORBIDDEN" in reviewer.output and not out.exists()
    ok = _cli({**env, "OPERATOR_ID": "sec"}, "privacy", "export", user.external_ref,
              "--out", str(out), "--operator-key", str(ops.files["sec"]))  # fmt: skip
    assert ok.exit_code == 0, ok.output
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert json.loads(out.read_text())["user_id"] == str(user.user_id)
    again = _cli({**env, "OPERATOR_ID": "sec"}, "privacy", "export", user.external_ref,
                 "--out", str(out), "--operator-key", str(ops.files["sec"]))  # fmt: skip
    assert again.exit_code != 0 and "refusing to overwrite" in again.output
    with w.session() as s:
        event = audit.list_events(s, action="privacy.exported", limit=1)[0]
    assert event.actor == "operator:sec" and event.target_id == str(user.user_id)
    assert "row_counts" in event.details and user.external_ref not in json.dumps(event.details)
