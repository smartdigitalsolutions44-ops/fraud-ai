"""Stage 11: external audit anchoring (with a deliberate DB-superuser-style rewrite) and the
two-person policy approval rule."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from fraud_ai import audit
from fraud_ai.cli.main import cli
from fraud_ai.database.engine import make_session_factory, session_scope
from fraud_ai.database.models import AuditEvent, PolicyApproval
from fraud_ai.risk.approvals import approve, ensure_approved, status
from fraud_ai.risk.promotion import promote
from fraud_ai.risk.registry import PolicyError, activate, create_policy, load_policy
from fraud_ai.trust import keys as tk
from fraud_ai.trust.anchors import FileAnchorStore, SignedAnchor, create_anchor, verify_anchors
from tests.realtime_world import P1, P2, World, open_world

NOW = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def factory(any_engine: Engine) -> sessionmaker[Session]:
    return make_session_factory(any_engine)


@pytest.fixture(scope="module")
def audit_key() -> tk.KeyPair:
    return tk.generate()


def _events(factory: sessionmaker[Session], n: int, start: int = 0) -> None:
    with session_scope(factory) as s:
        for i in range(start, start + n):
            audit.record(
                s,
                "service_key.created",
                actor="cli:test",
                target_type="service_key",
                target_id=f"fak_{i:016d}",
                details={"name": f"k{i}"},
                now=NOW + timedelta(seconds=i),
            )


def _anchor(factory: sessionmaker[Session], store: FileAnchorStore, key: tk.KeyPair) -> Any:
    with factory() as s:
        return create_anchor(s, store, key, actor="cli:test", now=NOW + timedelta(hours=1))


def _trusted(key: tk.KeyPair) -> dict[str, Any]:
    return {key.key_id: key.public}


def _rewrite_consistently(engine: Engine, sequence: int, details: dict[str, Any]) -> None:
    """What a DB superuser could do: drop the triggers, edit an event, and recompute every
    later hash so the internal chain verifies again."""
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(text("DROP TRIGGER audit_events_immutable ON audit_events"))
        else:
            conn.execute(text("DROP TRIGGER audit_events_no_update"))
    factory = make_session_factory(engine)
    with session_scope(factory) as s:
        previous: str | None = None
        for row in s.scalars(select(AuditEvent).order_by(AuditEvent.sequence)):
            if row.sequence == sequence:
                row.details = details
            if row.sequence >= sequence:
                row.previous_sha256 = previous
                row.event_sha256 = audit._digest(row)
            previous = row.event_sha256


def test_anchor_round_trip_and_growth(
    factory: sessionmaker[Session], tmp_path: Path, audit_key: tk.KeyPair
) -> None:
    store = FileAnchorStore(tmp_path / "anchors")
    _events(factory, 3)
    first, location = _anchor(factory, store, audit_key)
    assert first.number == 1 and first.sequence == 4  # the anchored head is audit.anchored
    assert Path(location).exists()
    _events(factory, 2, start=10)
    with factory() as s:
        report = verify_anchors(s, store, _trusted(audit_key))
    assert report.ok and report.unanchored_events == 2 and report.anchors == 1
    second, _ = _anchor(factory, store, audit_key)
    assert second.statement["previous_anchor_sha256"] == first.sha256()
    with factory() as s:
        report = verify_anchors(s, store, _trusted(audit_key))
        assert report.ok and report.unanchored_events == 0
        assert audit.verify_chain(s).ok


def test_consistent_rewrite_is_caught_by_the_anchor(
    factory: sessionmaker[Session], any_engine: Engine, tmp_path: Path, audit_key: tk.KeyPair
) -> None:
    store = FileAnchorStore(tmp_path / "anchors")
    _events(factory, 4)
    _anchor(factory, store, audit_key)
    _rewrite_consistently(any_engine, 2, {"name": "rewritten-by-dba"})
    with factory() as s:
        assert audit.verify_chain(s).ok  # the internal chain alone is fooled
        report = verify_anchors(s, store, _trusted(audit_key))
    assert not report.ok
    assert any("no longer has the anchored hash" in p for p in report.problems)


def test_truncation_and_anchor_tampering_are_caught(
    factory: sessionmaker[Session], any_engine: Engine, tmp_path: Path, audit_key: tk.KeyPair
) -> None:
    store = FileAnchorStore(tmp_path / "anchors")
    _events(factory, 3)
    _anchor(factory, store, audit_key)
    _anchor(factory, store, audit_key)
    files = sorted((tmp_path / "anchors").glob("anchor-*.json"))
    # A forged statement (sequence changed) no longer matches its signature.
    forged = SignedAnchor.from_json(files[0].read_text())
    forged.statement["head_sha256"] = "0" * 64
    files[0].write_text(forged.to_json())
    with factory() as s:
        report = verify_anchors(s, store, _trusted(audit_key))
    assert any("anchor 1: audit signature does not verify" in p for p in report.problems)
    # Removing an anchor from the middle breaks the anchor chain.
    files[0].unlink()
    with factory() as s:
        report = verify_anchors(s, store, _trusted(audit_key))
    assert any("an anchor is missing" in p for p in report.problems)
    # An anchor signed by another (e.g. the model) key is not trusted.
    model_key = tk.generate()
    with factory() as s:
        assert not verify_anchors(s, store, _trusted(model_key)).ok
    # Truncating the chain (deleting the anchored tail) is detected.
    with any_engine.begin() as conn:
        if any_engine.dialect.name == "postgresql":
            conn.execute(text("DROP TRIGGER audit_events_immutable ON audit_events"))
        else:
            conn.execute(text("DROP TRIGGER audit_events_no_delete"))
        conn.execute(text("DELETE FROM audit_events WHERE sequence > 3"))
    with factory() as s:
        assert audit.verify_chain(s).ok
        report = verify_anchors(s, store, _trusted(audit_key))
    assert any("events were removed" in p for p in report.problems)


def test_anchor_refuses_a_broken_chain_and_overwrites(
    factory: sessionmaker[Session], any_engine: Engine, tmp_path: Path, audit_key: tk.KeyPair
) -> None:
    store = FileAnchorStore(tmp_path / "anchors")
    _events(factory, 2)
    anchor, _ = _anchor(factory, store, audit_key)
    with pytest.raises(tk.TrustError, match="never overwritten"):
        store.append(anchor)
    with any_engine.begin() as conn:
        if any_engine.dialect.name == "postgresql":
            conn.execute(text("DROP TRIGGER audit_events_immutable ON audit_events"))
        else:
            conn.execute(text("DROP TRIGGER audit_events_no_update"))
        conn.execute(text("UPDATE audit_events SET actor = 'x' WHERE sequence = 1"))
    with pytest.raises(tk.TrustError, match="broken chain"):
        _anchor(factory, store, audit_key)
    with pytest.raises(tk.TrustError, match="not in AUDIT_ANCHOR_PUBLIC_KEYS"), factory() as s:
        create_anchor(s, store, audit_key, actor="t", trusted=_trusted(tk.generate()))


def test_anchor_cli(sqlite_url: str, tmp_path: Path) -> None:
    key = tmp_path / "audit.pem"
    runner = CliRunner()
    from fraud_ai.config.settings import get_settings

    def run(env: dict[str, str], *args: str) -> Any:
        get_settings.cache_clear()
        try:
            return runner.invoke(cli, list(args), env=env, catch_exceptions=False)
        finally:
            get_settings.cache_clear()

    out = run({}, "keys", "generate", "--purpose", "audit", "--out", str(key))
    public = next(line.split()[-1] for line in out.output.splitlines() if "public key" in line)
    env = {
        "DATABASE_URL": sqlite_url,
        "AUDIT_ANCHOR_PUBLIC_KEYS": public,
        "AUDIT_ANCHOR_DIRECTORY": str(tmp_path / "anchors"),
        "AUDIT_ANCHOR_PRIVATE_KEY_FILE": str(key),
    }
    made = run(env, "audit", "anchor")
    assert made.exit_code == 0 and "anchor 1" in made.output, made.output
    ok = run(env, "audit", "verify-anchor")
    assert ok.exit_code == 0 and "anchors OK" in ok.output
    no_keys = run({k: v for k, v in env.items() if k != "AUDIT_ANCHOR_PUBLIC_KEYS"},
                  "audit", "verify-anchor")  # fmt: skip
    assert no_keys.exit_code != 0


# ------------------------------------------------------------------ two-person approval
@pytest.fixture
def w(realtime_world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(realtime_world_dir, tmp_path)


def _candidate(w: World) -> None:
    with session_scope(w.factory) as s:
        promote(s, P2, "shadow", actor="cli:a", note="shadowed")
        promote(s, P2, "evaluation", actor="cli:a", note="simulated",
                evidence={"simulation": {"events": 1}})  # fmt: skip
        promote(s, P2, "candidate", actor="cli:a", note="ok", approved=True)


def test_two_person_rule(w: World) -> None:
    with session_scope(w.factory) as s, pytest.raises(PolicyError, match="only a promoted"):
        approve(s, P2, operator="alice", note="n", ttl_hours=72, now=NOW)
    _candidate(w)
    with session_scope(w.factory) as s:
        with pytest.raises(PolicyError, match="needs 2 approvals"):
            activate(s, P2, approvals_required=2, now=NOW)
        with pytest.raises(PolicyError, match="operator identity"):
            approve(s, P2, operator=None, note="n", ttl_hours=72, now=NOW)
        approve(s, P2, operator="alice", note="reviewed simulation", ttl_hours=72, now=NOW)
    with session_scope(w.factory) as s:
        with pytest.raises(PolicyError, match="already approved"):
            approve(s, P2, operator="alice", note="again", ttl_hours=72, now=NOW)
        with pytest.raises(PolicyError, match="1 valid"):
            activate(s, P2, approvals_required=2, now=NOW)
        with pytest.raises(PolicyError, match="ALLOWLIST"):
            approve(s, P2, operator="mallory", note="n", ttl_hours=72, allowed={"bob"}, now=NOW)
        approve(s, P2, operator="bob", note="second pair of eyes", ttl_hours=72, now=NOW)
    with session_scope(w.factory) as s:
        state = ensure_approved(s, P2, required=2, now=NOW)
        assert state.valid_operators == ("alice", "bob")
        deployment = activate(s, P2, approvals_required=2, now=NOW, activated_by="operator:bob")
        assert deployment.policy_version == P2
        actions = [e.action for e in audit.list_events(s, limit=20)]
        assert actions.count("policy.approved") == 2
    # The database refuses a duplicate even if the code check were bypassed.
    with pytest.raises(Exception), session_scope(w.factory) as s:  # noqa: B017
        s.add(PolicyApproval(policy_version=P2, policy_sha256="0" * 64, operator="alice",
                             note="dup", approved_at=NOW))  # fmt: skip
        s.flush()


def test_approvals_expire(w: World) -> None:
    _candidate(w)
    with session_scope(w.factory) as s:
        approve(s, P2, operator="alice", note="a", ttl_hours=24, now=NOW)
        approve(s, P2, operator="bob", note="b", ttl_hours=24, now=NOW + timedelta(hours=20))
    with w.factory() as s:
        assert status(s, P2, required=2, now=NOW + timedelta(hours=23)).satisfied
        late = status(s, P2, required=2, now=NOW + timedelta(hours=25))
        assert not late.satisfied and late.expired == ("alice",)
        with pytest.raises(PolicyError, match="expired: alice"):
            ensure_approved(s, P2, required=2, now=NOW + timedelta(hours=25))


def test_approval_is_pinned_to_the_definition(w: World) -> None:
    _candidate(w)
    with session_scope(w.factory) as s:
        approve(s, P2, operator="alice", note="a", ttl_hours=0, now=NOW)
        approve(s, P2, operator="bob", note="b", ttl_hours=0, now=NOW)
    with w.factory() as s:
        assert status(s, P2, required=2, now=NOW + timedelta(days=365)).satisfied  # no TTL
    # A different (new) policy version does not inherit approvals.
    with session_scope(w.factory) as s:
        new = load_policy(s, P1).model_copy(update={"policy_version": "risk-policy-1.2.0"})
        create_policy(s, new)
        assert not status(s, "risk-policy-1.2.0", required=2, now=NOW).satisfied
