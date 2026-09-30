"""Stage 12 external audit anchors: the write-once S3 Object Lock store, scheduled anchoring
(`audit anchor-now`), `audit anchor-status`, and failure tracking.

The S3 logic is tested against an in-memory stand-in with Object Lock semantics (versions,
delete markers, COMPLIANCE retention). ``TEST_ANCHOR_S3_ENDPOINT`` (and ``_ACCESS_KEY``,
``_SECRET_KEY``, ``_BUCKET``) runs the same checks against a real S3 service; staging uses
RustFS. The stand-in proves the *logic*, the real service proves the *immutability*."""

from __future__ import annotations

import io
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from fraud_ai import audit
from fraud_ai.cli.main import cli
from fraud_ai.config.settings import get_settings
from fraud_ai.database.engine import make_session_factory, session_scope
from fraud_ai.trust import keys as tk
from fraud_ai.trust.anchor_s3 import S3Config, S3ObjectLockAnchorStore
from fraud_ai.trust.anchors import (
    create_anchor,
    latest_status,
    verify_anchors,
)


# ------------------------------------------------------------------ an Object Lock stand-in
@dataclass
class _Obj:
    object_name: str
    version_id: str
    data: bytes
    last_modified: datetime
    is_delete_marker: bool = False
    retention: Any = None


class _Denied(Exception):
    code = "AccessDenied"


@dataclass
class FakeLockedS3:
    """What the store relies on: versioning, COMPLIANCE retention, delete markers."""

    versioning: str = "Enabled"
    lock_mode: str | None = "COMPLIANCE"
    honour_retention: bool = True
    objects: list[_Obj] = field(default_factory=list)
    clock: datetime = datetime(2026, 7, 1, tzinfo=UTC)

    def bucket_exists(self, bucket: str) -> bool:
        return True

    def get_bucket_versioning(self, bucket: str) -> Any:
        return type("V", (), {"status": self.versioning})()

    def get_object_lock_config(self, bucket: str) -> Any:
        if self.lock_mode is None:
            from minio.error import S3Error

            raise S3Error(
                None,
                "ObjectLockConfigurationNotFoundError",
                "no lock",
                "",
                "",
                "",  # type: ignore[arg-type]
            )
        return type("L", (), {"mode": self.lock_mode, "duration": 1})()

    def _tick(self) -> datetime:
        self.clock += timedelta(seconds=1)
        return self.clock

    def put_object(self, bucket: str, name: str, data: Any, length: int, **kw: Any) -> Any:
        version = uuid.uuid4().hex
        self.objects.append(
            _Obj(
                name,
                version,
                data.read(),
                self._tick(),
                retention=kw.get("retention") if self.honour_retention else None,
            )
        )
        return type("R", (), {"version_id": version})()

    def list_objects(self, bucket: str, prefix: str = "", **kw: Any) -> list[_Obj]:
        return [o for o in self.objects if o.object_name.startswith(prefix)]

    def _find(self, name: str, version_id: str | None) -> _Obj:
        return next(o for o in self.objects if o.object_name == name and o.version_id == version_id)

    def get_object(self, bucket: str, name: str, version_id: str | None = None) -> Any:
        obj = self._find(name, version_id)

        class Response(io.BytesIO):
            def release_conn(self) -> None:
                pass

        return Response(obj.data)

    def get_object_retention(self, bucket: str, name: str, version_id: str | None = None) -> Any:
        return self._find(name, version_id).retention

    def remove_object(self, bucket: str, name: str, version_id: str | None = None) -> None:
        if version_id is None:  # a delete marker (hides the object from plain listings)
            self.objects.append(_Obj(name, uuid.uuid4().hex, b"", self._tick(), True))
            return
        obj = self._find(name, version_id)
        if obj.retention is not None and obj.retention.mode == "COMPLIANCE":
            raise _Denied("object protected by COMPLIANCE retention")
        self.objects.remove(obj)


# ------------------------------------------------------------------ fixtures
@pytest.fixture
def factory(any_engine: Engine) -> sessionmaker[Session]:
    return make_session_factory(any_engine)


@pytest.fixture(scope="module")
def key() -> tk.KeyPair:
    return tk.generate()


def _store(fake: FakeLockedS3) -> S3ObjectLockAnchorStore:
    config = S3Config("s3.test", "anchors", "fraud-ai/audit-anchors/", "ak", "sk")
    return S3ObjectLockAnchorStore(config, client=fake)


def _events(factory: sessionmaker[Session], n: int) -> None:
    with session_scope(factory) as s:
        for i in range(n):
            audit.record(s, "service_key.created", actor="cli:test", target_type="service_key",
                         target_id=f"k{i}")  # fmt: skip


def _anchor(factory: sessionmaker[Session], store: Any, key: tk.KeyPair) -> Any:
    with factory() as s:
        return create_anchor(s, store, key, actor="job:test")


# ------------------------------------------------------------------ S3 store logic
def test_s3_store_round_trip(factory: sessionmaker[Session], key: tk.KeyPair) -> None:
    fake = FakeLockedS3()
    store = _store(fake)
    _events(factory, 3)
    _, location = _anchor(factory, store, key)
    assert location.startswith(
        "s3://anchors/fraud-ai/audit-anchors/anchor-00000001.json?versionId="
    )
    assert fake.objects[0].retention.mode == "COMPLIANCE"
    _events(factory, 2)
    _anchor(factory, store, key)
    with factory() as s:
        report = verify_anchors(s, store, {key.key_id: key.public})
        assert report.ok and report.anchors == 2, report.problems
        status = latest_status(s)
    assert status is not None and status.anchor_number == 2
    assert status.destination == "s3://anchors/fraud-ai/audit-anchors/"
    assert status.key_id == key.key_id and status.events_since == 0


def test_s3_store_refuses_a_bucket_that_is_not_write_once(
    factory: sessionmaker[Session], key: tk.KeyPair
) -> None:
    _events(factory, 1)
    for fake, message in (
        (FakeLockedS3(versioning="Suspended"), "no versioning"),
        (FakeLockedS3(lock_mode="GOVERNANCE"), "not COMPLIANCE"),
        (FakeLockedS3(lock_mode=None), "not COMPLIANCE"),
    ):
        with pytest.raises(tk.TrustError, match=message):
            _anchor(factory, _store(fake), key)
        # ...and the failure is recorded, never silent.
        with factory() as s:
            failed = audit.list_events(s, action="audit.anchor_failed", limit=1)
            assert failed and message.split()[-1] in failed[0].details["error"]
    # A service that ignores the retention header is caught on read-back.
    with pytest.raises(tk.TrustError, match="did not apply the COMPLIANCE retention"):
        _anchor(factory, _store(FakeLockedS3(honour_retention=False)), key)


def test_s3_overwrite_and_hiding_attempts_are_reported(
    factory: sessionmaker[Session], key: tk.KeyPair
) -> None:
    fake = FakeLockedS3()
    store = _store(fake)
    _events(factory, 2)
    anchor, _ = _anchor(factory, store, key)
    original = fake.objects[0]
    # The locked version cannot be deleted...
    with pytest.raises(_Denied):
        fake.remove_object("anchors", original.object_name, original.version_id)
    # ...but someone with write access uploads a forged "version 2" of the same key,
    # and adds a delete marker. The store still reads the ORIGINAL and reports both.
    forged = json.loads(original.data)
    forged["statement"]["head_sha256"] = "0" * 64
    fake.put_object("anchors", original.object_name, io.BytesIO(json.dumps(forged).encode()), 1)
    fake.remove_object("anchors", original.object_name)
    fake.put_object("anchors", "fraud-ai/audit-anchors/notes.txt", io.BytesIO(b"x"), 1)
    with factory() as s:
        report = verify_anchors(s, store, {key.key_id: key.public})
    problems = " ".join(report.problems)
    assert not report.ok
    assert "2 versions" in problems and "delete marker" in problems
    assert "unexpected object" in problems
    assert "does not verify" not in problems  # the original (signed) anchor was used
    with pytest.raises(tk.TrustError, match="never overwritten"):
        store.append(anchor)


# ------------------------------------------------------------------ CLI: anchor-now, status
def _cli(env: dict[str, str], *args: str) -> Any:
    get_settings.cache_clear()
    try:
        return CliRunner().invoke(cli, list(args), env=env)
    finally:
        get_settings.cache_clear()


def test_anchor_now_and_status(sqlite_url: str, tmp_path: Path, key: tk.KeyPair) -> None:
    key_file = tmp_path / "audit.pem"
    tk.write_private_key(key, key_file)
    env = {
        "DATABASE_URL": sqlite_url,
        "AUDIT_ANCHOR_PUBLIC_KEYS": tk.encode_public(key.public),
        "AUDIT_ANCHOR_DIRECTORY": str(tmp_path / "anchors"),
        "AUDIT_ANCHOR_PRIVATE_KEY_FILE": str(key_file),
    }
    missing = _cli(env, "audit", "anchor-status")
    assert missing.exit_code == 1 and "no anchor" in missing.output
    first = _cli(env, "audit", "anchor-now")
    assert first.exit_code == 0, first.output
    line = json.loads(first.output)
    assert line["status"] == "anchored" and line["anchor_number"] == 1
    assert line["key_id"] == key.key_id and line["destination"].startswith(str(tmp_path))
    assert set(line) >= {"anchored_at", "head_sha256", "sequence"}
    idle = json.loads(_cli(env, "audit", "anchor-now").output)
    assert idle["status"] == "up_to_date" and idle["anchor_number"] == 1
    forced = json.loads(_cli(env, "audit", "anchor-now", "--always").output)
    assert forced["anchor_number"] == 2
    ok = _cli(env, "audit", "anchor-status")
    assert ok.exit_code == 0 and "anchor status OK" in ok.output
    assert "a plain directory is not write-once" in ok.output
    stale = _cli(env, "audit", "anchor-status", "--max-age-minutes", "0.0001")
    assert stale.exit_code == 1 and "min old" in stale.output
    # The anchor recorded in the database is gone from the store: reported.
    for f in (tmp_path / "anchors").glob("anchor-00000002.json"):
        f.unlink()
    gone = _cli(env, "audit", "anchor-status")
    assert gone.exit_code == 1 and "not in the store" in gone.output


# ------------------------------------------------------------------ a real S3 service
S3 = os.environ.get("TEST_ANCHOR_S3_ENDPOINT")


@pytest.mark.skipif(not S3, reason="TEST_ANCHOR_S3_ENDPOINT not set")
def test_real_object_lock_service(factory: sessionmaker[Session], key: tk.KeyPair) -> None:
    from minio.commonconfig import COMPLIANCE
    from minio.retention import Retention

    assert S3
    config = S3Config(
        S3,
        os.environ.get("TEST_ANCHOR_S3_BUCKET", "fraud-ai-anchors-test"),
        f"test-{uuid.uuid4().hex[:8]}/",
        os.environ["TEST_ANCHOR_S3_ACCESS_KEY"],
        os.environ["TEST_ANCHOR_S3_SECRET_KEY"],
        secure=os.environ.get("TEST_ANCHOR_S3_SECURE", "false") == "true",
        retention_days=1,
    )
    store = S3ObjectLockAnchorStore(config)
    state = store.ensure_write_once()
    assert state["versioning"] == "Enabled"
    _events(factory, 2)
    anchor, location = _anchor(factory, store, key)
    client = store.client
    name = store._object_name(anchor.number)
    version = location.split("versionId=")[1]
    # The S3 service itself refuses to delete the locked version or shorten its lock.
    with pytest.raises(Exception, match=r"(?i)retention|denied|lock"):
        client.remove_object(config.bucket, name, version_id=version)
    with pytest.raises(Exception, match=r"(?i)retention|denied|lock"):
        client.set_object_retention(
            config.bucket,
            name,
            Retention(COMPLIANCE, datetime.now(UTC) + timedelta(minutes=1)),
            version_id=version,
        )
    client.remove_object(config.bucket, name)  # a delete marker only
    with factory() as s:
        report = verify_anchors(s, store, {key.key_id: key.public})
    assert report.anchors == 1 and any("delete marker" in p for p in report.problems)
