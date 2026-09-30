"""Write-once audit-anchor storage on S3-compatible Object Lock (Stage 12).

:class:`S3ObjectLockAnchorStore` keeps one object per anchor in a bucket that has
**versioning** and **Object Lock in COMPLIANCE mode**. Every anchor is written with a
COMPLIANCE retention date. Until that date the S3 service refuses, for *every* credential
including the root account, to:

* delete the object version;
* shorten its retention or switch it to GOVERNANCE mode.

The store refuses to work with a bucket that lacks versioning or COMPLIANCE Object Lock.
It will not pretend a plain bucket is write-once.

What the application can still do, and how it is caught:

* **Upload another version of an anchor key.** Versioning keeps the original locked version.
  :meth:`anchors` always reads the **oldest** version and reports every extra version as a
  tamper signal.
* **Add a delete marker** (hides the object from a plain listing). Anchors are read from
  the version listing, so the locked version is still found. The marker is reported.

What it does **not** protect against (documented in TRUST_CHAIN.md):

* someone with administrative access to the *storage system itself* (the disks, or the
  object-store host). They can remove data underneath the S3 API. Real WORM needs the
  bucket under separate administrative control, for example AWS S3 Object Lock in a
  separate account, or an operator-run appliance;
* anchors never written: events after the newest anchor are unanchored until the next run.

Works with AWS S3 and S3-compatible services that implement Object Lock (staging: RustFS).
Uses the ``minio`` SDK (optional dependency ``fraud-ai[anchors]``).
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fraud_ai.trust.anchors import SignedAnchor
from fraud_ai.trust.keys import TrustError

_KEY = re.compile(r"anchor-(\d{8})\.json$")
MAX_ANCHOR_BYTES = 64 * 1024


@dataclass(frozen=True)
class S3Config:
    endpoint: str
    bucket: str
    prefix: str
    access_key: str
    secret_key: str
    region: str | None = None
    secure: bool = True
    ca_file: Path | None = None
    retention_days: int = 400
    timeout: float = 10.0


@dataclass
class _Version:
    key: str
    version_id: str | None
    is_delete_marker: bool
    last_modified: datetime | None


@dataclass
class S3ObjectLockAnchorStore:
    config: S3Config
    client: Any = None
    _problems: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.client is None:
            self.client = _client(self.config)
        if self.config.prefix and not self.config.prefix.endswith("/"):
            raise TrustError("ANCHOR_S3_PREFIX must end with '/'")

    # ------------------------------------------------------------------ description
    def describe(self) -> str:
        return f"s3://{self.config.bucket}/{self.config.prefix}"

    def _object_name(self, number: int) -> str:
        return f"{self.config.prefix}anchor-{number:08d}.json"

    # ------------------------------------------------------------------ bucket checks
    def lock_state(self) -> dict[str, Any]:
        """Versioning and Object Lock configuration, as the S3 service reports it."""
        from minio.error import S3Error

        c, bucket = self.client, self.config.bucket
        try:
            if not c.bucket_exists(bucket):
                raise TrustError(f"anchor bucket {bucket!r} does not exist")
            versioning = c.get_bucket_versioning(bucket).status
            try:
                lock = c.get_object_lock_config(bucket)
                mode = lock.mode
                duration = lock.duration
            except ValueError:  # Object Lock enabled, but no default retention rule
                mode, duration = "ENABLED_NO_DEFAULT", None
            except S3Error as exc:
                if exc.code != "ObjectLockConfigurationNotFoundError":
                    raise
                mode, duration = None, None
        except S3Error as exc:
            raise TrustError(f"cannot read the anchor bucket configuration: {exc.code}") from None
        except OSError as exc:
            raise TrustError(f"the anchor store is unreachable: {exc}") from None
        return {"bucket": bucket, "versioning": versioning, "lock_mode": mode, "default": duration}

    def ensure_write_once(self) -> dict[str, Any]:
        state = self.lock_state()
        if state["versioning"] != "Enabled":
            raise TrustError(
                f"anchor bucket {state['bucket']!r} has no versioning; it is not write-once"
            )
        if state["lock_mode"] not in ("COMPLIANCE", "ENABLED_NO_DEFAULT"):
            raise TrustError(
                f"anchor bucket {state['bucket']!r} Object Lock is {state['lock_mode']!r}, not "
                "COMPLIANCE; refusing to treat it as write-once"
            )
        return state

    # ------------------------------------------------------------------ versions
    def _versions(self) -> list[_Version]:
        from minio.error import S3Error

        try:
            objects = self.client.list_objects(
                self.config.bucket, prefix=self.config.prefix, recursive=True, include_version=True
            )
            return [
                _Version(o.object_name, o.version_id, bool(o.is_delete_marker), o.last_modified)
                for o in objects
            ]
        except S3Error as exc:
            raise TrustError(f"cannot list anchors: {exc.code}") from None
        except OSError as exc:
            raise TrustError(f"the anchor store is unreachable: {exc}") from None

    def _read(self, key: str, version_id: str | None) -> bytes:
        response = self.client.get_object(self.config.bucket, key, version_id=version_id)
        try:
            data = response.read(MAX_ANCHOR_BYTES + 1)
        finally:
            response.close()
            response.release_conn()
        if len(data) > MAX_ANCHOR_BYTES:
            raise TrustError(f"{key} is too large to be an anchor")
        return bytes(data)

    def _retention(self, key: str, version_id: str | None) -> tuple[str | None, datetime | None]:
        from minio.error import S3Error

        try:
            retention = self.client.get_object_retention(
                self.config.bucket, key, version_id=version_id
            )
        except S3Error:
            return None, None
        if retention is None:
            return None, None
        return retention.mode, retention.retain_until_date

    # ------------------------------------------------------------------ store API
    def append(self, anchor: SignedAnchor) -> str:
        from minio.commonconfig import COMPLIANCE
        from minio.error import S3Error
        from minio.retention import Retention

        self.ensure_write_once()
        key = self._object_name(anchor.number)
        if any(v.key == key for v in self._versions()):
            raise TrustError(f"{key} already exists; anchors are never overwritten")
        body = (anchor.to_json() + "\n").encode()
        until = datetime.now(UTC) + timedelta(days=self.config.retention_days)
        try:
            result = self.client.put_object(
                self.config.bucket,
                key,
                io.BytesIO(body),
                len(body),
                content_type="application/json",
                retention=Retention(COMPLIANCE, until),
            )
        except S3Error as exc:
            raise TrustError(f"writing the anchor failed: {exc.code}") from None
        version = result.version_id
        # Read back: the object must exist, be identical and carry the COMPLIANCE lock.
        if self._read(key, version) != body:
            raise TrustError(f"{key}: the stored anchor differs from what was written")
        mode, retain_until = self._retention(key, version)
        if (
            mode != "COMPLIANCE"
            or retain_until is None
            or retain_until < until - timedelta(minutes=5)
        ):
            raise TrustError(
                f"{key}: the S3 service did not apply the COMPLIANCE retention (got {mode})"
            )
        return f"s3://{self.config.bucket}/{key}?versionId={version}"

    def anchors(self) -> list[SignedAnchor]:
        """Every anchor, from its **oldest** stored version. Extra versions, delete markers,
        missing locks and stray objects are collected in :meth:`integrity_problems`."""
        self._problems = []
        by_key: dict[str, list[_Version]] = {}
        for version in self._versions():
            by_key.setdefault(version.key, []).append(version)
        out: list[SignedAnchor] = []
        for key in sorted(by_key):
            versions = by_key[key]
            match = _KEY.search(key)
            if match is None:
                self._problems.append(f"unexpected object {key} in the anchor store")
                continue
            data_versions = [v for v in versions if not v.is_delete_marker]
            markers = len(versions) - len(data_versions)
            if markers:
                self._problems.append(f"{key}: {markers} delete marker(s) (a deletion attempt)")
            if not data_versions:
                self._problems.append(f"{key}: no stored version (only delete markers)")
                continue
            if len(data_versions) > 1:
                self._problems.append(
                    f"{key}: {len(data_versions)} versions; the oldest (original) one is used "
                    "(an overwrite attempt)"
                )
            oldest = min(
                data_versions, key=lambda v: v.last_modified or datetime.max.replace(tzinfo=UTC)
            )
            mode, _ = self._retention(key, oldest.version_id)
            if mode != "COMPLIANCE":
                self._problems.append(f"{key}: not under COMPLIANCE retention ({mode})")
            anchor = SignedAnchor.from_json(self._read(key, oldest.version_id).decode())
            if anchor.number != int(match.group(1)):
                self._problems.append(f"{key}: holds anchor {anchor.number}")
            out.append(anchor)
        return sorted(out, key=lambda a: a.number)

    def integrity_problems(self) -> list[str]:
        problems = list(self._problems)
        try:
            self.ensure_write_once()
        except TrustError as exc:
            problems.append(str(exc))
        return problems


def _client(config: S3Config) -> Any:
    try:
        import urllib3
        from minio import Minio
    except ImportError:  # pragma: no cover - optional dependency
        raise TrustError(
            "the S3 anchor store needs the 'anchors' extra: pip install 'fraud-ai[anchors]'"
        ) from None
    http = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=config.timeout, read=config.timeout),
        retries=urllib3.Retry(total=2, backoff_factor=0.2, status_forcelist=(502, 503, 504)),
        cert_reqs="CERT_REQUIRED" if config.secure else "CERT_NONE",
        ca_certs=str(config.ca_file) if config.ca_file else None,
    )
    return Minio(
        config.endpoint,
        access_key=config.access_key,
        secret_key=config.secret_key,
        region=config.region,
        secure=config.secure,
        http_client=http,
    )
