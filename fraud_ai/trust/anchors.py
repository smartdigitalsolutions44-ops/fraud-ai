"""External anchoring of the audit chain (Stage 11).

The hash chain in ``audit_events`` detects edits by anyone who does not also rewrite every
later hash. A database superuser *can* rewrite the whole chain consistently (drop the
triggers, edit, recompute). An anchor defeats that: it records the chain head (**sequence**
and **event hash**) **outside the database**, signed with a dedicated Ed25519 audit key
that the database never sees.

**Anchor statement** (purpose ``audit``)::

    {"chain": "fraud-ai-audit", "sequence": N, "head_sha256": <event N hash>,
     "events": N, "anchored_at": <ISO time>, "anchor_number": k,
     "previous_anchor_sha256": <SHA-256 of anchor k-1's canonical JSON, or null>}

The anchors are themselves chained, so removing one from the middle of the store is
detected.

**Store.** :class:`AuditAnchorProvider` is the interface. :class:`FileAnchorStore` is the
bundled implementation: one JSON file per anchor, created with ``O_EXCL`` (never
overwritten) in a directory the database host should not be able to write. Point it at
write-once storage (object lock / WORM bucket, a separate host, or a mounted append-only
volume) for real protection. A local directory on the same host as the database is only
as strong as that host.

**Verification** (:func:`verify_anchors`) checks:

1. the database chain itself (:func:`fraud_ai.audit.verify_chain`);
2. every anchor's signature, against ``AUDIT_ANCHOR_PUBLIC_KEYS``;
3. the anchor chain (numbering and previous-anchor hashes);
4. **position:** the database event at each anchored sequence still has the anchored hash
   (a consistent rewrite changes it);
5. **no missing section:** the database still reaches every anchored sequence (truncation
   is detected).

What an anchor does **not** cover: events after the latest anchor, and anchors deleted from
the *end* of the store by someone with write access to it. Anchor often, and keep the store
out of the database administrator's reach.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai import audit
from fraud_ai.database.models import AuditEvent
from fraud_ai.trust import keys as tk
from fraud_ai.trust.keys import Signature, Signer, TrustError

PURPOSE = "audit"
CHAIN = "fraud-ai-audit"


@dataclass(frozen=True)
class SignedAnchor:
    statement: dict[str, Any]
    signature: Signature

    @property
    def number(self) -> int:
        return int(self.statement["anchor_number"])

    @property
    def sequence(self) -> int:
        return int(self.statement["sequence"])

    def sha256(self) -> str:
        return hashlib.sha256(tk.canonical_json(self.statement)).hexdigest()

    def to_json(self) -> str:
        return json.dumps(
            {"statement": self.statement, "signature": self.signature.to_dict()},
            indent=2,
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text: str) -> SignedAnchor:
        try:
            data = json.loads(text)
            return cls(dict(data["statement"]), Signature.from_dict(data["signature"]))
        except (ValueError, KeyError, TypeError):
            raise TrustError("malformed anchor file") from None


class AuditAnchorProvider(Protocol):
    """Where anchors live: somewhere the database administrator cannot rewrite.

    Implementations: :class:`FileAnchorStore` (a directory) and
    :class:`fraud_ai.trust.anchor_s3.S3ObjectLockAnchorStore` (write-once Object Lock)."""

    def append(self, anchor: SignedAnchor) -> str: ...

    def anchors(self) -> list[SignedAnchor]: ...

    def describe(self) -> str: ...

    def integrity_problems(self) -> list[str]: ...


class FileAnchorStore:
    """One create-only JSON file per anchor (``anchor-<number>.json``)."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def describe(self) -> str:
        return f"file://{self.directory.resolve()}"

    def integrity_problems(self) -> list[str]:
        # A plain directory cannot tell whether a file was replaced; only the signatures
        # and the anchor chain can. Stated, not hidden: see `audit anchor-status`.
        return []

    def append(self, anchor: SignedAnchor) -> str:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"anchor-{anchor.number:08d}.json"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            raise TrustError(f"{path} already exists; anchors are never overwritten") from None
        with os.fdopen(fd, "w") as handle:
            handle.write(anchor.to_json() + "\n")
        return str(path)

    def anchors(self) -> list[SignedAnchor]:
        if not self.directory.exists():
            return []
        return [
            SignedAnchor.from_json(p.read_text())
            for p in sorted(self.directory.glob("anchor-*.json"))
        ]


def create_anchor(
    session: Session,
    store: AuditAnchorProvider,
    pair: Signer,
    *,
    actor: str,
    trusted: dict[str, Ed25519PublicKey] | None = None,
    now: datetime | None = None,
) -> tuple[SignedAnchor, str]:
    """Record ``audit.anchored``, commit, then anchor the head (which is that very event).

    Commits the session: the anchor must never reference an uncommitted event."""
    if trusted is not None and pair.key_id not in trusted:
        raise TrustError(f"key {pair.key_id} is not in AUDIT_ANCHOR_PUBLIC_KEYS")
    report = audit.verify_chain(session)
    if not report.ok:
        raise TrustError(
            f"refusing to anchor a broken chain (sequence {report.first_bad_sequence}: "
            f"{report.reason})"
        )
    existing = store.anchors()
    previous = existing[-1] if existing else None
    now = now or datetime.now(UTC)
    head = audit.record(
        session,
        "audit.anchored",
        actor=actor,
        target_type="audit",
        details={
            "anchor_number": (previous.number + 1) if previous else 1,
            "key_id": pair.key_id,
            "destination": store.describe(),
        },
        now=now,
    )
    statement = {
        "chain": CHAIN,
        "sequence": head.sequence,
        "head_sha256": head.event_sha256,
        "events": head.sequence,
        "anchored_at": now.astimezone(UTC).isoformat(timespec="seconds"),
        "anchor_number": (previous.number + 1) if previous else 1,
        "previous_anchor_sha256": previous.sha256() if previous else None,
    }
    anchor = SignedAnchor(statement, tk.sign(PURPOSE, pair, statement))
    # The anchored event must exist before anything outside the database points at it.
    session.commit()
    try:
        location = store.append(anchor)
    except TrustError as exc:
        # Recorded, so `anchor-status` and the audit log show the gap (never silent).
        audit.record(
            session,
            "audit.anchor_failed",
            actor=actor,
            target_type="audit",
            details={
                "anchor_number": anchor.number,
                "destination": store.describe(),
                "error": str(exc)[:200],
            },
        )
        session.commit()
        raise
    return anchor, location


@dataclass
class AnchorReport:
    ok: bool
    chain_events: int
    anchors: int
    latest_anchored_sequence: int | None
    problems: list[str] = field(default_factory=list)
    unanchored_events: int = 0


def verify_anchors(
    session: Session, store: AuditAnchorProvider, trusted: dict[str, Ed25519PublicKey]
) -> AnchorReport:
    chain = audit.verify_chain(session)
    problems: list[str] = []
    if not chain.ok:
        problems.append(
            f"database chain broken at sequence {chain.first_bad_sequence}: {chain.reason}"
        )
    try:
        anchors = store.anchors()
    except TrustError as exc:
        return AnchorReport(False, chain.events, 0, None, [str(exc)])
    problems.extend(f"store: {p}" for p in store.integrity_problems())
    if not anchors:
        problems.append("no anchors found")
    hashes = {
        row.sequence: row.event_sha256
        for row in session.scalars(select(AuditEvent).order_by(AuditEvent.sequence))
    }
    top = max(hashes, default=0)
    previous: SignedAnchor | None = None
    for anchor in anchors:
        label = f"anchor {anchor.statement.get('anchor_number')}"
        try:
            tk.verify(PURPOSE, trusted, anchor.statement, anchor.signature)
        except TrustError as exc:
            problems.append(f"{label}: {exc}")
            previous = anchor
            continue
        expected_number = (previous.number + 1) if previous else 1
        if anchor.number != expected_number:
            problems.append(f"{label}: expected anchor {expected_number} (an anchor is missing)")
        expected_link = previous.sha256() if previous else None
        if anchor.statement.get("previous_anchor_sha256") != expected_link:
            problems.append(f"{label}: does not link to the previous anchor")
        if anchor.statement.get("chain") != CHAIN:
            problems.append(f"{label}: not an anchor of this audit chain")
        seq = anchor.sequence
        if seq > top:
            problems.append(
                f"{label}: the database chain ends at {top} but sequence {seq} was anchored "
                "(events were removed)"
            )
        elif hashes.get(seq) != anchor.statement.get("head_sha256"):
            problems.append(
                f"{label}: event {seq} no longer has the anchored hash (history was rewritten)"
            )
        previous = anchor
    latest = anchors[-1].sequence if anchors else None
    return AnchorReport(
        ok=not problems,
        chain_events=chain.events,
        anchors=len(anchors),
        latest_anchored_sequence=latest,
        problems=problems,
        unanchored_events=max(0, top - (latest or 0)),
    )


def store_from_settings(settings: Any, directory: Path | None = None) -> AuditAnchorProvider:
    """The configured anchor store (``--store`` overrides with a directory)."""
    if directory is not None:
        return FileAnchorStore(directory)
    kind = settings.effective_anchor_store
    if kind == "file":
        return FileAnchorStore(settings.audit_anchor_directory)
    if kind == "s3":
        from fraud_ai.trust.anchor_s3 import S3Config, S3ObjectLockAnchorStore

        if not settings.anchor_s3_access_key or settings.anchor_s3_secret_key is None:
            raise TrustError(
                "the S3 anchor store needs ANCHOR_S3_ACCESS_KEY and ANCHOR_S3_SECRET_KEY(_FILE)"
            )
        return S3ObjectLockAnchorStore(
            S3Config(
                endpoint=settings.anchor_s3_endpoint,
                bucket=settings.anchor_s3_bucket,
                prefix=settings.anchor_s3_prefix,
                access_key=settings.anchor_s3_access_key,
                secret_key=settings.anchor_s3_secret_key.get_secret_value(),
                region=settings.anchor_s3_region,
                secure=settings.anchor_s3_secure,
                ca_file=settings.anchor_s3_ca_file,
                retention_days=settings.anchor_retention_days,
            )
        )
    raise TrustError("no anchor store: set AUDIT_ANCHOR_STORE (file or s3) or give --store")


@dataclass(frozen=True)
class AnchorStatus:
    """The newest ``audit.anchored`` event: what `audit anchor-status` reports."""

    anchor_number: int
    sequence: int
    head_sha256: str
    key_id: str
    destination: str | None
    anchored_at: datetime
    events_since: int

    def age_minutes(self, now: datetime | None = None) -> float:
        at = self.anchored_at if self.anchored_at.tzinfo else self.anchored_at.replace(tzinfo=UTC)
        return ((now or datetime.now(UTC)) - at).total_seconds() / 60.0


def latest_status(session: Session) -> AnchorStatus | None:
    row = session.scalar(
        select(AuditEvent)
        .where(AuditEvent.action == "audit.anchored")
        .order_by(AuditEvent.sequence.desc())
        .limit(1)
    )
    if row is None:
        return None
    top = session.scalar(select(AuditEvent.sequence).order_by(AuditEvent.sequence.desc()).limit(1))
    details = row.details or {}
    return AnchorStatus(
        anchor_number=int(details.get("anchor_number", 0)),
        sequence=row.sequence,
        head_sha256=row.event_sha256,
        key_id=str(details.get("key_id", "")),
        destination=details.get("destination"),
        anchored_at=row.occurred_at,
        events_since=max(0, int(top or 0) - row.sequence),
    )
