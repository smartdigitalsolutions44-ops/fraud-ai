"""Audit restore/tamper drill (Stage 12), run against a RESTORED CLONE of the database.

Played by ``deploy/staging/stack.sh drill``:

1. an anchor is created on the live system (``audit anchor-now``);
2. the database is dumped by the ``fraud_backup`` role and restored into a clone;
3. **this script**, as a database superuser on the clone, plays the attacker: it drops the
   append-only trigger, edits an old audit event and recomputes every later hash, so the
   clone's internal chain is consistent again;
4. it verifies the clone's internal chain, which is fooled (OK);
5. it verifies the clone against the external write-once anchors, which detect the
   rewrite (MISMATCH).

Exit code 0 means the drill succeeded: the rewrite was detected. Never point this at the
real database: it refuses unless the target database name contains ``clone``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import select, text
from sqlalchemy.engine import make_url

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fraud_ai import audit
from fraud_ai.config.settings import get_settings
from fraud_ai.database.engine import (
    create_db_engine,
    make_session_factory,
    session_scope,
)
from fraud_ai.database.models import AuditEvent
from fraud_ai.trust.anchors import store_from_settings, verify_anchors
from fraud_ai.trust.keys import parse_public_keys


def rewrite(url: str, sequence: int) -> dict[str, object]:
    engine = create_db_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events"))
    factory = make_session_factory(engine)
    with session_scope(factory) as s:
        previous: str | None = None
        edited: dict[str, object] = {}
        for row in s.scalars(select(AuditEvent).order_by(AuditEvent.sequence)):
            if row.sequence == sequence:
                edited = {"action": row.action, "before": row.details}
                row.details = {"rewritten": "by a database superuser in the drill"}
            if row.sequence >= sequence:
                row.previous_sha256 = previous
                row.event_sha256 = audit._digest(row)
            previous = row.event_sha256
    engine.dispose()
    return edited


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--admin-url-file", type=Path, required=True)
    parser.add_argument("--clone", required=True, help="the restored clone database name")
    parser.add_argument("--sequence", type=int, default=2, help="the event to rewrite")
    args = parser.parse_args()
    if "clone" not in args.clone:
        sys.exit("refusing: the target database name must contain 'clone'")
    url = make_url(args.admin_url_file.read_text().strip()).set(database=args.clone)
    clone_url = url.render_as_string(hide_password=False)
    edited = rewrite(clone_url, args.sequence)
    settings = get_settings()
    engine = create_db_engine(clone_url)
    with make_session_factory(engine)() as s:
        chain = audit.verify_chain(s)
        report = verify_anchors(
            s, store_from_settings(settings), parse_public_keys(settings.audit_anchor_public_keys)
        )
    engine.dispose()
    result = {
        "clone": args.clone,
        "rewritten_event": args.sequence,
        "rewritten_action": edited.get("action"),
        "internal_chain_ok": chain.ok,
        "anchor_verification_ok": report.ok,
        "anchor_problems": report.problems,
        "detected": chain.ok and not report.ok,
    }
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["detected"] else 1)


if __name__ == "__main__":
    main()
