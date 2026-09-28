"""Stage 10 deployment hardening.

* ``service_api_keys``: ``expires_at``, ``last_used_at`` and ``rotated_from_key_id``
  (key expiry and rotation lineage).
* ``policy_deployments.activated_by``: who or what initiated an activation.
* ``audit_events``: an append-only, hash-chained log of administrative actions. Triggers
  refuse UPDATE and DELETE on both PostgreSQL and SQLite.
* ``policy_lifecycle_events``: append-only policy promotion history.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-01 09:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import fraud_ai.database.base

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json() -> sa.types.TypeEngine[object]:
    return sa.JSON().with_variant(sa.dialects.postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def _dt() -> fraud_ai.database.base.UTCDateTime:
    return fraud_ai.database.base.UTCDateTime(timezone=True)


_PG_FUNCTION = """
CREATE OR REPLACE FUNCTION fraud_ai_audit_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql
"""


def upgrade() -> None:
    with op.batch_alter_table("service_api_keys") as batch:
        batch.add_column(sa.Column("expires_at", _dt(), nullable=True))
        batch.add_column(sa.Column("last_used_at", _dt(), nullable=True))
        batch.add_column(sa.Column("rotated_from_key_id", sa.String(length=40), nullable=True))
    with op.batch_alter_table("policy_deployments") as batch:
        batch.add_column(sa.Column("activated_by", sa.String(length=200), nullable=True))

    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("occurred_at", _dt(), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=40), nullable=False),
        sa.Column("target_id", sa.String(length=120), nullable=True),
        sa.Column("details", _json(), nullable=False),
        sa.Column("previous_sha256", sa.String(length=64), nullable=True),
        sa.Column("event_sha256", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "length(event_sha256) = 64", name=op.f("ck_audit_events_event_sha256_length")
        ),
        sa.PrimaryKeyConstraint("event_id", name=op.f("pk_audit_events")),
        sa.UniqueConstraint("sequence", name=op.f("uq_audit_events_sequence")),
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"], unique=False)

    op.create_table(
        "policy_lifecycle_events",
        sa.Column("lifecycle_id", sa.Uuid(), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("stage", sa.String(length=16), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("evidence", _json(), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("created_at", _dt(), nullable=False),
        sa.CheckConstraint(
            "stage IN ('shadow', 'evaluation', 'candidate', 'rejected')",
            name=op.f("ck_policy_lifecycle_events_stage_known"),
        ),
        sa.ForeignKeyConstraint(
            ["policy_version"],
            ["risk_policies.policy_version"],
            name=op.f("fk_policy_lifecycle_events_policy_version_risk_policies"),
        ),
        sa.PrimaryKeyConstraint("lifecycle_id", name=op.f("pk_policy_lifecycle_events")),
    )
    op.create_index(
        "ix_policy_lifecycle_policy", "policy_lifecycle_events", ["policy_version"], unique=False
    )

    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(_PG_FUNCTION)
        op.execute(
            "CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events "
            "FOR EACH ROW EXECUTE FUNCTION fraud_ai_audit_immutable()"
        )
    elif dialect == "sqlite":
        for verb in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER audit_events_no_{verb.lower()} BEFORE {verb} ON audit_events "
                "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END"
            )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events")
        op.execute("DROP FUNCTION IF EXISTS fraud_ai_audit_immutable()")
    elif dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_delete")
    op.drop_index("ix_policy_lifecycle_policy", table_name="policy_lifecycle_events")
    op.drop_table("policy_lifecycle_events")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_table("audit_events")
    with op.batch_alter_table("policy_deployments") as batch:
        batch.drop_column("activated_by")
    with op.batch_alter_table("service_api_keys") as batch:
        batch.drop_column("rotated_from_key_id")
        batch.drop_column("last_used_at")
        batch.drop_column("expires_at")
