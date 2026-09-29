"""Stage 11 trust chain.

* ``model_artifact_signatures``: Ed25519 signatures over model artefacts (key id,
  algorithm, signature, the per-file SHA-256 set, who signed and when). Private keys are
  never stored.
* ``policy_approvals``: the two-person approval record (operator, note, policy hash,
  expiry). The same operator cannot approve one policy twice (unique constraint).

Both tables are append-only. Triggers refuse UPDATE and DELETE on PostgreSQL and SQLite,
as for ``audit_events``.

Revision ID: 0009
Revises: 0008
Create Date: 2026-12-01 09:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import fraud_ai.database.base

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APPEND_ONLY = ("model_artifact_signatures", "policy_approvals")

_PG_FUNCTION = """
CREATE OR REPLACE FUNCTION fraud_ai_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql
"""


def _json() -> sa.types.TypeEngine[object]:
    return sa.JSON().with_variant(sa.dialects.postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def _dt() -> fraud_ai.database.base.UTCDateTime:
    return fraud_ai.database.base.UTCDateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "model_artifact_signatures",
        sa.Column("signature_id", sa.Uuid(), nullable=False),
        sa.Column("model_version_id", sa.Uuid(), nullable=False),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("files", _json(), nullable=False),
        sa.Column("key_id", sa.String(length=40), nullable=False),
        sa.Column("algorithm", sa.String(length=16), nullable=False),
        sa.Column("signature", sa.String(length=128), nullable=False),
        sa.Column("signed_at", _dt(), nullable=False),
        sa.Column("signed_by", sa.String(length=200), nullable=False),
        sa.CheckConstraint(
            "algorithm = 'ed25519'", name=op.f("ck_model_artifact_signatures_algorithm_known")
        ),
        sa.ForeignKeyConstraint(
            ["model_version_id"],
            ["model_versions.model_version_id"],
            name=op.f("fk_model_artifact_signatures_model_version_id_model_versions"),
        ),
        sa.PrimaryKeyConstraint("signature_id", name=op.f("pk_model_artifact_signatures")),
    )
    op.create_index(
        "ix_model_artifact_signatures_model",
        "model_artifact_signatures",
        ["model_version_id"],
        unique=False,
    )
    op.create_table(
        "policy_approvals",
        sa.Column("approval_id", sa.Uuid(), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("policy_sha256", sa.String(length=64), nullable=False),
        sa.Column("operator", sa.String(length=120), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=False),
        sa.Column("approved_at", _dt(), nullable=False),
        sa.Column("expires_at", _dt(), nullable=True),
        sa.ForeignKeyConstraint(
            ["policy_version"],
            ["risk_policies.policy_version"],
            name=op.f("fk_policy_approvals_policy_version_risk_policies"),
        ),
        sa.PrimaryKeyConstraint("approval_id", name=op.f("pk_policy_approvals")),
        sa.UniqueConstraint("policy_version", "operator", name="uq_policy_approval_operator"),
    )
    op.create_index(
        "ix_policy_approvals_policy", "policy_approvals", ["policy_version"], unique=False
    )

    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(_PG_FUNCTION)
        for table in APPEND_ONLY:
            op.execute(
                f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
                "FOR EACH ROW EXECUTE FUNCTION fraud_ai_append_only()"
            )
    elif dialect == "sqlite":
        for table in APPEND_ONLY:
            for verb in ("UPDATE", "DELETE"):
                op.execute(
                    f"CREATE TRIGGER {table}_no_{verb.lower()} BEFORE {verb} ON {table} "
                    f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"
                )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    for table in APPEND_ONLY:
        if dialect == "postgresql":
            op.execute(f"DROP TRIGGER IF EXISTS {table}_append_only ON {table}")
        elif dialect == "sqlite":
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_update")
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_delete")
    if dialect == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS fraud_ai_append_only()")
    op.drop_index("ix_policy_approvals_policy", table_name="policy_approvals")
    op.drop_table("policy_approvals")
    op.drop_index("ix_model_artifact_signatures_model", table_name="model_artifact_signatures")
    op.drop_table("model_artifact_signatures")
