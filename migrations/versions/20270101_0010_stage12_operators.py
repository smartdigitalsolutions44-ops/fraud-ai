"""Stage 12 operator authentication.

* ``operator_assertions``: consumed operator assertions (single use by ``jti``): operator,
  key id, action, target, validity and the token's SHA-256 (never the token). Append-only.
* ``policy_approvals``: ``operator_key_id``, ``assertion_jti`` (unique) and ``assertion``,
  the consumed, action-bound assertion that activation re-verifies.
* ``review_outcomes.reviewer``: who resolved the review (an authenticated operator, an API
  key or a CLI user).

Revision ID: 0010
Revises: 0009
Create Date: 2027-01-01 09:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import fraud_ai.database.base

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _dt() -> fraud_ai.database.base.UTCDateTime:
    return fraud_ai.database.base.UTCDateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "operator_assertions",
        sa.Column("assertion_id", sa.Uuid(), nullable=False),
        sa.Column("jti", sa.String(length=64), nullable=False),
        sa.Column("operator_id", sa.String(length=64), nullable=False),
        sa.Column("key_id", sa.String(length=40), nullable=False),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("target", sa.String(length=200), nullable=False),
        sa.Column("issued_at", _dt(), nullable=False),
        sa.Column("expires_at", _dt(), nullable=False),
        sa.Column("used_at", _dt(), nullable=False),
        sa.Column("token_sha256", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("assertion_id", name=op.f("pk_operator_assertions")),
        sa.UniqueConstraint("jti", name="uq_operator_assertions_jti"),
    )
    op.create_index(
        "ix_operator_assertions_operator", "operator_assertions", ["operator_id"], unique=False
    )
    op.add_column("policy_approvals", sa.Column("operator_key_id", sa.String(length=40)))
    op.add_column("policy_approvals", sa.Column("assertion_jti", sa.String(length=64)))
    op.add_column("policy_approvals", sa.Column("assertion", sa.Text()))
    op.create_index(
        "ux_policy_approvals_assertion_jti", "policy_approvals", ["assertion_jti"], unique=True
    )
    op.add_column("review_outcomes", sa.Column("reviewer", sa.String(length=120)))

    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        # fraud_ai_append_only() exists since 0009.
        op.execute(
            "CREATE TRIGGER operator_assertions_append_only BEFORE UPDATE OR DELETE ON "
            "operator_assertions FOR EACH ROW EXECUTE FUNCTION fraud_ai_append_only()"
        )
    elif dialect == "sqlite":
        for verb in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER operator_assertions_no_{verb.lower()} BEFORE {verb} ON "
                "operator_assertions BEGIN SELECT RAISE(ABORT, 'operator_assertions is "
                "append-only'); END"
            )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS operator_assertions_append_only ON operator_assertions")
    elif dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS operator_assertions_no_update")
        op.execute("DROP TRIGGER IF EXISTS operator_assertions_no_delete")
    with op.batch_alter_table("review_outcomes") as batch:
        batch.drop_column("reviewer")
    op.drop_index("ux_policy_approvals_assertion_jti", table_name="policy_approvals")
    with op.batch_alter_table("policy_approvals") as batch:
        batch.drop_column("assertion")
        batch.drop_column("assertion_jti")
        batch.drop_column("operator_key_id")
    op.drop_index("ix_operator_assertions_operator", table_name="operator_assertions")
    op.drop_table("operator_assertions")
