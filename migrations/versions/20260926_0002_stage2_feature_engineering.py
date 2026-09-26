"""Stage 2 feature engineering: feature snapshots and point-in-time source columns.

* ``feature_snapshots``: persisted, hashed feature vectors.
* ``transactions.decision_outcome``: immutable authorisation outcome (``status`` is
  overwritten by a later chargeback, so it cannot be used point-in-time). Backfilled from
  ``status``: a CHARGEBACK can only follow an APPROVED decision.
* ``addresses.verified_at`` / ``payment_methods.verified_at``: first verification time.
* ``network_events.is_mobile_network``: per-observation intel snapshot. Existing rows are
  left NULL (unknown) - backfilling from ``network_identities`` would copy *current* intel
  into historical observations, which is exactly the leakage this stage prevents.
* ``ix_transactions_shipping_address_id_occurred_at``: the point-in-time "orders to this
  address" feature query was a sequential scan over all transactions (EXPLAIN ANALYZE on
  PostgreSQL); every other feature query already used an index.
* New account-lifecycle event types (email/phone verification and change, MFA enrol and
  removal, address and payment-method verification) widen two enum CHECK constraints.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-26 09:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import fraud_ai.database.base

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen copies of the enum values: migrations must not change if the enums do later.
EVENT_TYPES_0001 = [
    "ACCOUNT_CREATED",
    "LOGIN_ATTEMPT",
    "LOGIN_SUCCESS",
    "LOGIN_FAILURE",
    "PASSWORD_RESET",
    "NEW_DEVICE",
    "ADDRESS_ADDED",
    "ADDRESS_CHANGED",
    "PAYMENT_METHOD_ADDED",
    "TRANSACTION_CREATED",
    "TRANSACTION_APPROVED",
    "TRANSACTION_DECLINED",
    "CHARGEBACK",
    "FRAUD_CONFIRMED",
]
LIFECYCLE_TYPES = [
    "EMAIL_VERIFIED",
    "EMAIL_CHANGED",
    "PHONE_VERIFIED",
    "PHONE_CHANGED",
    "MFA_ENABLED",
    "MFA_DISABLED",
]
EVENT_TYPES_0002 = [
    *EVENT_TYPES_0001,
    *LIFECYCLE_TYPES,
    "ADDRESS_VERIFIED",
    "PAYMENT_METHOD_VERIFIED",
]
SECURITY_TYPES_0001 = ["PASSWORD_RESET", "NEW_DEVICE", "ADDRESS_CHANGED", "PAYMENT_METHOD_ADDED"]
SECURITY_TYPES_0002 = [*SECURITY_TYPES_0001, *LIFECYCLE_TYPES]


def _in(column: str, values: list[str]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _replace_check(table: str, name: str, column: str, values: list[str]) -> None:
    with op.batch_alter_table(table) as batch_op:
        batch_op.drop_constraint(op.f(name), type_="check")
        batch_op.create_check_constraint(op.f(name), _in(column, values))


def upgrade() -> None:
    _replace_check("events", "ck_events_event_type", "event_type", EVENT_TYPES_0002)
    _replace_check(
        "security_events",
        "ck_security_events_security_event_type",
        "security_event_type",
        SECURITY_TYPES_0002,
    )

    with op.batch_alter_table("transactions") as batch_op:
        batch_op.add_column(
            sa.Column(
                "decision_outcome",
                sa.Enum(
                    "APPROVED",
                    "DECLINED",
                    name="transaction_decision",
                    native_enum=False,
                    create_constraint=False,
                    length=16,
                ),
                nullable=True,
            )
        )
        batch_op.create_check_constraint(
            op.f("ck_transactions_transaction_decision"),
            _in("decision_outcome", ["APPROVED", "DECLINED"]),
        )
    op.execute(
        "UPDATE transactions SET decision_outcome = CASE status "
        "WHEN 'APPROVED' THEN 'APPROVED' WHEN 'CHARGEBACK' THEN 'APPROVED' "
        "WHEN 'DECLINED' THEN 'DECLINED' END WHERE decided_at IS NOT NULL"
    )

    op.add_column(
        "addresses",
        sa.Column("verified_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "payment_methods",
        sa.Column("verified_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=True),
    )
    op.add_column("network_events", sa.Column("is_mobile_network", sa.Boolean(), nullable=True))

    op.create_table(
        "feature_snapshots",
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("transaction_id", sa.Uuid(), nullable=True),
        sa.Column("login_event_id", sa.Uuid(), nullable=True),
        sa.Column("feature_version", sa.String(length=50), nullable=False),
        sa.Column(
            "generated_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False
        ),
        sa.Column(
            "as_of_timestamp", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False
        ),
        sa.Column(
            "features",
            sa.JSON().with_variant(
                sa.dialects.postgresql.JSONB(astext_type=sa.Text()), "postgresql"
            ),
            nullable=False,
        ),
        sa.Column("feature_hash", sa.String(length=64), nullable=False),
        sa.Column("source_event_count", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "length(feature_hash) = 64", name=op.f("ck_feature_snapshots_feature_hash_sha256")
        ),
        sa.CheckConstraint(
            "source_event_count >= 0",
            name=op.f("ck_feature_snapshots_source_event_count_non_negative"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.event_id"], name=op.f("fk_feature_snapshots_event_id_events")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_feature_snapshots_user_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["transaction_id"],
            ["transactions.transaction_id"],
            name=op.f("fk_feature_snapshots_transaction_id_transactions"),
        ),
        sa.ForeignKeyConstraint(
            ["login_event_id"],
            ["login_events.login_event_id"],
            name=op.f("fk_feature_snapshots_login_event_id_login_events"),
        ),
        sa.PrimaryKeyConstraint("snapshot_id", name=op.f("pk_feature_snapshots")),
        sa.UniqueConstraint(
            "event_id",
            "feature_version",
            "as_of_timestamp",
            name=op.f("uq_feature_snapshots_event_id_feature_version_as_of_timestamp"),
        ),
    )
    op.create_index(
        "ix_feature_snapshots_version_as_of",
        "feature_snapshots",
        ["feature_version", "as_of_timestamp"],
    )
    op.create_index("ix_feature_snapshots_user_id", "feature_snapshots", ["user_id"])
    op.create_index("ix_feature_snapshots_transaction_id", "feature_snapshots", ["transaction_id"])
    op.create_index(
        "ix_transactions_shipping_address_id_occurred_at",
        "transactions",
        ["shipping_address_id", "occurred_at"],
    )


def downgrade() -> None:
    """Fails (by design) if rows use the new event types: they cannot be represented."""
    op.drop_index("ix_transactions_shipping_address_id_occurred_at", table_name="transactions")
    op.drop_index("ix_feature_snapshots_transaction_id", table_name="feature_snapshots")
    op.drop_index("ix_feature_snapshots_user_id", table_name="feature_snapshots")
    op.drop_index("ix_feature_snapshots_version_as_of", table_name="feature_snapshots")
    op.drop_table("feature_snapshots")
    with op.batch_alter_table("network_events") as batch_op:
        batch_op.drop_column("is_mobile_network")
    with op.batch_alter_table("payment_methods") as batch_op:
        batch_op.drop_column("verified_at")
    with op.batch_alter_table("addresses") as batch_op:
        batch_op.drop_column("verified_at")
    with op.batch_alter_table("transactions") as batch_op:
        batch_op.drop_constraint(op.f("ck_transactions_transaction_decision"), type_="check")
        batch_op.drop_column("decision_outcome")
    _replace_check(
        "security_events",
        "ck_security_events_security_event_type",
        "security_event_type",
        SECURITY_TYPES_0001,
    )
    _replace_check("events", "ck_events_event_type", "event_type", EVENT_TYPES_0001)
