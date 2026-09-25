"""Stage 1 initial schema: event log, entity history, labels, model registry.

Enum CHECK constraints are declared explicitly (named via the naming convention) so the
same DDL applies on PostgreSQL and SQLite.

Revision ID: 0001
Revises:
Create Date: 2026-09-25 22:54:33.969841

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

import fraud_ai.database.base

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("device_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "first_seen_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False
        ),
        sa.Column(
            "last_seen_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False
        ),
        sa.Column("os_family", sa.String(length=64), nullable=True),
        sa.Column("client_family", sa.String(length=64), nullable=True),
        sa.Column(
            "device_type",
            sa.Enum(
                "mobile",
                "tablet",
                "desktop",
                "other",
                "unknown",
                name="device_type",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("successful_logins", sa.Integer(), server_default="0", nullable=False),
        sa.Column("failed_logins", sa.Integer(), server_default="0", nullable=False),
        sa.CheckConstraint(
            "device_type IN ('mobile', 'tablet', 'desktop', 'other', 'unknown')",
            name=op.f("ck_devices_device_type"),
        ),
        sa.CheckConstraint("last_seen_at >= first_seen_at", name=op.f("ck_devices_seen_order")),
        sa.CheckConstraint(
            "successful_logins >= 0 AND failed_logins >= 0",
            name=op.f("ck_devices_counters_non_negative"),
        ),
        sa.PrimaryKeyConstraint("device_id", name=op.f("pk_devices")),
        sa.UniqueConstraint("device_hash", name=op.f("uq_devices_device_hash")),
    )
    op.create_table(
        "model_versions",
        sa.Column("model_version_id", sa.Uuid(), nullable=False),
        sa.Column("model_name", sa.String(length=100), nullable=False),
        sa.Column("model_version", sa.String(length=50), nullable=False),
        sa.Column("algorithm", sa.String(length=64), nullable=True),
        sa.Column(
            "training_timestamp", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False
        ),
        sa.Column("training_dataset_version", sa.String(length=100), nullable=False),
        sa.Column("feature_version", sa.String(length=50), nullable=False),
        sa.Column(
            "metrics",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("model_path", sa.String(length=1024), nullable=False),
        sa.Column("active", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("model_version_id", name=op.f("pk_model_versions")),
        sa.UniqueConstraint(
            "model_name", "model_version", name=op.f("uq_model_versions_model_name_model_version")
        ),
    )
    with op.batch_alter_table("model_versions", schema=None) as batch_op:
        batch_op.create_index(
            "uq_model_versions_one_active",
            ["model_name"],
            unique=True,
            postgresql_where=sa.text("active"),
            sqlite_where=sa.text("active"),
        )

    op.create_table(
        "network_identities",
        sa.Column("network_identity_id", sa.Uuid(), nullable=False),
        sa.Column("ip_hash", sa.String(length=64), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("ip_version", sa.SmallInteger(), nullable=False),
        sa.Column("asn", sa.BigInteger(), nullable=True),
        sa.Column("asn_org", sa.String(length=255), nullable=True),
        sa.Column("country", sa.String(length=2), nullable=True),
        sa.Column("region", sa.String(length=100), nullable=True),
        sa.Column(
            "network_type",
            sa.Enum(
                "residential",
                "mobile",
                "business",
                "datacenter",
                "education",
                "unknown",
                name="network_type",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("is_mobile_network", sa.Boolean(), nullable=True),
        sa.Column("is_datacenter", sa.Boolean(), nullable=True),
        sa.Column("is_known_proxy", sa.Boolean(), nullable=True),
        sa.Column("is_known_vpn", sa.Boolean(), nullable=True),
        sa.Column("is_tor", sa.Boolean(), nullable=True),
        sa.Column("proxy_confidence", sa.Float(), nullable=True),
        sa.Column("intel_source", sa.String(length=64), nullable=True),
        sa.Column(
            "intel_updated_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "first_seen_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False
        ),
        sa.Column(
            "last_seen_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False
        ),
        sa.Column("distinct_user_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("failed_login_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("successful_login_count", sa.Integer(), server_default="0", nullable=False),
        sa.CheckConstraint(
            "network_type IN ('residential', 'mobile', 'business', 'datacenter', 'education', 'unknown')",
            name=op.f("ck_network_identities_network_type"),
        ),
        sa.CheckConstraint(
            "distinct_user_count >= 0 AND failed_login_count >= 0 AND successful_login_count >= 0",
            name=op.f("ck_network_identities_counters_non_negative"),
        ),
        sa.CheckConstraint("ip_version IN (4, 6)", name=op.f("ck_network_identities_ip_version")),
        sa.CheckConstraint(
            "last_seen_at >= first_seen_at", name=op.f("ck_network_identities_seen_order")
        ),
        sa.CheckConstraint(
            "proxy_confidence IS NULL OR (proxy_confidence >= 0 AND proxy_confidence <= 1)",
            name=op.f("ck_network_identities_proxy_confidence_range"),
        ),
        sa.PrimaryKeyConstraint("network_identity_id", name=op.f("pk_network_identities")),
        sa.UniqueConstraint("ip_hash", name=op.f("uq_network_identities_ip_hash")),
    )
    with op.batch_alter_table("network_identities", schema=None) as batch_op:
        batch_op.create_index("ix_network_identities_asn", ["asn"], unique=False)

    op.create_table(
        "users",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("external_ref", sa.String(length=128), nullable=False),
        sa.Column(
            "account_created_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False
        ),
        sa.Column("home_country", sa.String(length=2), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "active",
                "locked",
                "closed",
                name="user_status",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("synthetic_scenario", sa.String(length=64), nullable=True),
        sa.Column("created_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.Column("updated_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'locked', 'closed')", name=op.f("ck_users_user_status")
        ),
        sa.CheckConstraint("length(home_country) = 2", name=op.f("ck_users_home_country_iso2")),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_users")),
        sa.UniqueConstraint("external_ref", name=op.f("uq_users_external_ref")),
    )
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_users_synthetic_scenario"), ["synthetic_scenario"], unique=False
        )

    op.create_table(
        "events",
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column(
            "event_type",
            sa.Enum(
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
                name="event_type",
                native_enum=False,
                create_constraint=False,
                length=40,
            ),
            nullable=False,
        ),
        sa.Column("occurred_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("device_id", sa.Uuid(), nullable=True),
        sa.Column(
            "source",
            sa.Enum(
                "web",
                "mobile_app",
                "api",
                "backoffice",
                "batch_import",
                "synthetic",
                name="event_source",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("schema_version", sa.SmallInteger(), nullable=False),
        sa.Column("ingested_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "event_type IN ('ACCOUNT_CREATED', 'LOGIN_ATTEMPT', 'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'PASSWORD_RESET', 'NEW_DEVICE', 'ADDRESS_ADDED', 'ADDRESS_CHANGED', 'PAYMENT_METHOD_ADDED', 'TRANSACTION_CREATED', 'TRANSACTION_APPROVED', 'TRANSACTION_DECLINED', 'CHARGEBACK', 'FRAUD_CONFIRMED')",
            name=op.f("ck_events_event_type"),
        ),
        sa.CheckConstraint(
            "source IN ('web', 'mobile_app', 'api', 'backoffice', 'batch_import', 'synthetic')",
            name=op.f("ck_events_event_source"),
        ),
        sa.CheckConstraint("schema_version >= 1", name=op.f("ck_events_schema_version_positive")),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.device_id"], name=op.f("fk_events_device_id_devices")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_events_user_id_users")
        ),
        sa.PrimaryKeyConstraint("event_id", name=op.f("pk_events")),
    )
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.create_index(
            "ix_events_device_id_occurred_at", ["device_id", "occurred_at"], unique=False
        )
        batch_op.create_index(
            "ix_events_event_type_occurred_at", ["event_type", "occurred_at"], unique=False
        )
        batch_op.create_index(
            "ix_events_user_id_occurred_at", ["user_id", "occurred_at"], unique=False
        )

    op.create_table(
        "user_devices",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column(
            "first_seen_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False
        ),
        sa.Column(
            "last_seen_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False
        ),
        sa.Column("is_trusted", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("successful_logins", sa.Integer(), server_default="0", nullable=False),
        sa.Column("failed_logins", sa.Integer(), server_default="0", nullable=False),
        sa.CheckConstraint(
            "last_seen_at >= first_seen_at", name=op.f("ck_user_devices_seen_order")
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.device_id"],
            name=op.f("fk_user_devices_device_id_devices"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.user_id"],
            name=op.f("fk_user_devices_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", "device_id", name=op.f("pk_user_devices")),
    )
    with op.batch_alter_table("user_devices", schema=None) as batch_op:
        batch_op.create_index("ix_user_devices_device_id", ["device_id"], unique=False)

    op.create_table(
        "addresses",
        sa.Column("address_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("address_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "address_type",
            sa.Enum(
                "home",
                "billing",
                "shipping",
                name="address_type",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("country", sa.String(length=2), nullable=False),
        sa.Column("region", sa.String(length=100), nullable=True),
        sa.Column("postal_prefix", sa.String(length=10), nullable=True),
        sa.Column("added_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.Column(
            "superseded_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=True
        ),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("replaces_address_id", sa.Uuid(), nullable=True),
        sa.Column("created_event_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "address_type IN ('home', 'billing', 'shipping')",
            name=op.f("ck_addresses_address_type"),
        ),
        sa.CheckConstraint("length(country) = 2", name=op.f("ck_addresses_country_iso2")),
        sa.CheckConstraint(
            "superseded_at IS NULL OR superseded_at >= added_at",
            name=op.f("ck_addresses_superseded_order"),
        ),
        sa.ForeignKeyConstraint(
            ["created_event_id"],
            ["events.event_id"],
            name=op.f("fk_addresses_created_event_id_events"),
        ),
        sa.ForeignKeyConstraint(
            ["replaces_address_id"],
            ["addresses.address_id"],
            name=op.f("fk_addresses_replaces_address_id_addresses"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.user_id"],
            name=op.f("fk_addresses_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("address_id", name=op.f("pk_addresses")),
    )
    with op.batch_alter_table("addresses", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_addresses_address_hash"), ["address_hash"], unique=False
        )
        batch_op.create_index(
            "ix_addresses_user_id_added_at", ["user_id", "added_at"], unique=False
        )

    op.create_table(
        "login_events",
        sa.Column("login_event_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("device_id", sa.Uuid(), nullable=True),
        sa.Column("network_identity_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("occurred_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.Column(
            "outcome",
            sa.Enum(
                "ATTEMPT",
                "SUCCESS",
                "FAILURE",
                name="login_outcome",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "auth_method",
            sa.Enum(
                "password",
                "passkey",
                "sso",
                "magic_link",
                "session_refresh",
                name="auth_method",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("mfa_used", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("failure_reason", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "auth_method IN ('password', 'passkey', 'sso', 'magic_link', 'session_refresh')",
            name=op.f("ck_login_events_auth_method"),
        ),
        sa.CheckConstraint(
            "outcome IN ('ATTEMPT', 'SUCCESS', 'FAILURE')",
            name=op.f("ck_login_events_login_outcome"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.device_id"], name=op.f("fk_login_events_device_id_devices")
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.event_id"], name=op.f("fk_login_events_event_id_events")
        ),
        sa.ForeignKeyConstraint(
            ["network_identity_id"],
            ["network_identities.network_identity_id"],
            name=op.f("fk_login_events_network_identity_id_network_identities"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_login_events_user_id_users")
        ),
        sa.PrimaryKeyConstraint("login_event_id", name=op.f("pk_login_events")),
        sa.UniqueConstraint("event_id", name=op.f("uq_login_events_event_id")),
    )
    with op.batch_alter_table("login_events", schema=None) as batch_op:
        batch_op.create_index(
            "ix_login_events_device_id_occurred_at", ["device_id", "occurred_at"], unique=False
        )
        batch_op.create_index(
            "ix_login_events_identity_occurred_at",
            ["network_identity_id", "occurred_at"],
            unique=False,
        )
        batch_op.create_index(
            "ix_login_events_user_id_occurred_at", ["user_id", "occurred_at"], unique=False
        )

    op.create_table(
        "network_events",
        sa.Column("network_event_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("network_identity_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("device_id", sa.Uuid(), nullable=True),
        sa.Column("observed_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.Column("asn", sa.BigInteger(), nullable=True),
        sa.Column("country", sa.String(length=2), nullable=True),
        sa.Column(
            "network_type",
            sa.Enum(
                "residential",
                "mobile",
                "business",
                "datacenter",
                "education",
                "unknown",
                name="network_event_network_type",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("is_known_vpn", sa.Boolean(), nullable=True),
        sa.Column("is_known_proxy", sa.Boolean(), nullable=True),
        sa.Column("is_tor", sa.Boolean(), nullable=True),
        sa.Column("is_datacenter", sa.Boolean(), nullable=True),
        sa.Column("proxy_confidence", sa.Float(), nullable=True),
        sa.CheckConstraint(
            "network_type IN ('residential', 'mobile', 'business', 'datacenter', 'education', 'unknown')",
            name=op.f("ck_network_events_network_event_network_type"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.device_id"], name=op.f("fk_network_events_device_id_devices")
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.event_id"], name=op.f("fk_network_events_event_id_events")
        ),
        sa.ForeignKeyConstraint(
            ["network_identity_id"],
            ["network_identities.network_identity_id"],
            name=op.f("fk_network_events_network_identity_id_network_identities"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_network_events_user_id_users")
        ),
        sa.PrimaryKeyConstraint("network_event_id", name=op.f("pk_network_events")),
        sa.UniqueConstraint("event_id", name=op.f("uq_network_events_event_id")),
    )
    with op.batch_alter_table("network_events", schema=None) as batch_op:
        batch_op.create_index(
            "ix_network_events_identity_observed_at",
            ["network_identity_id", "observed_at"],
            unique=False,
        )
        batch_op.create_index(
            "ix_network_events_identity_user", ["network_identity_id", "user_id"], unique=False
        )
        batch_op.create_index(
            "ix_network_events_user_id_observed_at", ["user_id", "observed_at"], unique=False
        )

    op.create_table(
        "payment_methods",
        sa.Column("payment_method_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_reference", sa.String(length=128), nullable=False),
        sa.Column(
            "method_type",
            sa.Enum(
                "card",
                "bank_account",
                "wallet",
                name="payment_method_type",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("card_brand", sa.String(length=32), nullable=True),
        sa.Column("card_last4", sa.String(length=4), nullable=True),
        sa.Column(
            "funding",
            sa.Enum(
                "credit",
                "debit",
                "prepaid",
                "unknown",
                name="card_funding",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=True,
        ),
        sa.Column("issuer_country", sa.String(length=2), nullable=True),
        sa.Column("fingerprint_hash", sa.String(length=64), nullable=True),
        sa.Column("added_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.Column("created_event_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "funding IN ('credit', 'debit', 'prepaid', 'unknown')",
            name=op.f("ck_payment_methods_card_funding"),
        ),
        sa.CheckConstraint(
            "method_type IN ('card', 'bank_account', 'wallet')",
            name=op.f("ck_payment_methods_payment_method_type"),
        ),
        sa.CheckConstraint(
            "card_last4 IS NULL OR length(card_last4) = 4",
            name=op.f("ck_payment_methods_last4_length"),
        ),
        sa.ForeignKeyConstraint(
            ["created_event_id"],
            ["events.event_id"],
            name=op.f("fk_payment_methods_created_event_id_events"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.user_id"],
            name=op.f("fk_payment_methods_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("payment_method_id", name=op.f("pk_payment_methods")),
        sa.UniqueConstraint("token_reference", name=op.f("uq_payment_methods_token_reference")),
    )
    with op.batch_alter_table("payment_methods", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_payment_methods_fingerprint_hash"), ["fingerprint_hash"], unique=False
        )
        batch_op.create_index("ix_payment_methods_user_id", ["user_id"], unique=False)

    op.create_table(
        "security_events",
        sa.Column("security_event_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=True),
        sa.Column("network_identity_id", sa.Uuid(), nullable=True),
        sa.Column(
            "security_event_type",
            sa.Enum(
                "PASSWORD_RESET",
                "NEW_DEVICE",
                "ADDRESS_CHANGED",
                "PAYMENT_METHOD_ADDED",
                name="security_event_type",
                native_enum=False,
                create_constraint=False,
                length=40,
            ),
            nullable=False,
        ),
        sa.Column("occurred_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.Column(
            "details",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "security_event_type IN ('PASSWORD_RESET', 'NEW_DEVICE', 'ADDRESS_CHANGED', 'PAYMENT_METHOD_ADDED')",
            name=op.f("ck_security_events_security_event_type"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.device_id"], name=op.f("fk_security_events_device_id_devices")
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.event_id"], name=op.f("fk_security_events_event_id_events")
        ),
        sa.ForeignKeyConstraint(
            ["network_identity_id"],
            ["network_identities.network_identity_id"],
            name=op.f("fk_security_events_network_identity_id_network_identities"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_security_events_user_id_users")
        ),
        sa.PrimaryKeyConstraint("security_event_id", name=op.f("pk_security_events")),
    )
    with op.batch_alter_table("security_events", schema=None) as batch_op:
        batch_op.create_index(
            "ix_security_events_user_type_occurred",
            ["user_id", "security_event_type", "occurred_at"],
            unique=False,
        )

    op.create_table(
        "transactions",
        sa.Column("transaction_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("payment_method_id", sa.Uuid(), nullable=True),
        sa.Column("shipping_address_id", sa.Uuid(), nullable=True),
        sa.Column("device_id", sa.Uuid(), nullable=True),
        sa.Column("network_identity_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("amount_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("merchant_category", sa.String(length=4), nullable=True),
        sa.Column(
            "channel",
            sa.Enum(
                "web",
                "mobile_app",
                "api",
                name="transaction_channel",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "APPROVED",
                "DECLINED",
                "CHARGEBACK",
                name="transaction_status",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("occurred_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.Column("decided_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "channel IN ('web', 'mobile_app', 'api')",
            name=op.f("ck_transactions_transaction_channel"),
        ),
        sa.CheckConstraint(
            "status IN ('PENDING', 'APPROVED', 'DECLINED', 'CHARGEBACK')",
            name=op.f("ck_transactions_transaction_status"),
        ),
        sa.CheckConstraint("amount_minor >= 0", name=op.f("ck_transactions_amount_non_negative")),
        sa.CheckConstraint(
            "decided_at IS NULL OR decided_at >= occurred_at",
            name=op.f("ck_transactions_decided_order"),
        ),
        sa.CheckConstraint("length(currency) = 3", name=op.f("ck_transactions_currency_iso4217")),
        sa.ForeignKeyConstraint(
            ["device_id"], ["devices.device_id"], name=op.f("fk_transactions_device_id_devices")
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.event_id"], name=op.f("fk_transactions_event_id_events")
        ),
        sa.ForeignKeyConstraint(
            ["network_identity_id"],
            ["network_identities.network_identity_id"],
            name=op.f("fk_transactions_network_identity_id_network_identities"),
        ),
        sa.ForeignKeyConstraint(
            ["payment_method_id"],
            ["payment_methods.payment_method_id"],
            name=op.f("fk_transactions_payment_method_id_payment_methods"),
        ),
        sa.ForeignKeyConstraint(
            ["shipping_address_id"],
            ["addresses.address_id"],
            name=op.f("fk_transactions_shipping_address_id_addresses"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_transactions_user_id_users")
        ),
        sa.PrimaryKeyConstraint("transaction_id", name=op.f("pk_transactions")),
        sa.UniqueConstraint("event_id", name=op.f("uq_transactions_event_id")),
    )
    with op.batch_alter_table("transactions", schema=None) as batch_op:
        batch_op.create_index(
            "ix_transactions_payment_method_id", ["payment_method_id"], unique=False
        )
        batch_op.create_index("ix_transactions_status", ["status"], unique=False)
        batch_op.create_index(
            "ix_transactions_user_id_occurred_at", ["user_id", "occurred_at"], unique=False
        )

    op.create_table(
        "fraud_labels",
        sa.Column("label_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("transaction_id", sa.Uuid(), nullable=True),
        sa.Column("event_id", sa.Uuid(), nullable=True),
        sa.Column("source_event_id", sa.Uuid(), nullable=True),
        sa.Column(
            "label",
            sa.Enum(
                "FRAUD",
                "LEGITIMATE",
                name="label_value",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "fraud_type",
            sa.Enum(
                "account_takeover",
                "credential_stuffing",
                "stolen_payment_method",
                "friendly_fraud",
                "other",
                name="fraud_type",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=True,
        ),
        sa.Column(
            "label_source",
            sa.Enum(
                "chargeback",
                "analyst",
                "customer_report",
                "synthetic_ground_truth",
                name="label_source",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("labelled_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "fraud_type IN ('account_takeover', 'credential_stuffing', 'stolen_payment_method', 'friendly_fraud', 'other')",
            name=op.f("ck_fraud_labels_fraud_type"),
        ),
        sa.CheckConstraint(
            "label <> 'FRAUD' OR fraud_type IS NOT NULL",
            name=op.f("ck_fraud_labels_fraud_requires_type"),
        ),
        sa.CheckConstraint(
            "label IN ('FRAUD', 'LEGITIMATE')", name=op.f("ck_fraud_labels_label_value")
        ),
        sa.CheckConstraint(
            "label_source IN ('chargeback', 'analyst', 'customer_report', 'synthetic_ground_truth')",
            name=op.f("ck_fraud_labels_label_source"),
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name=op.f("ck_fraud_labels_confidence_range")
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.event_id"], name=op.f("fk_fraud_labels_event_id_events")
        ),
        sa.ForeignKeyConstraint(
            ["source_event_id"],
            ["events.event_id"],
            name=op.f("fk_fraud_labels_source_event_id_events"),
        ),
        sa.ForeignKeyConstraint(
            ["transaction_id"],
            ["transactions.transaction_id"],
            name=op.f("fk_fraud_labels_transaction_id_transactions"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_fraud_labels_user_id_users")
        ),
        sa.PrimaryKeyConstraint("label_id", name=op.f("pk_fraud_labels")),
        sa.UniqueConstraint("source_event_id", name=op.f("uq_fraud_labels_source_event_id")),
    )
    with op.batch_alter_table("fraud_labels", schema=None) as batch_op:
        batch_op.create_index("ix_fraud_labels_transaction_id", ["transaction_id"], unique=False)
        batch_op.create_index("ix_fraud_labels_user_id", ["user_id"], unique=False)

    op.create_table(
        "fraud_signals",
        sa.Column("signal_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("transaction_id", sa.Uuid(), nullable=True),
        sa.Column("signal_name", sa.String(length=64), nullable=False),
        sa.Column(
            "signal_source",
            sa.Enum(
                "rule",
                "model",
                "network_intel",
                "analyst",
                "feature",
                name="signal_source",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("value", sa.Float(), nullable=True),
        sa.Column(
            "details",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("observed_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "signal_source IN ('rule', 'model', 'network_intel', 'analyst', 'feature')",
            name=op.f("ck_fraud_signals_signal_source"),
        ),
        sa.CheckConstraint(
            "event_id IS NOT NULL OR user_id IS NOT NULL OR transaction_id IS NOT NULL",
            name=op.f("ck_fraud_signals_has_subject"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.event_id"], name=op.f("fk_fraud_signals_event_id_events")
        ),
        sa.ForeignKeyConstraint(
            ["transaction_id"],
            ["transactions.transaction_id"],
            name=op.f("fk_fraud_signals_transaction_id_transactions"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_fraud_signals_user_id_users")
        ),
        sa.PrimaryKeyConstraint("signal_id", name=op.f("pk_fraud_signals")),
    )
    with op.batch_alter_table("fraud_signals", schema=None) as batch_op:
        batch_op.create_index("ix_fraud_signals_transaction_id", ["transaction_id"], unique=False)
        batch_op.create_index(
            "ix_fraud_signals_user_id_observed_at", ["user_id", "observed_at"], unique=False
        )

    op.create_table(
        "model_predictions",
        sa.Column("prediction_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("transaction_id", sa.Uuid(), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("model_name", sa.String(length=100), nullable=False),
        sa.Column("model_version", sa.String(length=50), nullable=False),
        sa.Column(
            "prediction_timestamp",
            fraud_ai.database.base.UTCDateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("fraud_probability", sa.Float(), nullable=False),
        sa.Column("predicted_class", sa.SmallInteger(), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("feature_version", sa.String(length=50), nullable=False),
        sa.Column("feature_snapshot_reference", sa.String(length=512), nullable=True),
        sa.CheckConstraint(
            "(predicted_class = 1 AND fraud_probability >= threshold) OR (predicted_class = 0 AND fraud_probability < threshold)",
            name=op.f("ck_model_predictions_class_matches_threshold"),
        ),
        sa.CheckConstraint(
            "fraud_probability >= 0 AND fraud_probability <= 1",
            name=op.f("ck_model_predictions_probability_range"),
        ),
        sa.CheckConstraint(
            "threshold >= 0 AND threshold <= 1", name=op.f("ck_model_predictions_threshold_range")
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.event_id"], name=op.f("fk_model_predictions_event_id_events")
        ),
        sa.ForeignKeyConstraint(
            ["model_name", "model_version"],
            ["model_versions.model_name", "model_versions.model_version"],
            name=op.f("fk_model_predictions_model_name_model_versions"),
        ),
        sa.ForeignKeyConstraint(
            ["transaction_id"],
            ["transactions.transaction_id"],
            name=op.f("fk_model_predictions_transaction_id_transactions"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_model_predictions_user_id_users")
        ),
        sa.PrimaryKeyConstraint("prediction_id", name=op.f("pk_model_predictions")),
    )
    with op.batch_alter_table("model_predictions", schema=None) as batch_op:
        batch_op.create_index("ix_model_predictions_event_id", ["event_id"], unique=False)
        batch_op.create_index(
            "ix_model_predictions_model_ts",
            ["model_name", "model_version", "prediction_timestamp"],
            unique=False,
        )
        batch_op.create_index(
            "ix_model_predictions_transaction_id", ["transaction_id"], unique=False
        )

    op.create_table(
        "risk_assessments",
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("transaction_id", sa.Uuid(), nullable=True),
        sa.Column("prediction_id", sa.Uuid(), nullable=True),
        sa.Column("assessed_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.Column("ml_probability", sa.Float(), nullable=True),
        sa.Column("rule_score", sa.Float(), nullable=False),
        sa.Column("final_risk_score", sa.Float(), nullable=False),
        sa.Column(
            "decision",
            sa.Enum(
                "ALLOW",
                "STEP_UP_AUTHENTICATION",
                "MANUAL_REVIEW",
                "BLOCK",
                name="decision",
                native_enum=False,
                create_constraint=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column(
            "triggered_rules",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("explanation_model", sa.String(length=100), nullable=True),
        sa.CheckConstraint(
            "decision IN ('ALLOW', 'STEP_UP_AUTHENTICATION', 'MANUAL_REVIEW', 'BLOCK')",
            name=op.f("ck_risk_assessments_decision"),
        ),
        sa.CheckConstraint(
            "final_risk_score >= 0 AND final_risk_score <= 1",
            name=op.f("ck_risk_assessments_final_score_range"),
        ),
        sa.CheckConstraint(
            "ml_probability IS NULL OR (ml_probability >= 0 AND ml_probability <= 1)",
            name=op.f("ck_risk_assessments_ml_probability_range"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.event_id"], name=op.f("fk_risk_assessments_event_id_events")
        ),
        sa.ForeignKeyConstraint(
            ["prediction_id"],
            ["model_predictions.prediction_id"],
            name=op.f("fk_risk_assessments_prediction_id_model_predictions"),
        ),
        sa.ForeignKeyConstraint(
            ["transaction_id"],
            ["transactions.transaction_id"],
            name=op.f("fk_risk_assessments_transaction_id_transactions"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_risk_assessments_user_id_users")
        ),
        sa.PrimaryKeyConstraint("assessment_id", name=op.f("pk_risk_assessments")),
    )
    with op.batch_alter_table("risk_assessments", schema=None) as batch_op:
        batch_op.create_index(
            "ix_risk_assessments_transaction_id", ["transaction_id"], unique=False
        )
        batch_op.create_index(
            "ix_risk_assessments_user_id_assessed_at", ["user_id", "assessed_at"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("risk_assessments", schema=None) as batch_op:
        batch_op.drop_index("ix_risk_assessments_user_id_assessed_at")
        batch_op.drop_index("ix_risk_assessments_transaction_id")

    op.drop_table("risk_assessments")
    with op.batch_alter_table("model_predictions", schema=None) as batch_op:
        batch_op.drop_index("ix_model_predictions_transaction_id")
        batch_op.drop_index("ix_model_predictions_model_ts")
        batch_op.drop_index("ix_model_predictions_event_id")

    op.drop_table("model_predictions")
    with op.batch_alter_table("fraud_signals", schema=None) as batch_op:
        batch_op.drop_index("ix_fraud_signals_user_id_observed_at")
        batch_op.drop_index("ix_fraud_signals_transaction_id")

    op.drop_table("fraud_signals")
    with op.batch_alter_table("fraud_labels", schema=None) as batch_op:
        batch_op.drop_index("ix_fraud_labels_user_id")
        batch_op.drop_index("ix_fraud_labels_transaction_id")

    op.drop_table("fraud_labels")
    with op.batch_alter_table("transactions", schema=None) as batch_op:
        batch_op.drop_index("ix_transactions_user_id_occurred_at")
        batch_op.drop_index("ix_transactions_status")
        batch_op.drop_index("ix_transactions_payment_method_id")

    op.drop_table("transactions")
    with op.batch_alter_table("security_events", schema=None) as batch_op:
        batch_op.drop_index("ix_security_events_user_type_occurred")

    op.drop_table("security_events")
    with op.batch_alter_table("payment_methods", schema=None) as batch_op:
        batch_op.drop_index("ix_payment_methods_user_id")
        batch_op.drop_index(batch_op.f("ix_payment_methods_fingerprint_hash"))

    op.drop_table("payment_methods")
    with op.batch_alter_table("network_events", schema=None) as batch_op:
        batch_op.drop_index("ix_network_events_user_id_observed_at")
        batch_op.drop_index("ix_network_events_identity_user")
        batch_op.drop_index("ix_network_events_identity_observed_at")

    op.drop_table("network_events")
    with op.batch_alter_table("login_events", schema=None) as batch_op:
        batch_op.drop_index("ix_login_events_user_id_occurred_at")
        batch_op.drop_index("ix_login_events_identity_occurred_at")
        batch_op.drop_index("ix_login_events_device_id_occurred_at")

    op.drop_table("login_events")
    with op.batch_alter_table("addresses", schema=None) as batch_op:
        batch_op.drop_index("ix_addresses_user_id_added_at")
        batch_op.drop_index(batch_op.f("ix_addresses_address_hash"))

    op.drop_table("addresses")
    with op.batch_alter_table("user_devices", schema=None) as batch_op:
        batch_op.drop_index("ix_user_devices_device_id")

    op.drop_table("user_devices")
    with op.batch_alter_table("events", schema=None) as batch_op:
        batch_op.drop_index("ix_events_user_id_occurred_at")
        batch_op.drop_index("ix_events_event_type_occurred_at")
        batch_op.drop_index("ix_events_device_id_occurred_at")

    op.drop_table("events")
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_users_synthetic_scenario"))

    op.drop_table("users")
    with op.batch_alter_table("network_identities", schema=None) as batch_op:
        batch_op.drop_index("ix_network_identities_asn")

    op.drop_table("network_identities")
    with op.batch_alter_table("model_versions", schema=None) as batch_op:
        batch_op.drop_index(
            "uq_model_versions_one_active",
            postgresql_where=sa.text("active"),
            sqlite_where=sa.text("active"),
        )

    op.drop_table("model_versions")
    op.drop_table("devices")
