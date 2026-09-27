"""Stage 9 secure service and authentication integration.

* ``service_api_keys``: API key ids with salted SHA-256 secret hashes, scopes, revocation.
* ``request_idempotency``: first responses per (API key, route, Idempotency-Key).
* ``request_replay_tokens``: accepted request/callback signatures until they expire.
* ``webauthn_credentials``: passkey public keys (never private keys), sign counters.
* ``authentication_challenges``: single-use, short-lived challenge hashes bound to user,
  session and assessment.
* ``authentication_attempts``: append-only step-up outcomes, linked to the immutable
  follow-up assessment.
* ``payment_auth_requests``: requests to an external payment-authentication provider
  (token reference hash only; no card data).

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-01 09:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import fraud_ai.database.base

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json() -> sa.types.TypeEngine[object]:
    return sa.JSON().with_variant(sa.dialects.postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def _dt() -> fraud_ai.database.base.UTCDateTime:
    return fraud_ai.database.base.UTCDateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "request_idempotency",
        sa.Column("record_id", sa.Uuid(), nullable=False),
        sa.Column("api_key_id", sa.String(length=40), nullable=False),
        sa.Column("route", sa.String(length=100), nullable=False),
        sa.Column("idempotency_key", sa.String(length=100), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("response_body", _json(), nullable=True),
        sa.Column("policy_version", sa.String(length=32), nullable=True),
        sa.Column("created_at", _dt(), nullable=False),
        sa.PrimaryKeyConstraint("record_id", name=op.f("pk_request_idempotency")),
        sa.UniqueConstraint(
            "api_key_id",
            "route",
            "idempotency_key",
            name=op.f("uq_request_idempotency_api_key_id_route_idempotency_key"),
        ),
    )
    with op.batch_alter_table("request_idempotency", schema=None) as batch_op:
        batch_op.create_index("ix_request_idempotency_created_at", ["created_at"], unique=False)

    op.create_table(
        "request_replay_tokens",
        sa.Column("token_id", sa.Uuid(), nullable=False),
        sa.Column("signer", sa.String(length=64), nullable=False),
        sa.Column("signature_sha256", sa.String(length=64), nullable=False),
        sa.Column("signed_at", _dt(), nullable=False),
        sa.Column("expires_at", _dt(), nullable=False),
        sa.Column("received_at", _dt(), nullable=False),
        sa.PrimaryKeyConstraint("token_id", name=op.f("pk_request_replay_tokens")),
        sa.UniqueConstraint(
            "signature_sha256", name=op.f("uq_request_replay_tokens_signature_sha256")
        ),
    )
    with op.batch_alter_table("request_replay_tokens", schema=None) as batch_op:
        batch_op.create_index("ix_request_replay_tokens_expires_at", ["expires_at"], unique=False)

    op.create_table(
        "service_api_keys",
        sa.Column("api_key_pk", sa.Uuid(), nullable=False),
        sa.Column("key_id", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("secret_salt", sa.String(length=64), nullable=False),
        sa.Column("secret_sha256", sa.String(length=64), nullable=False),
        sa.Column("scopes", _json(), nullable=False),
        sa.Column("created_at", _dt(), nullable=False),
        sa.Column("revoked_at", _dt(), nullable=True),
        sa.CheckConstraint(
            "length(secret_sha256) = 64", name=op.f("ck_service_api_keys_secret_sha256_length")
        ),
        sa.PrimaryKeyConstraint("api_key_pk", name=op.f("pk_service_api_keys")),
        sa.UniqueConstraint("key_id", name=op.f("uq_service_api_keys_key_id")),
    )
    op.create_table(
        "webauthn_credentials",
        sa.Column("credential_pk", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.String(length=1400), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False),
        sa.Column("transports", _json(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", _dt(), nullable=False),
        sa.Column("last_used_at", _dt(), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')",
            name=op.f("ck_webauthn_credentials_credential_status"),
        ),
        sa.CheckConstraint(
            "sign_count >= 0", name=op.f("ck_webauthn_credentials_sign_count_non_negative")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_webauthn_credentials_user_id_users")
        ),
        sa.PrimaryKeyConstraint("credential_pk", name=op.f("pk_webauthn_credentials")),
        sa.UniqueConstraint("credential_id", name=op.f("uq_webauthn_credentials_credential_id")),
    )
    with op.batch_alter_table("webauthn_credentials", schema=None) as batch_op:
        batch_op.create_index("ix_webauthn_credentials_user_id", ["user_id"], unique=False)

    op.create_table(
        "authentication_challenges",
        sa.Column("challenge_id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("challenge_sha256", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("assessment_id", sa.Uuid(), nullable=True),
        sa.Column("api_key_id", sa.String(length=40), nullable=True),
        sa.Column("created_at", _dt(), nullable=False),
        sa.Column("expires_at", _dt(), nullable=False),
        sa.Column("consumed_at", _dt(), nullable=True),
        sa.CheckConstraint(
            "purpose IN ('registration', 'authentication')",
            name=op.f("ck_authentication_challenges_challenge_purpose"),
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["risk_assessments.assessment_id"],
            name=op.f("fk_authentication_challenges_assessment_id_risk_assessments"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.user_id"], name=op.f("fk_authentication_challenges_user_id_users")
        ),
        sa.PrimaryKeyConstraint("challenge_id", name=op.f("pk_authentication_challenges")),
        sa.UniqueConstraint(
            "challenge_sha256", name=op.f("uq_authentication_challenges_challenge_sha256")
        ),
    )
    with op.batch_alter_table("authentication_challenges", schema=None) as batch_op:
        batch_op.create_index(
            "ix_authentication_challenges_assessment_id", ["assessment_id"], unique=False
        )

    op.create_table(
        "payment_auth_requests",
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("provider_reference", sa.String(length=100), nullable=False),
        sa.Column("token_ref_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("created_at", _dt(), nullable=False),
        sa.Column("completed_at", _dt(), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'authenticated', 'failed', 'cancelled', 'timeout', 'unavailable')",
            name=op.f("ck_payment_auth_requests_payment_auth_status"),
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["risk_assessments.assessment_id"],
            name=op.f("fk_payment_auth_requests_assessment_id_risk_assessments"),
        ),
        sa.PrimaryKeyConstraint("request_id", name=op.f("pk_payment_auth_requests")),
        sa.UniqueConstraint(
            "provider",
            "provider_reference",
            name=op.f("uq_payment_auth_requests_provider_provider_reference"),
        ),
    )
    with op.batch_alter_table("payment_auth_requests", schema=None) as batch_op:
        batch_op.create_index(
            "ix_payment_auth_requests_assessment_id", ["assessment_id"], unique=False
        )

    op.create_table(
        "authentication_attempts",
        sa.Column("attempt_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("method", sa.String(length=32), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("failure_reason", sa.String(length=64), nullable=True),
        sa.Column("credential_ref", sa.String(length=100), nullable=True),
        sa.Column("challenge_id", sa.Uuid(), nullable=True),
        sa.Column("payment_request_id", sa.Uuid(), nullable=True),
        sa.Column("followup_assessment_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", _dt(), nullable=False),
        sa.CheckConstraint(
            "method IN ('webauthn', 'payment_authentication')",
            name=op.f("ck_authentication_attempts_authentication_method"),
        ),
        sa.CheckConstraint(
            "result IN ('SUCCESS', 'FAILED', 'EXPIRED', 'CANCELLED', 'UNAVAILABLE')",
            name=op.f("ck_authentication_attempts_authentication_result"),
        ),
        sa.CheckConstraint(
            "attempt_number >= 1", name=op.f("ck_authentication_attempts_attempt_number_positive")
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["risk_assessments.assessment_id"],
            name=op.f("fk_authentication_attempts_assessment_id_risk_assessments"),
        ),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["authentication_challenges.challenge_id"],
            name=op.f("fk_authentication_attempts_challenge_id_authentication_challenges"),
        ),
        sa.ForeignKeyConstraint(
            ["followup_assessment_id"],
            ["risk_assessments.assessment_id"],
            name=op.f("fk_authentication_attempts_followup_assessment_id_risk_assessments"),
        ),
        sa.ForeignKeyConstraint(
            ["payment_request_id"],
            ["payment_auth_requests.request_id"],
            name=op.f("fk_authentication_attempts_payment_request_id_payment_auth_requests"),
        ),
        sa.PrimaryKeyConstraint("attempt_id", name=op.f("pk_authentication_attempts")),
        sa.UniqueConstraint(
            "assessment_id",
            "attempt_number",
            name=op.f("uq_authentication_attempts_assessment_id_attempt_number"),
        ),
    )


def downgrade() -> None:
    op.drop_table("authentication_attempts")
    with op.batch_alter_table("payment_auth_requests", schema=None) as batch_op:
        batch_op.drop_index("ix_payment_auth_requests_assessment_id")

    op.drop_table("payment_auth_requests")
    with op.batch_alter_table("authentication_challenges", schema=None) as batch_op:
        batch_op.drop_index("ix_authentication_challenges_assessment_id")

    op.drop_table("authentication_challenges")
    with op.batch_alter_table("webauthn_credentials", schema=None) as batch_op:
        batch_op.drop_index("ix_webauthn_credentials_user_id")

    op.drop_table("webauthn_credentials")
    op.drop_table("service_api_keys")
    with op.batch_alter_table("request_replay_tokens", schema=None) as batch_op:
        batch_op.drop_index("ix_request_replay_tokens_expires_at")

    op.drop_table("request_replay_tokens")
    with op.batch_alter_table("request_idempotency", schema=None) as batch_op:
        batch_op.drop_index("ix_request_idempotency_created_at")

    op.drop_table("request_idempotency")
