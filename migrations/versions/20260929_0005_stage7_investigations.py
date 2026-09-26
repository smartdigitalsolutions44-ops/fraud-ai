"""Stage 7 local LLM analyst assistance: persisted investigations.

* ``investigations``: validated, cited explanations of one event, append-only and versioned
  per event (``explanation_version``). Each row records the evidence packet and its SHA-256,
  the prompt, schema and evidence versions, the runtime, model and generation parameters,
  and the validation result. Explanations never change scores, labels or decisions.

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-29 09:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import fraud_ai.database.base

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json() -> sa.types.TypeEngine[object]:
    return sa.JSON().with_variant(sa.dialects.postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("explanation_version", sa.Integer(), nullable=False),
        sa.Column("created_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.Column("explanation_text", sa.Text(), nullable=False),
        sa.Column("explanation_json", _json(), nullable=False),
        sa.Column("explanation_schema_version", sa.String(length=64), nullable=False),
        sa.Column("evidence_packet", _json(), nullable=False),
        sa.Column("evidence_packet_sha256", sa.String(length=64), nullable=False),
        sa.Column("evidence_schema_version", sa.String(length=64), nullable=False),
        sa.Column("prompt_version", sa.String(length=64), nullable=False),
        sa.Column("llm_runtime", sa.String(length=32), nullable=False),
        sa.Column("llm_model", sa.String(length=200), nullable=False),
        sa.Column("llm_model_version", sa.String(length=200), nullable=True),
        sa.Column("generation_parameters", _json(), nullable=False),
        sa.Column("validation", _json(), nullable=False),
        sa.Column("latency_seconds", sa.Float(), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "explanation_version >= 1",
            name=op.f("ck_investigations_explanation_version_positive"),
        ),
        sa.CheckConstraint(
            "length(evidence_packet_sha256) = 64",
            name=op.f("ck_investigations_packet_hash_sha256"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.event_id"], name=op.f("fk_investigations_event_id_events")
        ),
        sa.PrimaryKeyConstraint("investigation_id", name=op.f("pk_investigations")),
        sa.UniqueConstraint(
            "event_id",
            "explanation_version",
            name=op.f("uq_investigations_event_id_explanation_version"),
        ),
    )
    op.create_index("ix_investigations_event_id", "investigations", ["event_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_investigations_event_id", table_name="investigations")
    op.drop_table("investigations")
