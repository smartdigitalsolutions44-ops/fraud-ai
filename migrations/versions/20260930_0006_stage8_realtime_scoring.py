"""Stage 8 real-time scoring and risk-decision orchestration.

* ``events.arrival_time``: when the event reached the platform (NULL for historical and
  bulk loads, which count as arriving on time).
* ``risk_policies``: immutable, hashed, versioned risk policies.
* ``policy_deployments``: append-only activation history (active policy, shadow models,
  shadow policies).
* ``risk_assessments``: versioned, immutable decisions with an idempotency key, the model
  scores, rule results, shadow results, action request, per-stage latency, fallback and
  failure records, event and arrival time. The unused Stage 1 ``rule_score`` and the
  Stage 1 explanation columns are dropped (Stage 7 stores explanations in
  ``investigations``). The decision CHECK constraint moves to the Stage 8 decision set;
  there is no permanent ``BLOCK``.
* ``review_queue`` / ``review_outcomes``: the manual-review queue and append-only
  outcomes.

No code path wrote ``risk_assessments`` before this stage, so the upgrade refuses to run
on a non-empty table instead of inventing values for the new NOT NULL columns.

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-30 09:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import fraud_ai.database.base

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen copies: migrations must not change if the enums do later.
DECISIONS_0001 = ["ALLOW", "STEP_UP_AUTHENTICATION", "MANUAL_REVIEW", "BLOCK"]
DECISIONS_0006 = [
    "ALLOW",
    "ALLOW_WITH_MONITORING",
    "STEP_UP_AUTHENTICATION",
    "MANUAL_REVIEW",
    "TEMPORARY_BLOCK",
]
REVIEW_STATUSES = ["open", "needs_more_information", "resolved"]
RESOLUTIONS = ["legitimate", "fraud", "needs_more_information"]


def _json() -> sa.types.TypeEngine[object]:
    return sa.JSON().with_variant(sa.dialects.postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def _dt() -> fraud_ai.database.base.UTCDateTime:
    return fraud_ai.database.base.UTCDateTime(timezone=True)


def _in(column: str, values: list[str]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def upgrade() -> None:
    rows = op.get_bind().execute(sa.text("SELECT COUNT(*) FROM risk_assessments")).scalar()
    if rows:
        raise RuntimeError(
            f"risk_assessments holds {rows} rows written outside the platform; migration "
            "0006 cannot invent their Stage 8 fields. Archive and empty the table first."
        )
    op.create_table(
        "risk_policies",
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("definition", _json(), nullable=False),
        sa.Column("definition_sha256", sa.String(length=64), nullable=False),
        sa.Column("derivation", _json(), nullable=False),
        sa.Column("synthetic_derived", sa.Boolean(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", _dt(), nullable=False),
        sa.CheckConstraint(
            "length(definition_sha256) = 64", name=op.f("ck_risk_policies_definition_sha256_length")
        ),
        sa.PrimaryKeyConstraint("policy_id", name=op.f("pk_risk_policies")),
        sa.UniqueConstraint("policy_version", name=op.f("uq_risk_policies_policy_version")),
    )
    op.create_table(
        "policy_deployments",
        sa.Column("deployment_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("shadow_models", _json(), nullable=False),
        sa.Column("shadow_policies", _json(), nullable=False),
        sa.Column("config_sha256", sa.String(length=64), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("activated_at", _dt(), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_version"],
            ["risk_policies.policy_version"],
            name=op.f("fk_policy_deployments_policy_version_risk_policies"),
        ),
        sa.PrimaryKeyConstraint("deployment_id", name=op.f("pk_policy_deployments")),
        sa.UniqueConstraint("sequence", name=op.f("uq_policy_deployments_sequence")),
    )
    with op.batch_alter_table("events") as batch_op:
        batch_op.add_column(sa.Column("arrival_time", _dt(), nullable=True))

    with op.batch_alter_table("risk_assessments") as batch_op:
        batch_op.add_column(sa.Column("assessment_version", sa.Integer(), nullable=False))
        batch_op.add_column(sa.Column("supersedes_assessment_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("idempotency_key", sa.String(length=64), nullable=False))
        batch_op.add_column(sa.Column("mode", sa.String(length=16), nullable=False))
        batch_op.add_column(sa.Column("deployment_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("event_time", _dt(), nullable=True))
        batch_op.add_column(sa.Column("arrival_time", _dt(), nullable=True))
        batch_op.add_column(sa.Column("lateness_seconds", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("rules_version", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("primary_model", sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column("calibrated_score", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("risk_level", sa.String(length=16), nullable=False))
        batch_op.add_column(sa.Column("reason_codes", _json(), nullable=False))
        batch_op.add_column(sa.Column("model_scores", _json(), nullable=False))
        batch_op.add_column(sa.Column("shadow", _json(), nullable=False))
        batch_op.add_column(sa.Column("action", _json(), nullable=False))
        batch_op.add_column(sa.Column("latency_ms", _json(), nullable=False))
        batch_op.add_column(sa.Column("fallback_used", sa.Boolean(), nullable=False))
        batch_op.add_column(sa.Column("failures", _json(), nullable=False))
        batch_op.alter_column("final_risk_score", existing_type=sa.Float(), nullable=True)
        batch_op.drop_constraint(op.f("ck_risk_assessments_final_score_range"), type_="check")
        batch_op.create_check_constraint(
            op.f("ck_risk_assessments_final_score_range"),
            "final_risk_score IS NULL OR (final_risk_score >= 0 AND final_risk_score <= 1)",
        )
        batch_op.drop_constraint(op.f("ck_risk_assessments_decision"), type_="check")
        batch_op.create_check_constraint(
            op.f("ck_risk_assessments_decision"), _in("decision", DECISIONS_0006)
        )
        batch_op.create_check_constraint(
            op.f("ck_risk_assessments_assessment_version_positive"), "assessment_version >= 1"
        )
        batch_op.create_index("ix_risk_assessments_assessed_at", ["assessed_at"], unique=False)
        batch_op.create_unique_constraint(
            op.f("uq_risk_assessments_event_id_assessment_version"),
            ["event_id", "assessment_version"],
        )
        batch_op.create_unique_constraint(
            op.f("uq_risk_assessments_idempotency_key"), ["idempotency_key"]
        )
        batch_op.create_foreign_key(
            op.f("fk_risk_assessments_supersedes_assessment_id_risk_assessments"),
            "risk_assessments",
            ["supersedes_assessment_id"],
            ["assessment_id"],
        )
        batch_op.create_foreign_key(
            op.f("fk_risk_assessments_deployment_id_policy_deployments"),
            "policy_deployments",
            ["deployment_id"],
            ["deployment_id"],
        )
        batch_op.drop_column("explanation")
        batch_op.drop_column("explanation_model")
        batch_op.drop_column("rule_score")

    op.create_table(
        "review_queue",
        sa.Column("review_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("priority", sa.SmallInteger(), nullable=False),
        sa.Column("reason_codes", _json(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", _dt(), nullable=False),
        sa.Column("reviewed_at", _dt(), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=True),
        sa.CheckConstraint(
            _in("outcome", RESOLUTIONS), name=op.f("ck_review_queue_review_resolution")
        ),
        sa.CheckConstraint(
            _in("status", REVIEW_STATUSES), name=op.f("ck_review_queue_review_status")
        ),
        sa.CheckConstraint(
            "priority >= 1 AND priority <= 5", name=op.f("ck_review_queue_priority_range")
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["risk_assessments.assessment_id"],
            name=op.f("fk_review_queue_assessment_id_risk_assessments"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["events.event_id"], name=op.f("fk_review_queue_event_id_events")
        ),
        sa.PrimaryKeyConstraint("review_id", name=op.f("pk_review_queue")),
        sa.UniqueConstraint("assessment_id", name=op.f("uq_review_queue_assessment_id")),
    )
    op.create_index(
        "ix_review_queue_status_priority", "review_queue", ["status", "priority"], unique=False
    )
    op.create_table(
        "review_outcomes",
        sa.Column("outcome_id", sa.Uuid(), nullable=False),
        sa.Column("review_id", sa.Uuid(), nullable=False),
        sa.Column("resolution", sa.String(length=32), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("created_at", _dt(), nullable=False),
        sa.CheckConstraint(
            _in("resolution", RESOLUTIONS), name=op.f("ck_review_outcomes_review_resolution")
        ),
        sa.ForeignKeyConstraint(
            ["review_id"],
            ["review_queue.review_id"],
            name=op.f("fk_review_outcomes_review_id_review_queue"),
        ),
        sa.PrimaryKeyConstraint("outcome_id", name=op.f("pk_review_outcomes")),
    )
    op.create_index("ix_review_outcomes_review_id", "review_outcomes", ["review_id"], unique=False)


def downgrade() -> None:
    rows = op.get_bind().execute(sa.text("SELECT COUNT(*) FROM risk_assessments")).scalar()
    if rows:
        raise RuntimeError(
            f"risk_assessments holds {rows} Stage 8 decisions; downgrading would destroy "
            "them. Archive and empty the table first."
        )
    op.drop_index("ix_review_outcomes_review_id", table_name="review_outcomes")
    op.drop_table("review_outcomes")
    op.drop_index("ix_review_queue_status_priority", table_name="review_queue")
    op.drop_table("review_queue")
    with op.batch_alter_table("risk_assessments") as batch_op:
        batch_op.add_column(sa.Column("rule_score", sa.Float(), nullable=False))
        batch_op.add_column(sa.Column("explanation_model", sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column("explanation", sa.Text(), nullable=True))
        batch_op.drop_constraint(
            op.f("fk_risk_assessments_deployment_id_policy_deployments"), type_="foreignkey"
        )
        batch_op.drop_constraint(
            op.f("fk_risk_assessments_supersedes_assessment_id_risk_assessments"),
            type_="foreignkey",
        )
        batch_op.drop_constraint(op.f("uq_risk_assessments_idempotency_key"), type_="unique")
        batch_op.drop_constraint(
            op.f("uq_risk_assessments_event_id_assessment_version"), type_="unique"
        )
        batch_op.drop_index("ix_risk_assessments_assessed_at")
        batch_op.drop_constraint(
            op.f("ck_risk_assessments_assessment_version_positive"), type_="check"
        )
        batch_op.drop_constraint(op.f("ck_risk_assessments_decision"), type_="check")
        batch_op.create_check_constraint(
            op.f("ck_risk_assessments_decision"), _in("decision", DECISIONS_0001)
        )
        batch_op.drop_constraint(op.f("ck_risk_assessments_final_score_range"), type_="check")
        batch_op.create_check_constraint(
            op.f("ck_risk_assessments_final_score_range"),
            "final_risk_score >= 0 AND final_risk_score <= 1",
        )
        batch_op.alter_column("final_risk_score", existing_type=sa.Float(), nullable=False)
        for column in (
            "failures",
            "fallback_used",
            "latency_ms",
            "action",
            "shadow",
            "model_scores",
            "reason_codes",
            "risk_level",
            "calibrated_score",
            "primary_model",
            "rules_version",
            "lateness_seconds",
            "arrival_time",
            "event_time",
            "deployment_id",
            "mode",
            "idempotency_key",
            "supersedes_assessment_id",
            "assessment_version",
        ):
            batch_op.drop_column(column)
    with op.batch_alter_table("events") as batch_op:
        batch_op.drop_column("arrival_time")
    op.drop_table("policy_deployments")
    op.drop_table("risk_policies")
