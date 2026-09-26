"""Stage 4 evaluation: persisted model calibrations.

* ``model_calibrations``: sigmoid/isotonic calibrators fitted for a model version, with the
  split they were fitted on (a CHECK constraint forbids the test split), the dataset
  fingerprint, parameters and calibration metrics.

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-28 09:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import fraud_ai.database.base

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json() -> sa.types.TypeEngine[object]:
    return sa.JSON().with_variant(sa.dialects.postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "model_calibrations",
        sa.Column("calibration_id", sa.Uuid(), nullable=False),
        sa.Column("model_version_id", sa.Uuid(), nullable=False),
        sa.Column("method", sa.String(length=32), nullable=False),
        sa.Column("fitted_on", sa.String(length=32), nullable=False),
        sa.Column("dataset_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("parameters", _json(), nullable=False),
        sa.Column("metrics", _json(), nullable=False),
        sa.Column("created_at", fraud_ai.database.base.UTCDateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "fitted_on <> 'test'", name=op.f("ck_model_calibrations_never_fitted_on_test")
        ),
        sa.ForeignKeyConstraint(
            ["model_version_id"],
            ["model_versions.model_version_id"],
            name=op.f("fk_model_calibrations_model_version_id_model_versions"),
        ),
        sa.PrimaryKeyConstraint("calibration_id", name=op.f("pk_model_calibrations")),
        sa.UniqueConstraint(
            "model_version_id",
            "method",
            "dataset_fingerprint",
            name=op.f("uq_model_calibrations_model_version_id_method_dataset_fingerprint"),
        ),
    )


def downgrade() -> None:
    op.drop_table("model_calibrations")
