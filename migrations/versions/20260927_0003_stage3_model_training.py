"""Stage 3 model training: reproducibility metadata and snapshot-linked predictions.

* ``model_versions``: dataset and feature-catalogue fingerprints, preprocessing version,
  split row counts, random seed, hyperparameters, training manifest (Python and library
  versions), artefact SHA-256 and the evaluation threshold. Nullable so that rows written
  before 0003 remain valid; the Stage 3 training pipeline always fills them.
* ``model_predictions.feature_snapshot_id``: FK to the exact persisted feature vector.
* ``uq_model_predictions_event_id_model_name_model_version``: one prediction per event per
  model version, so a historical prediction can never be silently replaced.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-27 09:00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json() -> sa.types.TypeEngine[object]:
    return sa.JSON().with_variant(sa.dialects.postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("model_versions") as batch_op:
        batch_op.add_column(sa.Column("dataset_fingerprint", sa.String(64), nullable=True))
        batch_op.add_column(
            sa.Column("feature_catalogue_fingerprint", sa.String(64), nullable=True)
        )
        batch_op.add_column(sa.Column("preprocessing_version", sa.String(50), nullable=True))
        batch_op.add_column(sa.Column("train_rows", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("validation_rows", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("test_rows", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("random_seed", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("hyperparameters", _json(), nullable=True))
        batch_op.add_column(sa.Column("training_manifest", _json(), nullable=True))
        batch_op.add_column(sa.Column("artifact_sha256", sa.String(64), nullable=True))
        batch_op.add_column(sa.Column("default_threshold", sa.Float(), nullable=True))
    with op.batch_alter_table("model_predictions") as batch_op:
        batch_op.add_column(sa.Column("feature_snapshot_id", sa.Uuid(), nullable=True))
        batch_op.create_foreign_key(
            op.f("fk_model_predictions_feature_snapshot_id_feature_snapshots"),
            "feature_snapshots",
            ["feature_snapshot_id"],
            ["snapshot_id"],
        )
        batch_op.create_unique_constraint(
            op.f("uq_model_predictions_event_id_model_name_model_version"),
            ["event_id", "model_name", "model_version"],
        )


def downgrade() -> None:
    with op.batch_alter_table("model_predictions") as batch_op:
        batch_op.drop_constraint(
            op.f("uq_model_predictions_event_id_model_name_model_version"), type_="unique"
        )
        batch_op.drop_constraint(
            op.f("fk_model_predictions_feature_snapshot_id_feature_snapshots"),
            type_="foreignkey",
        )
        batch_op.drop_column("feature_snapshot_id")
    with op.batch_alter_table("model_versions") as batch_op:
        for column in (
            "default_threshold",
            "artifact_sha256",
            "training_manifest",
            "hyperparameters",
            "random_seed",
            "test_rows",
            "validation_rows",
            "train_rows",
            "preprocessing_version",
            "feature_catalogue_fingerprint",
            "dataset_fingerprint",
        ):
            batch_op.drop_column(column)
