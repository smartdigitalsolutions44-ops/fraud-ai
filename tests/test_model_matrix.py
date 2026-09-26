from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from fraud_ai.features.definitions import get_feature_set
from fraud_ai.features.vector import MissingReason
from fraud_ai.models.matrix import (
    FeatureVersionMismatchError,
    LeakageError,
    ModelMatrix,
    assert_safe_feature_names,
    forbidden_reason,
)
from tests.model_helpers import FS, make_vector, make_vectors


def _record() -> dict[str, Any]:
    v = make_vector()
    return {n: v.values[n] if n in v.values else v.missing[n] for n in FS.names}


def test_every_released_feature_is_a_safe_column() -> None:
    assert_safe_feature_names(FS.names, FS.version)
    assert all(forbidden_reason(n) is None for n in FS.names)


@pytest.mark.parametrize(
    "column",
    [
        "event_id",
        "user_id",
        "transaction_id",
        "login_event_id",
        "snapshot_id",
        "id",
        "occurred_at",
        "labelled_at",
        "as_of_timestamp",
        "event_timestamp",
        "feature_hash",
        "label",
        "label_source",
        "is_fraud",
        "fraud_type",
        "provenance",
        "status",
        "y",
    ],
)
def test_metadata_columns_cannot_enter_the_matrix(column: str) -> None:
    assert forbidden_reason(column) is not None
    with pytest.raises(LeakageError):
        ModelMatrix.from_records([{**_record(), column: 1}], FS.version)


def test_unknown_feature_names_rejected() -> None:
    with pytest.raises(LeakageError, match="not a feature"):
        ModelMatrix.from_records([{**_record(), "shoe_size": 42}], FS.version)
    with pytest.raises(LeakageError, match="lacks"):
        ModelMatrix.from_records(
            [{k: v for k, v in _record().items() if k != "account_age_days"}], FS.version
        )


def test_from_vectors_reads_only_feature_values() -> None:
    vectors, _ = make_vectors(4)
    matrix = ModelMatrix.from_vectors(vectors)
    assert matrix.feature_names == FS.names and len(matrix) == 4
    flat = {str(x) for row in matrix.values for x in row}
    for v in vectors:  # no identifier or timestamp is anywhere in the matrix
        assert str(v.event_id) not in flat and v.event_timestamp.isoformat() not in flat
    reasons = {r for row in matrix.missing for r in row if r is not None}
    assert reasons <= set(MissingReason)
    assert len(matrix.take([0, 2])) == 2
    records = ModelMatrix.from_records([_record()], FS.version)
    assert records.feature_names == FS.names


def test_mixed_versions_and_altered_catalogue_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    vectors, _ = make_vectors(2)
    with pytest.raises(FeatureVersionMismatchError, match="mixed"):
        ModelMatrix.from_vectors(vectors, feature_version="fraud-features-9.9.9")
    good = ModelMatrix.from_vectors(vectors)
    with pytest.raises(FeatureVersionMismatchError, match="fingerprint"):
        replace(good, catalogue_fingerprint="0" * 64)
    with pytest.raises(FeatureVersionMismatchError, match="order"):
        replace(good, feature_names=tuple(reversed(good.feature_names)))
    # A catalogue edited without a version bump no longer matches existing matrices.
    import fraud_ai.models.matrix as matrix_module

    real = get_feature_set(FS.version)
    monkeypatch.setattr(
        matrix_module,
        "get_feature_set",
        lambda v=None: replace(real, parameters={**real.parameters, "x": 1}),
    )
    with pytest.raises(FeatureVersionMismatchError):
        ModelMatrix(
            good.feature_version,
            good.catalogue_fingerprint,
            good.feature_names,
            good.values,
            good.missing,
        )
