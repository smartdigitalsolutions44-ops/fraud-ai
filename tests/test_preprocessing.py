from __future__ import annotations

import json
from dataclasses import replace

import numpy as np
import pytest

from fraud_ai.features.vector import MissingReason as R
from fraud_ai.models.matrix import FeatureVersionMismatchError, ModelMatrix
from fraud_ai.models.preprocessing import (
    OTHER,
    PREPROCESSING_VERSION,
    PreprocessingConfig,
    PreprocessingError,
    Preprocessor,
)
from tests.model_helpers import FS, make_vector


def _matrix(rows: list[dict]) -> ModelMatrix:  # type: ignore[type-arg]
    return ModelMatrix.from_vectors([make_vector(r, seed=i) for i, r in enumerate(rows)])


def _fit(rows: list[dict], **config: bool) -> tuple[Preprocessor, np.ndarray]:  # type: ignore[type-arg]
    m = _matrix(rows)
    pre = Preprocessor(PreprocessingConfig(**config), FS.version).fit(m)
    return pre, pre.transform(m)


def _col(pre: Preprocessor, X: np.ndarray, name: str) -> list[float]:  # type: ignore[type-arg]
    return list(X[:, pre.output_columns.index(name)])


def test_numeric_imputation_uses_training_median_and_keeps_reasons() -> None:
    rows = [
        {"account_age_days": 10.0},
        {"account_age_days": 30.0},
        {"account_age_days": 50.0},
        {"account_age_days": R.UNKNOWN},
        {"account_age_days": R.NOT_OBSERVED},
        {"account_age_days": R.NOT_APPLICABLE},
    ]
    pre, X = _fit(rows, drop_constant_columns=False)
    assert _col(pre, X, "account_age_days") == [10.0, 30.0, 50.0, 30.0, 30.0, 30.0]  # not 0
    assert _col(pre, X, "account_age_days__unknown") == [0, 0, 0, 1, 0, 0]
    assert _col(pre, X, "account_age_days__not_observed") == [0, 0, 0, 0, 1, 0]
    assert _col(pre, X, "account_age_days__not_applicable") == [0, 0, 0, 0, 0, 1]


def test_boolean_and_categorical_one_hot_with_missing_categories() -> None:
    rows = [
        {"vpn_detected": True, "network_type": "mobile"},
        {"vpn_detected": False, "network_type": R.UNKNOWN},
        {"vpn_detected": R.NOT_OBSERVED, "network_type": "residential"},
        {"vpn_detected": R.UNKNOWN, "network_type": R.NOT_OBSERVED},
    ]
    pre, X = _fit(rows, drop_constant_columns=False)
    assert _col(pre, X, "vpn_detected=true") == [1, 0, 0, 0]
    assert _col(pre, X, "vpn_detected=false") == [0, 1, 0, 0]
    assert _col(pre, X, "vpn_detected=not_observed") == [0, 0, 1, 0]
    assert _col(pre, X, "vpn_detected=unknown") == [0, 0, 0, 1]
    assert _col(pre, X, "network_type=unknown") == [0, 1, 0, 0]
    assert _col(pre, X, "network_type=not_observed") == [0, 0, 0, 1]
    # Unseen open-vocabulary categories go to an explicit "other" bucket.
    train = _matrix([{"transaction_currency": "GBP"}, {"transaction_currency": "EUR"}])
    pre2 = Preprocessor(PreprocessingConfig(drop_constant_columns=False), FS.version).fit(train)
    X2 = pre2.transform(_matrix([{"transaction_currency": "JPY"}]))
    assert X2[0, pre2.output_columns.index(f"transaction_currency={OTHER}")] == 1.0


def test_log_and_standardise_and_constant_drop() -> None:
    rows = [{"transaction_amount_minor_units": v} for v in (0, 99, 9999)]
    pre, X = _fit(rows, log_transform=True, standardize=True)
    col = _col(pre, X, "transaction_amount_minor_units")
    assert abs(float(np.mean(col))) < 1e-9 and abs(float(np.std(col)) - 1.0) < 1e-9
    assert col[0] < col[1] < col[2]
    assert "event_kind=transaction" not in pre.output_columns  # constant -> dropped
    assert "event_kind=transaction" in pre.state["dropped"]  # type: ignore[index]


def test_column_order_is_deterministic_and_follows_feature_set() -> None:
    pre, _ = _fit([{}, {"account_age_days": 3.0}])
    pre2, _ = _fit([{}, {"account_age_days": 3.0}])
    assert pre.output_columns == pre2.output_columns
    bases = list(dict.fromkeys(pre.base_feature(c) for c in pre.output_columns))
    assert bases == [n for n in FS.names if n in set(bases)]


def test_json_round_trip_reproduces_transform_exactly() -> None:
    rows = [
        {"account_age_days": float(i), "network_type": "mobile" if i % 2 else R.UNKNOWN}
        for i in range(6)
    ]
    pre, X = _fit(rows, log_transform=True, standardize=True)
    loaded = Preprocessor.from_dict(json.loads(pre.to_json()))
    assert np.array_equal(loaded.transform(_matrix(rows)), X)
    assert loaded.fingerprint() == pre.fingerprint()
    assert loaded.config.version == PREPROCESSING_VERSION


def test_incompatible_preprocessing_and_catalogue_refused() -> None:
    pre, _ = _fit([{}, {"account_age_days": 1.0}])
    data = json.loads(pre.to_json())
    with pytest.raises(PreprocessingError, match="this build supports"):
        Preprocessor.from_dict({**data, "config": {**data["config"], "version": "preprocessing-9"}})
    with pytest.raises(FeatureVersionMismatchError, match="different"):
        Preprocessor.from_dict({**data, "catalogue_fingerprint": "f" * 64})
    with pytest.raises(FeatureVersionMismatchError, match="order"):
        Preprocessor.from_dict({**data, "feature_names": list(reversed(data["feature_names"]))})
    with pytest.raises(PreprocessingError):
        Preprocessor(replace(PreprocessingConfig(), version="nope"), FS.version)
    unfitted = Preprocessor(PreprocessingConfig(), FS.version)
    for call in (
        lambda: unfitted.transform(_matrix([{}])),
        lambda: unfitted.output_columns,
        unfitted.to_dict,
    ):
        with pytest.raises(PreprocessingError, match="not fitted"):
            call()
