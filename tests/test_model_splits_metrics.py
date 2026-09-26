from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import numpy as np
import pytest

from fraud_ai.models.metrics import (
    DEFAULT_THRESHOLDS,
    confusion_at,
    evaluate_scores,
    select_threshold,
    threshold_analysis,
)
from fraud_ai.models.splits import SplitConfig, SplitError, time_ordered_split

T = datetime(2026, 1, 1, tzinfo=UTC)


def _times(n: int, dup_every: int = 0) -> list[datetime]:
    return [T + timedelta(hours=(i // dup_every if dup_every else i)) for i in range(n)]


def _check_strict(times: list[datetime], split) -> None:  # type: ignore[no-untyped-def]
    tr = [times[i] for i in split.train]
    va = [times[i] for i in split.validation]
    te = [times[i] for i in split.test]
    assert max(tr) < min(va) and max(va) < min(te)
    assert set(split.train) | set(split.validation) | set(split.test) == set(range(len(times)))


def test_fraction_split_is_time_ordered_and_configurable() -> None:
    times = _times(100)
    ids = [uuid.uuid4() for _ in times]
    shuffled = list(zip(times, ids, strict=True))
    np.random.default_rng(0).shuffle(shuffled)  # input order must not matter
    ts, es = [t for t, _ in shuffled], [e for _, e in shuffled]
    split = time_ordered_split(ts, es, SplitConfig())
    assert split.sizes() == {"train": 70, "validation": 15, "test": 15}
    _check_strict(ts, split)
    other = time_ordered_split(ts, es, SplitConfig(0.5, 0.25))
    assert other.sizes() == {"train": 50, "validation": 25, "test": 25}
    assert split.boundaries["train_end"] < split.boundaries["validation_start"]


def test_ties_never_straddle_a_boundary() -> None:
    times = _times(100, dup_every=4)  # groups of 4 identical timestamps
    split = time_ordered_split(times, [uuid.uuid4() for _ in times], SplitConfig())
    _check_strict(times, split)


def test_date_split() -> None:
    times = _times(48)
    config = SplitConfig(train_end=T + timedelta(hours=30), validation_end=T + timedelta(hours=40))
    split = time_ordered_split(times, [uuid.uuid4() for _ in times], config)
    assert split.sizes() == {"train": 30, "validation": 10, "test": 8}
    _check_strict(times, split)
    assert config.describe()["strategy"] == "date"


def test_split_validation() -> None:
    for bad in (
        dict(train_fraction=0.9, validation_fraction=0.2),
        dict(train_fraction=0.0),
        dict(train_end=T),
        dict(train_end=T, validation_end=T),
    ):
        with pytest.raises(SplitError):
            SplitConfig(**bad)  # type: ignore[arg-type]
    with pytest.raises(SplitError, match="empty"):
        time_ordered_split(_times(2), [uuid.uuid4(), uuid.uuid4()], SplitConfig())
    with pytest.raises(SplitError, match="empty"):
        time_ordered_split(
            _times(5),
            [uuid.uuid4() for _ in range(5)],
            SplitConfig(train_end=T - timedelta(days=2), validation_end=T),
        )
    with pytest.raises(SplitError, match="length"):
        time_ordered_split(_times(3), [uuid.uuid4()], SplitConfig())


Y = np.array([1, 1, 1, 0, 0, 0, 0, 0, 0, 0])
P = np.array([0.95, 0.7, 0.3, 0.8, 0.4, 0.2, 0.1, 0.1, 0.05, 0.0])


def test_confusion_and_rates() -> None:
    row = confusion_at(Y, P, 0.5)
    assert (row.tp, row.fp, row.tn, row.fn) == (2, 1, 6, 1)
    assert row.precision == pytest.approx(2 / 3) and row.recall == pytest.approx(2 / 3)
    assert row.fpr == pytest.approx(1 / 7) and row.fnr == pytest.approx(1 / 3)
    assert row.tnr == pytest.approx(6 / 7) and row.tpr == row.recall
    assert row.f1 == pytest.approx(2 / 3) and row.flagged_rate == pytest.approx(0.3)


def test_undefined_ratios_are_none_not_zero() -> None:
    row = confusion_at(Y, P, 0.99)  # nothing flagged
    assert row.precision is None and row.f1 is None and row.recall == 0.0
    metrics = evaluate_scores(np.zeros(4, dtype=int), np.array([0.1, 0.2, 0.3, 0.4]), 0.5)
    assert metrics["pr_auc"] is None and metrics["roc_auc"] is None and metrics["recall"] is None


def test_evaluate_scores_and_threshold_analysis() -> None:
    m = evaluate_scores(Y, P, 0.5)
    assert m["confusion_matrix"] == [[6, 1], [1, 2]]
    assert 0 < m["pr_auc"] <= 1 and 0 < m["roc_auc"] <= 1 and m["prevalence"] == 0.3
    analysis = threshold_analysis(Y, P)
    assert [r.threshold for r in analysis.rows] == list(DEFAULT_THRESHOLDS)
    assert analysis.at(0.5).tp == 2 and len(analysis.to_list()) == len(DEFAULT_THRESHOLDS)
    recalls = [r.recall for r in analysis.rows]
    assert recalls == sorted(recalls, reverse=True)  # recall never rises with the threshold
    with pytest.raises(KeyError):
        analysis.at(0.33)
    selected = select_threshold(Y, P)
    assert selected is not None and 0.25 <= selected <= 0.7
    assert select_threshold(np.zeros(3, dtype=int), np.array([0.1, 0.2, 0.3])) is None
