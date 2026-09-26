"""Time-ordered dataset splits.

Fraud data is temporal: a model is always trained on the past and used on the future, so
evaluation must look the same. Random shuffling would let the model learn from events that
happen *after* the ones it is evaluated on. Two strategies:

* **fraction** (default): sort by (event time, event id) and take the oldest
  ``train_fraction`` for training, the next ``validation_fraction`` for validation and the
  rest for testing. Cut points move forward past equal timestamps, so the ordering
  ``max(train) < min(validation)`` and ``max(validation) < min(test)`` is strict.
* **date**: ``train < train_end <= validation < validation_end <= test``.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.utils.time import ensure_utc


class SplitError(FraudAIError):
    pass


@dataclass(frozen=True)
class SplitConfig:
    train_fraction: float = 0.70
    validation_fraction: float = 0.15
    train_end: datetime | None = None
    validation_end: datetime | None = None

    def __post_init__(self) -> None:
        if (self.train_end is None) != (self.validation_end is None):
            raise SplitError("date split needs both train_end and validation_end")
        if self.train_end is not None and self.validation_end is not None:
            if ensure_utc(self.train_end) >= ensure_utc(self.validation_end):
                raise SplitError("train_end must precede validation_end")
        elif not (
            0 < self.train_fraction < 1
            and 0 < self.validation_fraction < 1
            and self.train_fraction + self.validation_fraction < 1
        ):
            raise SplitError("fractions must be in (0, 1) and leave room for a test split")

    @property
    def strategy(self) -> str:
        return "date" if self.train_end is not None else "fraction"

    def describe(self) -> dict[str, Any]:
        if self.strategy == "date":
            assert self.train_end is not None and self.validation_end is not None
            return {
                "strategy": "date",
                "train_end": ensure_utc(self.train_end).isoformat(),
                "validation_end": ensure_utc(self.validation_end).isoformat(),
            }
        return {
            "strategy": "fraction",
            "train_fraction": self.train_fraction,
            "validation_fraction": self.validation_fraction,
            "test_fraction": round(1 - self.train_fraction - self.validation_fraction, 10),
        }


@dataclass(frozen=True)
class DatasetSplit:
    train: tuple[int, ...]
    validation: tuple[int, ...]
    test: tuple[int, ...]
    boundaries: dict[str, str]

    def sizes(self) -> dict[str, int]:
        return {
            "train": len(self.train),
            "validation": len(self.validation),
            "test": len(self.test),
        }


def _advance_past_ties(order: list[int], times: Sequence[datetime], cut: int) -> int:
    while 0 < cut < len(order) and times[order[cut]] == times[order[cut - 1]]:
        cut += 1
    return cut


def time_ordered_split(
    times: Sequence[datetime], event_ids: Sequence[uuid.UUID], config: SplitConfig
) -> DatasetSplit:
    if len(times) != len(event_ids):
        raise SplitError("times and event_ids differ in length")
    utc = [ensure_utc(t) for t in times]
    order = sorted(range(len(utc)), key=lambda i: (utc[i], str(event_ids[i])))
    if config.strategy == "date":
        assert config.train_end is not None and config.validation_end is not None
        t1, t2 = ensure_utc(config.train_end), ensure_utc(config.validation_end)
        train = [i for i in order if utc[i] < t1]
        validation = [i for i in order if t1 <= utc[i] < t2]
        test = [i for i in order if utc[i] >= t2]
    else:
        n = len(order)
        cut1 = _advance_past_ties(order, utc, round(n * config.train_fraction))
        cut2 = round(n * (config.train_fraction + config.validation_fraction))
        cut2 = _advance_past_ties(order, utc, max(cut2, cut1 + 1))
        train, validation, test = order[:cut1], order[cut1:cut2], order[cut2:]
    for name, part in (("train", train), ("validation", validation), ("test", test)):
        if not part:
            raise SplitError(f"{name} split is empty ({len(times)} examples)")
    boundaries = {
        f"{name}_{edge}": utc[part[pos]].isoformat()
        for name, part in (("train", train), ("validation", validation), ("test", test))
        for edge, pos in (("start", 0), ("end", -1))
    }
    return DatasetSplit(tuple(train), tuple(validation), tuple(test), boundaries)
