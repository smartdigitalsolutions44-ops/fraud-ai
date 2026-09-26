"""Model inputs that carry both the static feature matrix and the aligned sequences.

:class:`SequenceMatrix` *is* a :class:`~fraud_ai.models.matrix.ModelMatrix`, with the same
leakage guards on the static values, plus one :class:`SequenceBatch` row per matrix row.
Every model therefore receives the same object through the same pipeline:

* tabular models read the static values and ignore the sequences;
* sequence models require them;
* the hybrid model uses both.

Row selection (``take``) keeps the two aligned. Identifiers, timestamps and labels still
live only on the dataset examples, never in either input.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from fraud_ai.models.matrix import ModelMatrix
from fraud_ai.sequences.extraction import SequenceBatch, SequenceError


@dataclass(frozen=True)
class SequenceMatrix(ModelMatrix):
    sequences: SequenceBatch

    def __post_init__(self) -> None:
        super().__post_init__()
        if len(self.sequences) != len(self.values):
            raise SequenceError("sequence and matrix row counts differ")

    @classmethod
    def attach(cls, matrix: ModelMatrix, sequences: SequenceBatch) -> SequenceMatrix:
        return cls(
            matrix.feature_version,
            matrix.catalogue_fingerprint,
            matrix.feature_names,
            matrix.values,
            matrix.missing,
            sequences,
        )

    def take(self, indices: Sequence[int]) -> SequenceMatrix:
        return SequenceMatrix.attach(super().take(indices), self.sequences.take(list(indices)))
