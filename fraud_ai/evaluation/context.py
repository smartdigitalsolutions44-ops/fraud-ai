"""Evaluation context: one dataset, one split, one or more models, scored once.

Every evaluation report is built from the *recorded* dataset and split of the model(s)
(rebuilt from the training manifest). All models in a context must share the same dataset
fingerprint, so comparisons are always on exactly the same examples.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field, replace
from typing import Any

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import ModelVersion, User
from fraud_ai.evaluation.stats import Array, IntArray
from fraud_ai.models.base import FraudModel
from fraud_ai.models.factory import is_anomaly_model
from fraud_ai.models.registry import resolve_model
from fraud_ai.models.scoring import load_registered_model
from fraud_ai.models.training import PreparedData, config_from_manifest, prepare_data
from fraud_ai.sequences.definition import SequenceDefinition

SPLITS = ("train", "validation", "test")
EVALUATION_VERSION = "evaluation-1.0.0"


class EvaluationError(FraudAIError):
    pass


def pseudonym(event_id: uuid.UUID) -> str:
    """Stable report identifier; the internal event id never appears in reports."""
    return "ex-" + hashlib.sha256(f"fraud-ai-evaluation:{event_id}".encode()).hexdigest()[:16]


@dataclass
class ScoredModel:
    record: ModelVersion
    model: FraudModel
    scores: dict[str, Array] = field(default_factory=dict)

    @property
    def model_id(self) -> str:
        return f"{self.record.model_name}-{self.record.model_version}"

    @property
    def threshold(self) -> float:
        return self.record.default_threshold if self.record.default_threshold is not None else 0.5


@dataclass
class EvaluationContext:
    prepared: PreparedData
    models: list[ScoredModel]
    scenarios: list[str]  # per example (dataset order)
    fraud_types: list[str | None]

    @property
    def fingerprint(self) -> str:
        return self.prepared.fingerprint

    def indices(self, split: str) -> list[int]:
        return list(getattr(self.prepared.split, split))

    def labels(self, split: str) -> IntArray:
        return np.asarray(self.prepared.y[self.indices(split)], dtype=int)

    def vectors(self, split: str) -> list[Any]:
        examples = self.prepared.dataset.examples
        return [examples[i].vector for i in self.indices(split)]

    def amounts(self, split: str, divisor: float = 100.0) -> Array:
        """Transaction amounts in major units (minor units / 100; 2-dp currencies)."""
        out = []
        for v in self.vectors(split):
            value = v.values.get("transaction_amount_minor_units")
            out.append(float(value) / divisor if isinstance(value, int) else 0.0)
        return np.asarray(out, dtype=np.float64)

    def model(self, ref: str) -> ScoredModel:
        for m in self.models:
            if m.model_id == ref:
                return m
        raise EvaluationError(f"{ref} is not part of this evaluation")

    def header(self, report: str, **extra: Any) -> dict[str, Any]:
        return {
            "report": report,
            "evaluation_version": EVALUATION_VERSION,
            "models": [m.model_id for m in self.models],
            "dataset_fingerprint": self.fingerprint,
            "feature_version": self.prepared.matrix.feature_version,
            "split_sizes": self.prepared.split.sizes(),
            "data_note": "Results describe this dataset only. With the bundled generator it is "
            "SYNTHETIC: no real-world detection rate, loss or saving is implied.",
            **extra,
        }


def build_context(
    session: Session, refs: list[str], *, allow_anomaly: bool = False
) -> EvaluationContext:
    """``allow_anomaly`` admits anomaly-score models; fraud reports and comparisons leave
    it off so an anomaly score is never read as a fraud probability."""
    if not refs:
        raise EvaluationError("no models given")
    records = [resolve_model(session, r) for r in refs]
    if not allow_anomaly and (bad := [r for r in records if is_anomaly_model(r.model_name)]):
        raise EvaluationError(
            f"{bad[0].model_name}-{bad[0].model_version} outputs anomaly scores, not fraud "
            "probabilities; use `fraud-ai anomaly evaluate`"
        )
    fingerprints = {r.dataset_fingerprint for r in records}
    if len(fingerprints) != 1:
        raise EvaluationError(
            "models were trained on different datasets; they cannot be "
            "compared on the same examples"
        )
    manifest = records[0].training_manifest
    if not manifest:
        raise EvaluationError(f"{refs[0]} has no training manifest")
    # Sequence models need the point-in-time sequences their definition describes; tabular
    # models ignore them. All sequence models in one context must share one definition.
    datasets = [(r.training_manifest or {}).get("dataset", {}) for r in records]
    definitions = {d["sequence"]["fingerprint"]: d for d in datasets if d.get("sequence")}
    if len(definitions) > 1:
        raise EvaluationError(
            "sequence models use different sequence definitions; compare "
            "models built on the same definition"
        )
    config = config_from_manifest(manifest)
    recorded_digest = None
    if definitions:
        dataset = next(iter(definitions.values()))
        config = replace(config, sequence=SequenceDefinition.from_dict(dataset["sequence"]))
        recorded_digest = dataset.get("sequence_digest")
    prepared = prepare_data(session, config)
    if prepared.fingerprint != records[0].dataset_fingerprint:
        raise EvaluationError(
            "the recorded dataset can no longer be reproduced (the data "
            "changed since training); evaluation would not be comparable"
        )
    if recorded_digest is not None and prepared.sequence_digest() != recorded_digest:
        raise EvaluationError(
            "the recorded event sequences can no longer be reproduced; evaluation would not "
            "be comparable"
        )
    models = []
    for record in records:
        loaded = load_registered_model(record)
        scores = {s: loaded.predict_proba(prepared.part(s)[0]) for s in SPLITS}
        models.append(ScoredModel(record, loaded, scores))
    examples = prepared.dataset.examples
    user_ids = {e.vector.user_id for e in examples if e.vector.user_id is not None}
    scenario_of: dict[uuid.UUID, str] = {}
    ids = list(user_ids)
    for i in range(0, len(ids), 500):
        rows = session.execute(
            select(User.user_id, User.synthetic_scenario).where(User.user_id.in_(ids[i : i + 500]))
        )
        scenario_of.update({uid: scen or "unknown" for uid, scen in rows})
    scenarios = [
        scenario_of.get(e.vector.user_id, "unknown") if e.vector.user_id else "anonymous"
        for e in examples
    ]
    fraud_types = []
    for decision in prepared.dataset.labels:
        types = [
            p.fraud_type.value
            for p in decision.provenance
            if p.known_at_cutoff and p.fraud_type is not None
        ]
        fraud_types.append(types[0] if types else None)
    return EvaluationContext(prepared, models, scenarios, fraud_types)
