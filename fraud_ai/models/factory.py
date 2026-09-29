"""One place that knows every model kind.

Training, scoring, walk-forward evaluation and the CLI build and load models through
this factory, so a new kind needs no special-casing anywhere else.

* **Supervised kinds** output P(fraud): ``logistic``, ``random-forest``,
  ``gradient-boosting``, ``neural-network`` and the Stage 6 sequence kinds ``gru``,
  ``transformer`` and ``hybrid-gru`` (which also need point-in-time event sequences).
* **Anomaly kinds** output an anomaly score, which is *not* a fraud probability:
  ``autoencoder``. Scoring and fraud-model comparisons refuse them.

PyTorch is imported lazily, so commands that never touch a neural model stay fast.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fraud_ai.features.definitions import DEFAULT_FEATURE_VERSION
from fraud_ai.models.artifact_io import ArtifactBytes
from fraud_ai.models.base import FraudModel
from fraud_ai.models.estimators import SPECS, BaselineModel, ModelError

NEURAL_KIND = "neural-network"
AUTOENCODER_KIND = "autoencoder"
SEQUENCE_KINDS: tuple[str, ...] = ("gru", "transformer", "hybrid-gru")
SUPERVISED_KINDS: tuple[str, ...] = (*SPECS, NEURAL_KIND, *SEQUENCE_KINDS)
ANOMALY_KINDS: tuple[str, ...] = (AUTOENCODER_KIND,)
MODEL_NAMES: dict[str, str] = {
    **{kind: spec.model_name for kind, spec in SPECS.items()},
    NEURAL_KIND: "neural-network",
    AUTOENCODER_KIND: "autoencoder",
    **{kind: kind for kind in SEQUENCE_KINDS},
}
KIND_BY_NAME: dict[str, str] = {name: kind for kind, name in MODEL_NAMES.items()}


def model_name(kind: str) -> str:
    try:
        return MODEL_NAMES[kind]
    except KeyError:
        raise ModelError(f"unknown model kind {kind!r}") from None


def kind_for_name(name: str) -> str:
    try:
        return KIND_BY_NAME[name]
    except KeyError:
        raise ModelError(f"unknown model name {name!r}") from None


def is_anomaly_model(name: str) -> bool:
    return KIND_BY_NAME.get(name) in ANOMALY_KINDS


def is_sequence_kind(kind: str) -> bool:
    return kind in SEQUENCE_KINDS


def build_model(
    kind: str,
    version: str = "1.0.0",
    *,
    seed: int = 42,
    imbalance: str = "class_weight",
    hyperparameters: dict[str, Any] | None = None,
    feature_version: str = DEFAULT_FEATURE_VERSION,
) -> FraudModel:
    if kind in SPECS:
        return BaselineModel(
            SPECS[kind],
            version,
            seed=seed,
            imbalance=imbalance,
            hyperparameters=hyperparameters,
            feature_version=feature_version,
        )
    if kind == NEURAL_KIND:
        from fraud_ai.models.neural import NeuralNetworkModel

        return NeuralNetworkModel(
            version,
            seed=seed,
            imbalance=imbalance,
            hyperparameters=hyperparameters,
            feature_version=feature_version,
        )
    if kind in SEQUENCE_KINDS:
        from fraud_ai.models.sequence_models import SequenceModel

        return SequenceModel(
            kind,
            version,
            seed=seed,
            imbalance=imbalance,
            hyperparameters=hyperparameters,
            feature_version=feature_version,
        )
    if kind == AUTOENCODER_KIND:
        from fraud_ai.models.anomaly import AutoencoderModel

        return AutoencoderModel(
            version,
            seed=seed,
            hyperparameters=hyperparameters,
            feature_version=feature_version,
        )
    raise ModelError(f"unknown model kind {kind!r}")


def load_model(
    kind: str, directory: Path, expected_sha256: str, blob: ArtifactBytes | None = None
) -> FraudModel:
    """Verify the artefact digest, then load (the loaders check before deserialising).

    With ``blob`` (Stage 11) the loader uses exactly those already-read bytes."""
    if kind in SPECS:
        return BaselineModel.load(directory, expected_sha256, blob)
    if kind == NEURAL_KIND:
        from fraud_ai.models.neural import NeuralNetworkModel

        return NeuralNetworkModel.load(directory, expected_sha256, blob)
    if kind in SEQUENCE_KINDS:
        from fraud_ai.models.sequence_models import SequenceModel

        return SequenceModel.load(directory, expected_sha256, blob)
    if kind == AUTOENCODER_KIND:
        from fraud_ai.models.anomaly import AutoencoderModel

        return AutoencoderModel.load(directory, expected_sha256, blob)
    raise ModelError(f"unknown model kind {kind!r}")


def digest_names(kind: str, blob: ArtifactBytes) -> tuple[str, ...]:
    """The files covered by a kind's registered digest (the same lists the savers use)."""
    from fraud_ai.models.estimators import ESTIMATOR_FILE
    from fraud_ai.models.estimators import PREPROCESSOR_FILE as BASELINE_PREPROCESSOR

    if kind in SPECS:
        return (ESTIMATOR_FILE, BASELINE_PREPROCESSOR)
    if kind == NEURAL_KIND:
        from fraud_ai.models.neural import DIGEST_FILES

        return DIGEST_FILES
    if kind == AUTOENCODER_KIND:
        from fraud_ai.models.anomaly import DIGEST_FILES as AUTOENCODER_FILES

        return AUTOENCODER_FILES
    if kind in SEQUENCE_KINDS:
        from fraud_ai.models.sequence_models import CONFIG_FILE, PREPROCESSOR_FILE, WEIGHTS_FILE

        hybrid = blob.has(CONFIG_FILE) and blob.json(CONFIG_FILE).get("kind") == "hybrid-gru"
        return (WEIGHTS_FILE, CONFIG_FILE) + ((PREPROCESSOR_FILE,) if hybrid else ())
    raise ModelError(f"unknown model kind {kind!r}")
