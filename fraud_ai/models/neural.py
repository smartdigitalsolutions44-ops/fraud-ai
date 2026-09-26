"""Feed-forward neural network for tabular fraud classification (PyTorch).

Architecture (configurable; default ``input -> 128 -> 64 -> 32 -> 1``)::

    input -> [Linear -> LayerNorm -> ReLU -> Dropout] x len(hidden_sizes) -> Linear -> logit

* **Input** is the Stage 3 deterministic preprocessing (``preprocessing-1.0.0``) in the
  same configuration as the logistic baseline:
  * heavy-tailed units are signed-log transformed;
  * numeric values are imputed with the training median and standardised;
  * one-hot categories are kept;
  * the three missing reasons (``unknown``, ``not_observed``, ``not_applicable``) stay as
    separate indicator columns.

  The feature order, feature version, catalogue fingerprint and preprocessing version are
  therefore the ones the baselines use. Incompatible inputs are refused.
* **LayerNorm, not BatchNorm, by default.** LayerNorm normalises each row on its own, so
  a single-event prediction equals the same row scored in a batch. BatchNorm makes
  training depend on batch composition, which is awkward when fraud is about 1% of rows.
  Both are available (``normalization``).
* **Imbalance.** The loss is ``BCEWithLogitsLoss(pos_weight = negatives / positives)``.
  Focal loss (same weighting, times ``(1 - p_t) ** gamma``) is available for experiments
  and is not the default. Oversampling is available but is not the default.
* **Optimiser.** AdamW with a constant learning rate; no scheduler (not justified yet).
* **Training loop:**
  * seeded mini-batch shuffling and gradient-norm clipping;
  * per-epoch history: train loss, validation loss, train and validation PR-AUC,
    validation ROC-AUC, learning rate;
  * **early stopping on validation PR-AUC** (patience, minimum improvement);
  * the best checkpoint is restored.

  PR-AUC is the selection metric because it is what the project evaluates, and because
  validation loss under class weighting rewards over-confident scores. If the validation
  split has only one class, PR-AUC is undefined and validation loss is used instead; the
  history records which was used.
* **The test split** is never seen by training, early stopping or model selection.
"""

from __future__ import annotations

import copy
import json
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt
import torch
import torch.nn.functional as F
from sklearn.metrics import average_precision_score, roc_auc_score
from torch import nn

from fraud_ai.features.definitions import DEFAULT_FEATURE_VERSION
from fraud_ai.models.base import EvaluationResult, FraudModel, Labels, Validation
from fraud_ai.models.inspection import grouped_permutation_importance
from fraud_ai.models.matrix import ModelMatrix
from fraud_ai.models.metrics import evaluate_scores
from fraud_ai.models.preprocessing import PreprocessingConfig, Preprocessor
from fraud_ai.models.torch_support import (
    TorchModelError,
    deterministic,
    digest_files,
    environment,
    load_state,
    parameter_count,
    resolve_device,
    save_state,
    verify_digest,
    write_hashes,
)

MODEL_NAME = "neural-network"
ALGORITHM = "torch.FeedForward"
PREPROCESSING = PreprocessingConfig(log_transform=True, standardize=True)
ACTIVATIONS = ("relu", "gelu")
NORMALIZATIONS = ("layernorm", "batchnorm", "none")
LOSSES = ("weighted_bce", "focal")
IMBALANCE = ("class_weight", "oversample", "none")
WEIGHTS_FILE, CONFIG_FILE, PREPROCESSOR_FILE = "model.pt", "config.json", "preprocessing.json"
HISTORY_FILE, MANIFEST_FILE = "history.json", "manifest.json"
DIGEST_FILES = (WEIGHTS_FILE, CONFIG_FILE, PREPROCESSOR_FILE)
PREDICT_BATCH = 4096

Array = npt.NDArray[np.float64]


class NeuralModelError(TorchModelError):
    pass


@dataclass(frozen=True)
class NeuralConfig:
    hidden_sizes: tuple[int, ...] = (128, 64, 32)
    activation: str = "relu"
    normalization: str = "layernorm"
    dropout: float = 0.3
    batch_size: int = 256
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    max_epochs: int = 60
    patience: int = 8
    min_delta: float = 1e-4
    loss: str = "weighted_bce"
    focal_gamma: float = 2.0
    grad_clip: float = 1.0
    holdout_fraction: float = 0.15  # only when no validation split is given
    # Standardised inputs are clipped to +/- input_clip before the network: features that are
    # rarely observed get tiny training spreads, so their z-scores can reach the hundreds and
    # dominate activations (and reconstruction error). The Stage 3 preprocessing is unchanged.
    input_clip: float = 10.0
    device: str = "cpu"
    optimizer: str = field(default="AdamW", init=False)

    def __post_init__(self) -> None:
        if not self.hidden_sizes or any(h < 1 for h in self.hidden_sizes):
            raise NeuralModelError("hidden_sizes must be positive integers")
        if self.activation not in ACTIVATIONS:
            raise NeuralModelError(f"activation must be one of {ACTIVATIONS}")
        if self.normalization not in NORMALIZATIONS:
            raise NeuralModelError(f"normalization must be one of {NORMALIZATIONS}")
        if self.loss not in LOSSES:
            raise NeuralModelError(f"loss must be one of {LOSSES}")
        if not 0.0 <= self.dropout < 1.0:
            raise NeuralModelError("dropout must be in [0, 1)")
        if self.batch_size < 1 or self.max_epochs < 1 or self.patience < 1:
            raise NeuralModelError("batch_size, max_epochs and patience must be >= 1")
        if self.learning_rate <= 0 or self.weight_decay < 0 or self.grad_clip <= 0:
            raise NeuralModelError("learning_rate and grad_clip must be > 0, weight_decay >= 0")
        if not 0.0 < self.holdout_fraction < 0.5:
            raise NeuralModelError("holdout_fraction must be in (0, 0.5)")

        if self.input_clip <= 0:
            raise NeuralModelError("input_clip must be > 0")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["hidden_sizes"] = list(self.hidden_sizes)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> NeuralConfig:
        data = dict(data or {})
        data.pop("optimizer", None)
        known = {f.name for f in fields(cls) if f.init}
        if unknown := set(data) - known:
            raise NeuralModelError(f"unknown neural hyperparameters {sorted(unknown)}")
        if "hidden_sizes" in data:
            data["hidden_sizes"] = tuple(int(h) for h in data["hidden_sizes"])
        return cls(**data)


def build_network(input_dim: int, config: NeuralConfig) -> nn.Sequential:
    layers: list[nn.Module] = []
    width = input_dim
    for hidden in config.hidden_sizes:
        layers.append(nn.Linear(width, hidden))
        if config.normalization == "layernorm":
            layers.append(nn.LayerNorm(hidden))
        elif config.normalization == "batchnorm":
            layers.append(nn.BatchNorm1d(hidden))
        layers.append(nn.ReLU() if config.activation == "relu" else nn.GELU())
        if config.dropout > 0:
            layers.append(nn.Dropout(config.dropout))
        width = hidden
    layers.append(nn.Linear(width, 1))
    return nn.Sequential(*layers)


def fraud_loss(
    logits: torch.Tensor,
    targets: torch.Tensor,
    pos_weight: torch.Tensor,
    config: NeuralConfig,
) -> torch.Tensor:
    """Weighted BCE on logits; focal loss multiplies it by ``(1 - p_t) ** gamma``."""
    per_row = F.binary_cross_entropy_with_logits(
        logits, targets, pos_weight=pos_weight, reduction="none"
    )
    if config.loss == "focal":
        p = torch.sigmoid(logits)
        p_t = torch.where(targets > 0.5, p, 1 - p)
        per_row = per_row * (1 - p_t) ** config.focal_gamma
    return per_row.mean()


def _pr_roc(y: npt.NDArray[np.int_], p: Array) -> tuple[float | None, float | None]:
    if 0 < int(y.sum()) < len(y):
        return float(average_precision_score(y, p)), float(roc_auc_score(y, p))
    return None, None


class NeuralNetworkModel(FraudModel):
    model_name = MODEL_NAME

    def __init__(
        self,
        version: str = "1.0.0",
        *,
        seed: int = 42,
        imbalance: str = "class_weight",
        hyperparameters: dict[str, Any] | None = None,
        feature_version: str = DEFAULT_FEATURE_VERSION,
        oversample_ratio: float = 0.25,
    ) -> None:
        if imbalance not in IMBALANCE:
            raise NeuralModelError(f"imbalance must be one of {IMBALANCE}")
        self.version = version
        self.seed = seed
        self.imbalance = imbalance
        self.oversample_ratio = oversample_ratio
        self.feature_version = feature_version
        self.config = NeuralConfig.from_dict(hyperparameters)
        self.hyperparameters = self.config.to_dict()
        self.preprocessor = Preprocessor(PREPROCESSING, feature_version)
        self.device = resolve_device(self.config.device)
        self.network: nn.Sequential | None = None
        self.train_seconds: float | None = None
        self.history: list[dict[str, Any]] = []
        self.training_summary: dict[str, Any] = {}

    @property
    def algorithm(self) -> str:
        return ALGORITHM

    @property
    def parameter_count(self) -> int:
        if self.network is None:
            raise NeuralModelError("model is not trained")
        return parameter_count(self.network)

    # ------------------------------------------------------------------ training
    def _training_rows(self, y: npt.NDArray[np.int_]) -> npt.NDArray[np.int_]:
        idx = np.arange(len(y))
        if self.imbalance != "oversample":
            return idx
        pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
        target = int(len(neg) * self.oversample_ratio)
        if len(pos) == 0 or target <= len(pos):
            return idx
        rng = np.random.default_rng(self.seed)
        return np.concatenate([idx, rng.choice(pos, size=target - len(pos), replace=True)])

    def _split_validation(
        self, matrix: ModelMatrix, y: npt.NDArray[np.int_], validation: Validation | None
    ) -> tuple[ModelMatrix, npt.NDArray[np.int_], ModelMatrix, npt.NDArray[np.int_], str]:
        if validation is not None:
            val_m, val_y = validation
            return matrix, y, val_m, np.asarray(val_y, dtype=int), "validation split"
        # No validation split given (e.g. a caller outside the pipeline): hold out the
        # latest rows of the (time-ordered) training data - never the test split.
        cut = round(len(y) * (1 - self.config.holdout_fraction))
        if cut < 1 or cut >= len(y):
            raise NeuralModelError("too few training rows to hold out a validation tail")
        head, tail = list(range(cut)), list(range(cut, len(y)))
        return (
            matrix.take(head),
            y[:cut],
            matrix.take(tail),
            y[cut:],
            f"latest {self.config.holdout_fraction:.0%} of training rows",
        )

    def train(
        self, matrix: ModelMatrix, labels: Labels, validation: Validation | None = None
    ) -> None:
        y = np.asarray(labels, dtype=int)
        if len(y) != len(matrix):
            raise NeuralModelError("labels and matrix differ in length")
        if len(np.unique(y)) < 2:
            raise NeuralModelError("training data must contain both classes")
        fit_m, fit_y, val_m, val_y, source = self._split_validation(matrix, y, validation)
        if len(np.unique(fit_y)) < 2:
            raise NeuralModelError("training data must contain both classes")
        cfg = self.config
        started = time.perf_counter()
        with deterministic(self.seed):
            self.preprocessor.fit(fit_m)
            X = torch.as_tensor(self.transform(fit_m), dtype=torch.float32)
            Xv = torch.as_tensor(self.transform(val_m), dtype=torch.float32)
            t = torch.as_tensor(fit_y, dtype=torch.float32)
            tv = torch.as_tensor(val_y, dtype=torch.float32)
            positives = float(fit_y.sum())
            weight = (
                (len(fit_y) - positives) / positives if self.imbalance == "class_weight" else 1.0
            )
            pos_weight = torch.tensor(weight, dtype=torch.float32, device=self.device)
            network = build_network(X.shape[1], cfg).to(self.device)
            optimizer = torch.optim.AdamW(
                network.parameters(), lr=cfg.learning_rate, weight_decay=cfg.weight_decay
            )
            rows = torch.as_tensor(self._training_rows(fit_y))
            generator = torch.Generator().manual_seed(self.seed)
            use_pr = 0 < int(val_y.sum()) < len(val_y)
            best_score, best_epoch, stale = -np.inf, 0, 0
            best_state = copy.deepcopy(network.state_dict())
            history: list[dict[str, Any]] = []
            for epoch in range(1, cfg.max_epochs + 1):
                network.train()
                order = rows[torch.randperm(len(rows), generator=generator)]
                total = 0.0
                for start in range(0, len(order), cfg.batch_size):
                    batch = order[start : start + cfg.batch_size]
                    if cfg.normalization == "batchnorm" and len(batch) < 2:
                        continue  # BatchNorm cannot train on a single row
                    xb, yb = X[batch].to(self.device), t[batch].to(self.device)
                    optimizer.zero_grad()
                    loss = fraud_loss(network(xb).squeeze(1), yb, pos_weight, cfg)
                    loss.backward()  # type: ignore[no-untyped-call]
                    nn.utils.clip_grad_norm_(network.parameters(), cfg.grad_clip)
                    optimizer.step()
                    total += float(loss.item()) * len(batch)
                train_p = self._forward(network, X)
                val_logits = self._logits(network, Xv)
                val_loss = float(fraud_loss(val_logits, tv.to(self.device), pos_weight, cfg).item())
                val_p = torch.sigmoid(val_logits).cpu().double().numpy()
                val_pr, val_roc = _pr_roc(val_y, val_p)
                train_pr, _ = _pr_roc(fit_y, train_p)
                score = val_pr if use_pr and val_pr is not None else -val_loss
                improved = score > best_score + cfg.min_delta
                history.append(
                    {
                        "epoch": epoch,
                        "train_loss": total / len(rows),
                        "validation_loss": val_loss,
                        "train_pr_auc": train_pr,
                        "validation_pr_auc": val_pr,
                        "validation_roc_auc": val_roc,
                        "learning_rate": optimizer.param_groups[0]["lr"],
                        "best_so_far": improved,
                    }
                )
                if improved:
                    best_score, best_epoch, stale = score, epoch, 0
                    best_state = copy.deepcopy(network.state_dict())
                else:
                    stale += 1
                    if stale >= cfg.patience:
                        break
            network.load_state_dict(best_state)
            network.eval()
        self.network = network
        self.train_seconds = time.perf_counter() - started
        self.history = history
        self.training_summary = {
            "epochs_completed": len(history),
            "best_epoch": best_epoch,
            "stopped_early": len(history) < cfg.max_epochs,
            "selection_metric": "validation PR-AUC" if use_pr else "validation loss",
            "validation_source": source,
            "validation_rows": len(val_y),
            "validation_positives": int(val_y.sum()),
            "fit_rows": len(fit_y),
            "fit_positives": int(fit_y.sum()),
            "pos_weight": weight,
            "loss": cfg.loss,
            "overfitting_flags": overfitting_flags(history, best_epoch),
        }

    # ------------------------------------------------------------------ inference
    def _logits(self, network: nn.Module, X: torch.Tensor) -> torch.Tensor:
        network.eval()
        outputs = []
        with torch.inference_mode():
            for start in range(0, len(X), PREDICT_BATCH):
                outputs.append(network(X[start : start + PREDICT_BATCH].to(self.device)))
        if not outputs:
            return torch.zeros(0)
        return torch.cat(outputs).squeeze(1)

    def _forward(self, network: nn.Module, X: torch.Tensor) -> Array:
        return np.asarray(
            torch.sigmoid(self._logits(network, X)).cpu().double().numpy(), dtype=np.float64
        )

    def predict_transformed(self, X: Array) -> Array:
        if self.network is None:
            raise NeuralModelError("model is not trained")
        with deterministic():
            return self._forward(self.network, torch.as_tensor(X, dtype=torch.float32))

    def transform(self, matrix: ModelMatrix) -> Array:
        """Stage 3 preprocessing, then the recorded ``input_clip``."""
        clip = self.config.input_clip
        return np.clip(self.preprocessor.transform(matrix), -clip, clip)

    def predict_proba(self, matrix: ModelMatrix) -> Array:
        if self.network is None:
            raise NeuralModelError("model is not trained")
        return self.predict_transformed(self.transform(matrix))

    def evaluate(
        self, matrix: ModelMatrix, labels: Labels, threshold: float = 0.5
    ) -> EvaluationResult:
        metrics = evaluate_scores(labels, self.predict_proba(matrix), threshold)
        return EvaluationResult(metrics, len(matrix), threshold)

    # ------------------------------------------------------------------ inspection
    def architecture(self) -> list[str]:
        if self.network is None:
            raise NeuralModelError("model is not trained")
        return [str(layer) for layer in self.network]

    def explain(
        self, matrix: ModelMatrix | None = None, labels: Labels | None = None, top_k: int = 12
    ) -> dict[str, Any]:
        if self.network is None:
            raise NeuralModelError("model is not trained")
        if matrix is None or labels is None:
            return {
                "method": "grouped permutation importance",
                "note": "needs labelled data with both classes",
                "top_features": [],
            }
        return grouped_permutation_importance(
            self.predict_transformed,
            self.transform(matrix),
            labels,
            self.preprocessor.output_columns,
            self.preprocessor.base_feature,
            seed=self.seed,
            top_k=top_k,
        )

    # ------------------------------------------------------------------ persistence
    def manifest(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "model_version": self.version,
            "kind": MODEL_NAME,
            "algorithm": ALGORITHM,
            "feature_version": self.feature_version,
            "catalogue_fingerprint": self.preprocessor.catalogue_fingerprint,
            "preprocessing": asdict(PREPROCESSING),
            "preprocessing_version": PREPROCESSING.version,
            "output_columns": len(self.preprocessor.output_columns),
            "hyperparameters": self.hyperparameters,
            "architecture": self.architecture(),
            "parameter_count": self.parameter_count,
            "optimizer": "AdamW",
            "seed": self.seed,
            "imbalance": self.imbalance,
            "oversample_ratio": self.oversample_ratio,
            "training": self.training_summary,
            "environment": environment(self.device),
        }

    def save(self, directory: Path) -> str:
        if self.network is None:
            raise NeuralModelError("model is not trained")
        if directory.exists():
            raise NeuralModelError(
                f"artefact directory {directory} already exists; refusing to overwrite"
            )
        directory.mkdir(parents=True)
        save_state(self.network, directory / WEIGHTS_FILE)
        config = {
            "hyperparameters": self.hyperparameters,
            "input_dim": len(self.preprocessor.output_columns),
            "seed": self.seed,
            "imbalance": self.imbalance,
            "oversample_ratio": self.oversample_ratio,
            "model_version": self.version,
            "feature_version": self.feature_version,
        }
        (directory / CONFIG_FILE).write_text(json.dumps(config, indent=2, sort_keys=True))
        (directory / PREPROCESSOR_FILE).write_text(self.preprocessor.to_json())
        (directory / HISTORY_FILE).write_text(
            json.dumps({"history": self.history, "summary": self.training_summary}, indent=2)
        )
        digest = digest_files(directory, DIGEST_FILES)
        (directory / MANIFEST_FILE).write_text(
            json.dumps({**self.manifest(), "artifact_sha256": digest}, indent=2, sort_keys=True)
        )
        write_hashes(directory, digest, DIGEST_FILES)
        return digest

    @classmethod
    def load(cls, directory: Path, expected_sha256: str) -> NeuralNetworkModel:
        verify_digest(directory, DIGEST_FILES, expected_sha256)  # before reading any weights
        config = json.loads((directory / CONFIG_FILE).read_text())
        preprocessor = Preprocessor.from_dict(
            json.loads((directory / PREPROCESSOR_FILE).read_text())
        )
        if preprocessor.config != PREPROCESSING:
            raise NeuralModelError("stored preprocessing configuration differs from the model")
        if config["input_dim"] != len(preprocessor.output_columns):
            raise NeuralModelError("stored input width does not match the preprocessing")
        model = cls(
            config["model_version"],
            seed=config["seed"],
            imbalance=config["imbalance"],
            hyperparameters={**config["hyperparameters"], "device": "cpu"},
            feature_version=config["feature_version"],
            oversample_ratio=config["oversample_ratio"],
        )
        model.preprocessor = preprocessor
        network = build_network(config["input_dim"], model.config)
        load_state(network, directory / WEIGHTS_FILE)
        network.eval()
        model.network = network
        if (directory / HISTORY_FILE).exists():
            stored = json.loads((directory / HISTORY_FILE).read_text())
            model.history, model.training_summary = stored["history"], stored["summary"]
        return model


def overfitting_flags(history: list[dict[str, Any]], best_epoch: int) -> list[str]:
    """Warnings derived from the per-epoch history (never hidden by early stopping)."""
    flags: list[str] = []
    if not history or best_epoch < 1:
        return flags
    best = history[best_epoch - 1]
    train_pr, val_pr = best.get("train_pr_auc"), best.get("validation_pr_auc")
    if train_pr is not None and val_pr is not None:
        if train_pr - val_pr > 0.10:
            flags.append(
                f"train/validation PR-AUC gap {train_pr - val_pr:.3f} at the selected epoch "
                f"{best_epoch} (train {train_pr:.3f}, validation {val_pr:.3f})"
            )
        if train_pr >= 0.99:
            flags.append(f"train PR-AUC {train_pr:.3f} at epoch {best_epoch}: possible memorising")
    val_scores = [h["validation_pr_auc"] for h in history if h["validation_pr_auc"] is not None]
    if val_scores and val_pr is not None and val_scores[-1] < val_pr - 0.05:
        flags.append(
            f"validation PR-AUC fell from {val_pr:.3f} (epoch {best_epoch}) to "
            f"{val_scores[-1]:.3f} by the last epoch: later epochs overfit (best restored)"
        )
    losses = [h["validation_loss"] for h in history]
    if len(losses) > best_epoch and min(losses[best_epoch:]) > losses[best_epoch - 1] * 1.25:
        flags.append("validation loss rose by >25% after the selected epoch")
    return flags
