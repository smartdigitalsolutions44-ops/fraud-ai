"""EXPERIMENTAL autoencoder anomaly model: how unusual an event looks, not whether it is fraud.

    input -> encoder (64 -> 32) -> bottleneck (8) -> decoder (32 -> 64) -> reconstruction

* **Legitimate rows only.** The model is trained only on the *legitimate* rows of the
  training split, so it learns what normal behaviour looks like. Fraud rows are excluded
  from fitting, and their number is recorded.
* **Early stopping** uses the reconstruction loss on the legitimate rows of the validation
  split (the test split is never used).
* **Input** is the same Stage 3 preprocessing as the neural classifier: standardised
  numeric values, one-hot categories and the three distinct missing-reason indicators.
* **Output:**
  * the reconstruction error (mean squared error over the transformed columns);
  * an **anomaly score** in [0, 1]: the fraction of *training* legitimate events that
    reconstruct better. 0.99 means "more unusual than 99% of normal training behaviour".
* **The anomaly score is not a fraud probability.** ``score_kind`` is ``anomaly_score``.
  Scoring into ``model_predictions`` and the fraud-model comparisons refuse this model,
  and it is never combined into a production score. Unusual is not the same as
  fraudulent: house movers, new customers and VPN users are unusual too.
"""

from __future__ import annotations

import copy
import itertools
import json
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt
import torch
from torch import nn

from fraud_ai.features.definitions import DEFAULT_FEATURE_VERSION
from fraud_ai.models.artifact_io import ArtifactBytes
from fraud_ai.models.base import ANOMALY_SCORE, EvaluationResult, FraudModel, Labels, Validation
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
    read_verified,
    resolve_device,
    save_state,
    write_hashes,
)

MODEL_NAME = "autoencoder"
ALGORITHM = "torch.Autoencoder (anomaly score - not a fraud probability)"
PREPROCESSING = PreprocessingConfig(log_transform=True, standardize=True)
WEIGHTS_FILE, CONFIG_FILE, PREPROCESSOR_FILE = "model.pt", "config.json", "preprocessing.json"
REFERENCE_FILE, HISTORY_FILE, MANIFEST_FILE = "reference.json", "history.json", "manifest.json"
DIGEST_FILES = (WEIGHTS_FILE, CONFIG_FILE, PREPROCESSOR_FILE, REFERENCE_FILE)
REFERENCE_POINTS = 1001
PREDICT_BATCH = 4096

Array = npt.NDArray[np.float64]


class AnomalyModelError(TorchModelError):
    pass


@dataclass(frozen=True)
class AutoencoderConfig:
    hidden_sizes: tuple[int, ...] = (64, 32)
    bottleneck: int = 8
    activation: str = "relu"
    dropout: float = 0.0
    batch_size: int = 256
    learning_rate: float = 1e-3
    weight_decay: float = 1e-5
    max_epochs: int = 80
    patience: int = 8
    min_delta: float = 1e-5
    grad_clip: float = 1.0
    holdout_fraction: float = 0.15
    # Standardised inputs are clipped to +/- input_clip before the network: features that are
    # rarely observed get tiny training spreads, so their z-scores can reach the hundreds and
    # dominate activations (and reconstruction error). The Stage 3 preprocessing is unchanged.
    input_clip: float = 10.0
    device: str = "cpu"

    def __post_init__(self) -> None:
        if not self.hidden_sizes or min(self.hidden_sizes) < 1 or self.bottleneck < 1:
            raise AnomalyModelError("layer sizes must be positive")
        if self.activation not in ("relu", "gelu"):
            raise AnomalyModelError("activation must be relu or gelu")
        if not 0.0 <= self.dropout < 1.0:
            raise AnomalyModelError("dropout must be in [0, 1)")
        if self.batch_size < 1 or self.max_epochs < 1 or self.patience < 1:
            raise AnomalyModelError("batch_size, max_epochs and patience must be >= 1")

        if self.input_clip <= 0:
            raise AnomalyModelError("input_clip must be > 0")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["hidden_sizes"] = list(self.hidden_sizes)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AutoencoderConfig:
        data = dict(data or {})
        known = {f.name for f in fields(cls)}
        if unknown := set(data) - known:
            raise AnomalyModelError(f"unknown autoencoder hyperparameters {sorted(unknown)}")
        if "hidden_sizes" in data:
            data["hidden_sizes"] = tuple(int(h) for h in data["hidden_sizes"])
        return cls(**data)


def build_autoencoder(input_dim: int, config: AutoencoderConfig) -> nn.Sequential:
    def act() -> nn.Module:
        return nn.ReLU() if config.activation == "relu" else nn.GELU()

    layers: list[nn.Module] = []
    widths = [input_dim, *config.hidden_sizes]
    for a, b in itertools.pairwise(widths):
        layers += [nn.Linear(a, b), act()]
        if config.dropout > 0:
            layers.append(nn.Dropout(config.dropout))
    layers += [nn.Linear(widths[-1], config.bottleneck), act()]
    back = [config.bottleneck, *reversed(config.hidden_sizes)]
    for a, b in itertools.pairwise(back):
        layers += [nn.Linear(a, b), act()]
    layers.append(nn.Linear(back[-1], input_dim))
    return nn.Sequential(*layers)


class AutoencoderModel(FraudModel):
    model_name = MODEL_NAME
    score_kind = ANOMALY_SCORE

    def __init__(
        self,
        version: str = "1.0.0",
        *,
        seed: int = 42,
        hyperparameters: dict[str, Any] | None = None,
        feature_version: str = DEFAULT_FEATURE_VERSION,
    ) -> None:
        self.version = version
        self.seed = seed
        self.imbalance = "none (trained on legitimate rows only)"
        self.feature_version = feature_version
        self.config = AutoencoderConfig.from_dict(hyperparameters)
        self.hyperparameters = self.config.to_dict()
        self.preprocessor = Preprocessor(PREPROCESSING, feature_version)
        self.device = resolve_device(self.config.device)
        self.network: nn.Sequential | None = None
        self.reference: list[float] = []  # quantiles of training legitimate errors
        self.train_seconds: float | None = None
        self.history: list[dict[str, Any]] = []
        self.training_summary: dict[str, Any] = {}

    @property
    def algorithm(self) -> str:
        return ALGORITHM

    # ------------------------------------------------------------------ training
    def train(
        self, matrix: ModelMatrix, labels: Labels, validation: Validation | None = None
    ) -> None:
        y = np.asarray(labels, dtype=int)
        if len(y) != len(matrix):
            raise AnomalyModelError("labels and matrix differ in length")
        legit = [i for i in range(len(y)) if y[i] == 0]
        if validation is not None:
            val_m, val_y = validation
            val_rows = [i for i, v in enumerate(np.asarray(val_y, dtype=int)) if v == 0]
            fit_rows, source = legit, "legitimate rows of the validation split"
            val_matrix = val_m.take(val_rows)
        else:
            cut = round(len(legit) * (1 - self.config.holdout_fraction))
            fit_rows, source = legit[:cut], "latest legitimate training rows"
            val_matrix = matrix.take(legit[cut:])
        if len(fit_rows) < 2 or len(val_matrix) < 1:
            raise AnomalyModelError("too few legitimate rows to train the autoencoder")
        fit_matrix = matrix.take(fit_rows)
        cfg = self.config
        started = time.perf_counter()
        with deterministic(self.seed):
            self.preprocessor.fit(fit_matrix)
            X = torch.as_tensor(self.transform(fit_matrix), dtype=torch.float32)
            Xv = torch.as_tensor(self.transform(val_matrix), dtype=torch.float32)
            network = build_autoencoder(X.shape[1], cfg).to(self.device)
            optimizer = torch.optim.AdamW(
                network.parameters(), lr=cfg.learning_rate, weight_decay=cfg.weight_decay
            )
            generator = torch.Generator().manual_seed(self.seed)
            best, best_epoch, stale = np.inf, 0, 0
            best_state = copy.deepcopy(network.state_dict())
            history: list[dict[str, Any]] = []
            for epoch in range(1, cfg.max_epochs + 1):
                network.train()
                order = torch.randperm(len(X), generator=generator)
                total = 0.0
                for start in range(0, len(order), cfg.batch_size):
                    xb = X[order[start : start + cfg.batch_size]].to(self.device)
                    optimizer.zero_grad()
                    loss = ((network(xb) - xb) ** 2).mean()
                    loss.backward()
                    nn.utils.clip_grad_norm_(network.parameters(), cfg.grad_clip)
                    optimizer.step()
                    total += float(loss.item()) * len(xb)
                val_loss = float(self._errors(network, Xv).mean())
                improved = val_loss < best - cfg.min_delta
                history.append(
                    {
                        "epoch": epoch,
                        "train_loss": total / len(X),
                        "validation_loss": val_loss,
                        "learning_rate": optimizer.param_groups[0]["lr"],
                        "best_so_far": improved,
                    }
                )
                if improved:
                    best, best_epoch, stale = val_loss, epoch, 0
                    best_state = copy.deepcopy(network.state_dict())
                else:
                    stale += 1
                    if stale >= cfg.patience:
                        break
            network.load_state_dict(best_state)
            network.eval()
            train_errors = self._errors(network, X)
        self.network = network
        quantiles = np.quantile(train_errors, np.linspace(0, 1, REFERENCE_POINTS))
        self.reference = [float(q) for q in quantiles]
        self.train_seconds = time.perf_counter() - started
        self.history = history
        self.training_summary = {
            "epochs_completed": len(history),
            "best_epoch": best_epoch,
            "stopped_early": len(history) < cfg.max_epochs,
            "selection_metric": "validation reconstruction loss (legitimate rows)",
            "validation_source": source,
            "fit_rows": len(fit_rows),
            "fraud_rows_excluded_from_fit": int(len(y) - len(legit)),
            "validation_rows": len(val_matrix),
            "train_error_median": float(np.median(train_errors)),
            "train_error_p99": float(np.quantile(train_errors, 0.99)),
        }

    # ------------------------------------------------------------------ scoring
    def transform(self, matrix: ModelMatrix) -> Array:
        """Stage 3 preprocessing, then the recorded ``input_clip``."""
        clip = self.config.input_clip
        return np.clip(self.preprocessor.transform(matrix), -clip, clip)

    def _errors(self, network: nn.Module, X: torch.Tensor) -> Array:
        network.eval()
        out = []
        with torch.inference_mode():
            for start in range(0, len(X), PREDICT_BATCH):
                xb = X[start : start + PREDICT_BATCH].to(self.device)
                out.append(((network(xb) - xb) ** 2).mean(dim=1).cpu().double())
        if not out:
            return np.zeros(0)
        return np.asarray(torch.cat(out).numpy(), dtype=np.float64)

    def _column_errors(self, matrix: ModelMatrix) -> Array:
        if self.network is None:
            raise AnomalyModelError("model is not trained")
        with deterministic():
            X = torch.as_tensor(self.transform(matrix), dtype=torch.float32)
            with torch.inference_mode():
                recon = self.network(X.to(self.device)).cpu()
            return np.asarray(((recon - X) ** 2).double().numpy(), dtype=np.float64)

    def reconstruction_error(self, matrix: ModelMatrix) -> Array:
        if self.network is None:
            raise AnomalyModelError("model is not trained")
        with deterministic():
            X = torch.as_tensor(self.transform(matrix), dtype=torch.float32)
            return self._errors(self.network, X)

    def anomaly_score(self, errors: Array) -> Array:
        """Fraction of training legitimate events that reconstruct better (0..1)."""
        grid = np.linspace(0, 1, len(self.reference))
        return np.asarray(np.interp(errors, self.reference, grid), dtype=np.float64)

    def predict_proba(self, matrix: ModelMatrix) -> Array:
        """The ANOMALY SCORE (not a fraud probability) - see the module docstring."""
        return self.anomaly_score(self.reconstruction_error(matrix))

    def evaluate(
        self, matrix: ModelMatrix, labels: Labels, threshold: float = 0.95
    ) -> EvaluationResult:
        metrics = evaluate_scores(labels, self.predict_proba(matrix), threshold)
        return EvaluationResult(metrics, len(matrix), threshold, {"score": ANOMALY_SCORE})

    # ------------------------------------------------------------------ inspection
    def explain(
        self, matrix: ModelMatrix | None = None, labels: Labels | None = None, top_k: int = 12
    ) -> dict[str, Any]:
        """Which features reconstruct worst, overall and for fraud versus legitimate rows."""
        if matrix is None or len(matrix) == 0:
            return {"method": "reconstruction error by feature", "top_features": []}
        errors = self._column_errors(matrix)
        by_feature: dict[str, list[int]] = {}
        for j, column in enumerate(self.preprocessor.output_columns):
            by_feature.setdefault(self.preprocessor.base_feature(column), []).append(j)
        y = None if labels is None else np.asarray(labels, dtype=int)
        rows = []
        for feature, idx in by_feature.items():
            per_row = errors[:, idx].sum(axis=1)
            entry: dict[str, Any] = {"feature": feature, "mean_error": float(per_row.mean())}
            if y is not None and 0 < int(y.sum()) < len(y):
                entry["fraud_mean_error"] = float(per_row[y == 1].mean())
                entry["legitimate_mean_error"] = float(per_row[y == 0].mean())
                entry["importance"] = entry["fraud_mean_error"] - entry["legitimate_mean_error"]
            else:
                entry["importance"] = entry["mean_error"]
            rows.append(entry)
        rows.sort(key=lambda r: (-r["importance"], r["feature"]))
        return {
            "method": "reconstruction error by feature (fraud minus legitimate mean when "
            "labels are given); describes what looks unusual, not what is fraud",
            "top_features": rows[:top_k],
        }

    # ------------------------------------------------------------------ persistence
    def manifest(self) -> dict[str, Any]:
        if self.network is None:
            raise AnomalyModelError("model is not trained")
        return {
            "model_name": MODEL_NAME,
            "model_version": self.version,
            "kind": MODEL_NAME,
            "algorithm": ALGORITHM,
            "score_kind": ANOMALY_SCORE,
            "feature_version": self.feature_version,
            "catalogue_fingerprint": self.preprocessor.catalogue_fingerprint,
            "preprocessing": asdict(PREPROCESSING),
            "preprocessing_version": PREPROCESSING.version,
            "output_columns": len(self.preprocessor.output_columns),
            "hyperparameters": self.hyperparameters,
            "architecture": [str(layer) for layer in self.network],
            "parameter_count": parameter_count(self.network),
            "optimizer": "AdamW",
            "seed": self.seed,
            "imbalance": self.imbalance,
            "training": self.training_summary,
            "environment": environment(self.device),
        }

    def save(self, directory: Path) -> str:
        if self.network is None:
            raise AnomalyModelError("model is not trained")
        if directory.exists():
            raise AnomalyModelError(
                f"artefact directory {directory} already exists; refusing to overwrite"
            )
        directory.mkdir(parents=True)
        save_state(self.network, directory / WEIGHTS_FILE)
        config = {
            "hyperparameters": self.hyperparameters,
            "input_dim": len(self.preprocessor.output_columns),
            "seed": self.seed,
            "model_version": self.version,
            "feature_version": self.feature_version,
        }
        (directory / CONFIG_FILE).write_text(json.dumps(config, indent=2, sort_keys=True))
        (directory / PREPROCESSOR_FILE).write_text(self.preprocessor.to_json())
        (directory / REFERENCE_FILE).write_text(json.dumps({"quantiles": self.reference}))
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
    def load(
        cls, directory: Path, expected_sha256: str, blob: ArtifactBytes | None = None
    ) -> AutoencoderModel:
        blob = read_verified(directory, DIGEST_FILES, expected_sha256, blob)
        config = blob.json(CONFIG_FILE)
        preprocessor = Preprocessor.from_dict(blob.json(PREPROCESSOR_FILE))
        if preprocessor.config != PREPROCESSING:
            raise AnomalyModelError("stored preprocessing configuration differs from the model")
        if config["input_dim"] != len(preprocessor.output_columns):
            raise AnomalyModelError("stored input width does not match the preprocessing")
        model = cls(
            config["model_version"],
            seed=config["seed"],
            hyperparameters={**config["hyperparameters"], "device": "cpu"},
            feature_version=config["feature_version"],
        )
        model.preprocessor = preprocessor
        network = build_autoencoder(config["input_dim"], model.config)
        load_state(network, blob.data(WEIGHTS_FILE))
        network.eval()
        model.network = network
        model.reference = blob.json(REFERENCE_FILE)["quantiles"]
        if blob.has(HISTORY_FILE):
            stored = blob.json(HISTORY_FILE)
            model.history, model.training_summary = stored["history"], stored["summary"]
        return model
