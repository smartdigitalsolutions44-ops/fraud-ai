"""Stage 6 sequence models: GRU, causal Transformer and a hybrid (GRU + static features).

All three read a :class:`~fraud_ai.sequences.inputs.SequenceMatrix`: the user's last N
events before the scoring point, plus the scored event as the final position.

**Event encoder** (shared by all three):

* learned embeddings for event type, network type, device type, authentication method and
  channel. These are type vocabularies only; there are no user, IP, device or address ids;
* the numeric event features (time gaps, amount, known flags, ages, VPN, change flags),
  standardised with statistics from the *valid training positions*, clipped to
  ±``input_clip``, then projected to ``hidden_size``.

**Architectures:**

* **GRU.** The encoder feeds a unidirectional GRU through ``pack_padded_sequence``, so
  padding never enters the hidden state. The final hidden state (at the scored event)
  goes to the dense head, which outputs a logit. Bidirectional recurrence is impossible
  by construction: it would read "future" positions.
* **Causal Transformer.** The encoder plus a learned embedding of each position's distance
  from the scored event, followed by pre-norm blocks of causal multi-head self-attention
  (position *i* attends only to positions ≤ *i*; padding keys are masked). The output at
  the scored event goes to the dense head. Attention weights can be read for *research
  inspection only*: they are not explanations and prove nothing causal.
* **Hybrid (GRU + static).** The GRU sequence representation is concatenated with an MLP
  embedding of the Stage 3 preprocessed 107-feature static vector, then passed through a
  fusion MLP to the logit.

Training reuses the Stage 5 infrastructure:
* the shared loop (weighted BCE, AdamW, early stopping on validation PR-AUC, best
  checkpoint restored);
* deterministic single-threaded execution;
* ``state_dict``-only artefacts with SHA-256 verification before loading.

A model refuses sequences built with a definition whose fingerprint differs from its own.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

import numpy as np
import numpy.typing as npt
import torch
from sklearn.metrics import average_precision_score
from torch import nn
from torch.nn.utils.rnn import pack_padded_sequence

from fraud_ai.features.definitions import DEFAULT_FEATURE_VERSION
from fraud_ai.models.base import EvaluationResult, FraudModel, Labels, Validation
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
from fraud_ai.models.torch_training import (
    LOSSES,
    fit_binary,
    overfitting_flags,
    oversample_rows,
)
from fraud_ai.sequences.definition import CATEGORICAL_FEATURES, SequenceDefinition, vocabulary
from fraud_ai.sequences.extraction import NUMERIC_NAMES, SequenceBatch
from fraud_ai.sequences.inputs import SequenceMatrix

SEQUENCE_KINDS = ("gru", "transformer", "hybrid-gru")
ALGORITHMS = {
    "gru": "torch.GRU",
    "transformer": "torch.CausalTransformer",
    "hybrid-gru": "torch.Hybrid(GRU+static)",
}
STATIC_PREPROCESSING = PreprocessingConfig(log_transform=True, standardize=True)
WEIGHTS_FILE, CONFIG_FILE, PREPROCESSOR_FILE = "model.pt", "config.json", "preprocessing.json"
HISTORY_FILE, MANIFEST_FILE = "history.json", "manifest.json"
PREDICT_BATCH = 2048
IMBALANCE = ("class_weight", "oversample", "none")

Array = npt.NDArray[np.float64]


class SequenceModelError(TorchModelError):
    pass


@dataclass(frozen=True)
class SequenceConfig:
    hidden_size: int = 64
    layers: int = 1
    heads: int = 4
    ff_size: int = 128
    dropout: float = 0.2
    event_embedding: int = 8
    context_embedding: int = 4
    static_hidden: int = 64
    fusion_hidden: int = 32
    batch_size: int = 256
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    max_epochs: int = 40
    patience: int = 6
    min_delta: float = 1e-4
    loss: str = "weighted_bce"
    focal_gamma: float = 2.0
    grad_clip: float = 1.0
    input_clip: float = 10.0
    holdout_fraction: float = 0.15
    device: str = "cpu"

    def __post_init__(self) -> None:
        sizes = (
            self.hidden_size,
            self.layers,
            self.heads,
            self.ff_size,
            self.event_embedding,
            self.context_embedding,
            self.static_hidden,
            self.fusion_hidden,
        )
        if min(sizes) < 1:
            raise SequenceModelError("layer sizes must be positive")
        if self.hidden_size % self.heads:
            raise SequenceModelError("hidden_size must be divisible by heads")
        if not 0.0 <= self.dropout < 1.0:
            raise SequenceModelError("dropout must be in [0, 1)")
        if self.loss not in LOSSES:
            raise SequenceModelError(f"loss must be one of {LOSSES}")
        if self.batch_size < 1 or self.max_epochs < 1 or self.patience < 1:
            raise SequenceModelError("batch_size, max_epochs and patience must be >= 1")
        if self.learning_rate <= 0 or self.weight_decay < 0 or self.input_clip <= 0:
            raise SequenceModelError("invalid learning_rate, weight_decay or input_clip")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> SequenceConfig:
        data = dict(data or {})
        known = {f.name for f in fields(cls)}
        if unknown := set(data) - known:
            raise SequenceModelError(f"unknown sequence hyperparameters {sorted(unknown)}")
        return cls(**data)


# ---------------------------------------------------------------------- networks
class EventEncoder(nn.Module):
    """Categorical embeddings + standardised numeric features -> ``hidden_size``."""

    numeric_mean: torch.Tensor
    numeric_std: torch.Tensor

    def __init__(self, config: SequenceConfig) -> None:
        super().__init__()
        self.embeddings = nn.ModuleList()
        width = 0
        for name, values in CATEGORICAL_FEATURES.items():
            dim = config.event_embedding if name == "event_type" else config.context_embedding
            self.embeddings.append(nn.Embedding(len(vocabulary(values)), dim, padding_idx=0))
            width += dim
        n = len(NUMERIC_NAMES)
        self.register_buffer("numeric_mean", torch.zeros(n))
        self.register_buffer("numeric_std", torch.ones(n))
        self.clip = config.input_clip
        self.project = nn.Linear(width + n, config.hidden_size)

    def forward(self, categorical: torch.Tensor, numeric: torch.Tensor) -> torch.Tensor:
        parts = [emb(categorical[..., k]) for k, emb in enumerate(self.embeddings)]
        z = ((numeric - self.numeric_mean) / self.numeric_std).clamp(-self.clip, self.clip)
        out: torch.Tensor = torch.relu(self.project(torch.cat([*parts, z], dim=-1)))
        return out


class CausalBlock(nn.Module):
    def __init__(self, config: SequenceConfig) -> None:
        super().__init__()
        self.norm1 = nn.LayerNorm(config.hidden_size)
        self.attention = nn.MultiheadAttention(
            config.hidden_size, config.heads, dropout=config.dropout, batch_first=True
        )
        self.norm2 = nn.LayerNorm(config.hidden_size)
        self.ff = nn.Sequential(
            nn.Linear(config.hidden_size, config.ff_size),
            nn.GELU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.ff_size, config.hidden_size),
        )
        self.drop = nn.Dropout(config.dropout)

    def forward(
        self,
        x: torch.Tensor,
        causal: torch.Tensor,
        padding: torch.Tensor,
        keep_weights: bool = False,
    ) -> tuple[torch.Tensor, torch.Tensor | None]:
        h = self.norm1(x)
        attended, weights = self.attention(
            h,
            h,
            h,
            attn_mask=causal,
            key_padding_mask=padding,
            need_weights=keep_weights,
            average_attn_weights=True,
        )
        x = x + self.drop(attended)
        x = x + self.drop(self.ff(self.norm2(x)))
        return x, weights


def causal_mask(length: int, device: torch.device) -> torch.Tensor:
    """True = blocked: position i may only attend to positions <= i."""
    return torch.triu(torch.ones(length, length, dtype=torch.bool, device=device), diagonal=1)


class SequenceNetwork(nn.Module):
    def __init__(self, kind: str, config: SequenceConfig, length: int, static_dim: int = 0) -> None:
        super().__init__()
        self.kind = kind
        self.encoder = EventEncoder(config)
        h = config.hidden_size
        self.gru: nn.GRU | None = None
        self.blocks = nn.ModuleList()
        self.position: nn.Embedding | None = None
        if kind in ("gru", "hybrid-gru"):
            self.gru = nn.GRU(
                h,
                h,
                num_layers=config.layers,
                batch_first=True,
                dropout=config.dropout if config.layers > 1 else 0.0,
                bidirectional=False,
            )
        else:
            # distance from the scored event: 0 = the scored event; `length` = padding
            self.position = nn.Embedding(length + 1, h, padding_idx=length)
            self.blocks = nn.ModuleList(CausalBlock(config) for _ in range(config.layers))
            self.final_norm = nn.LayerNorm(h)
        self.static: nn.Sequential | None = None
        fused = h
        if kind == "hybrid-gru":
            if static_dim < 1:
                raise SequenceModelError("the hybrid model needs static features")
            self.static = nn.Sequential(
                nn.Linear(static_dim, config.static_hidden),
                nn.LayerNorm(config.static_hidden),
                nn.ReLU(),
                nn.Dropout(config.dropout),
            )
            fused = h + config.static_hidden
        self.head = nn.Sequential(
            nn.Linear(fused, config.fusion_hidden),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.fusion_hidden, 1),
        )
        self.length = length
        self.last_attention: torch.Tensor | None = None

    def represent(
        self,
        categorical: torch.Tensor,
        numeric: torch.Tensor,
        lengths: torch.Tensor,
        keep_attention: bool = False,
    ) -> torch.Tensor:
        x = self.encoder(categorical, numeric)
        if self.gru is not None:
            packed = pack_padded_sequence(x, lengths.cpu(), batch_first=True, enforce_sorted=False)
            _, h_n = self.gru(packed)
            final: torch.Tensor = h_n[-1]
            return final
        x = self.encode_positions(x, lengths, keep_attention)
        last = (lengths - 1).clamp(min=0)
        at_target: torch.Tensor = x[torch.arange(len(last)), last]
        return at_target

    def encode_positions(
        self, x: torch.Tensor, lengths: torch.Tensor, keep_attention: bool = False
    ) -> torch.Tensor:
        """Transformer outputs at every position (causal: position i sees only <= i)."""
        assert self.position is not None
        steps = torch.arange(self.length, device=x.device)[None, :]
        valid = steps < lengths[:, None]
        distance = torch.where(
            valid, lengths[:, None] - 1 - steps, torch.full_like(steps, self.length)
        )
        x = x + self.position(distance)
        causal = causal_mask(self.length, x.device)
        weights = None
        for i, block in enumerate(self.blocks):
            x, w = block(
                x, causal, ~valid, keep_weights=keep_attention and i == len(self.blocks) - 1
            )
            weights = w if w is not None else weights
        if weights is not None:
            last = (lengths - 1).clamp(min=0)
            self.last_attention = weights[torch.arange(len(last)), last].detach()
        out: torch.Tensor = self.final_norm(x)
        return out

    def forward(
        self,
        categorical: torch.Tensor,
        numeric: torch.Tensor,
        lengths: torch.Tensor,
        static: torch.Tensor | None = None,
    ) -> torch.Tensor:
        z = self.represent(categorical, numeric, lengths)
        if self.static is not None:
            if static is None:
                raise SequenceModelError("the hybrid model needs static features")
            z = torch.cat([z, self.static(static)], dim=-1)
        logits: torch.Tensor = self.head(z).squeeze(-1)
        return logits


# ---------------------------------------------------------------------- model
class _Tensors:
    def __init__(self, batch: SequenceBatch, static: Array | None) -> None:
        self.cat = torch.as_tensor(batch.categorical)
        self.num = torch.as_tensor(batch.numeric)
        self.len = torch.as_tensor(batch.lengths)
        self.static = None if static is None else torch.as_tensor(static, dtype=torch.float32)

    def __len__(self) -> int:
        return len(self.len)


class SequenceModel(FraudModel):
    input_kind = "sequence"

    def __init__(
        self,
        kind: str,
        version: str = "1.0.0",
        *,
        seed: int = 42,
        imbalance: str = "class_weight",
        hyperparameters: dict[str, Any] | None = None,
        feature_version: str = DEFAULT_FEATURE_VERSION,
        oversample_ratio: float = 0.25,
    ) -> None:
        if kind not in SEQUENCE_KINDS:
            raise SequenceModelError(f"kind must be one of {SEQUENCE_KINDS}")
        if imbalance not in IMBALANCE:
            raise SequenceModelError(f"imbalance must be one of {IMBALANCE}")
        self.kind = kind
        self.model_name = kind
        self.version = version
        self.seed = seed
        self.imbalance = imbalance
        self.oversample_ratio = oversample_ratio
        self.feature_version = feature_version
        self.config = SequenceConfig.from_dict(hyperparameters)
        self.hyperparameters = self.config.to_dict()
        self.device = resolve_device(self.config.device)
        self.definition: SequenceDefinition | None = None
        self.preprocessor = (
            Preprocessor(STATIC_PREPROCESSING, feature_version) if kind == "hybrid-gru" else None
        )
        self.network: SequenceNetwork | None = None
        self.train_seconds: float | None = None
        self.history: list[dict[str, Any]] = []
        self.training_summary: dict[str, Any] = {}

    @property
    def algorithm(self) -> str:
        return ALGORITHMS[self.kind]

    @property
    def parameter_count(self) -> int:
        if self.network is None:
            raise SequenceModelError("model is not trained")
        return parameter_count(self.network)

    # ------------------------------------------------------------------ inputs
    def _sequences(self, matrix: ModelMatrix) -> SequenceBatch:
        if not isinstance(matrix, SequenceMatrix):
            raise SequenceModelError(
                f"{self.kind} needs sequence inputs (a SequenceMatrix), not a plain matrix"
            )
        if self.definition is not None and (
            matrix.sequences.definition.fingerprint() != self.definition.fingerprint()
        ):
            raise SequenceModelError(
                "sequences were built with a different sequence definition than the model's"
            )
        return matrix.sequences

    def _static(self, matrix: ModelMatrix) -> Array | None:
        if self.preprocessor is None:
            return None
        clip = self.config.input_clip
        return np.clip(self.preprocessor.transform(matrix), -clip, clip)

    def _tensors(self, matrix: ModelMatrix) -> _Tensors:
        return _Tensors(self._sequences(matrix), self._static(matrix))

    def _logits(
        self, network: SequenceNetwork, t: _Tensors, idx: torch.Tensor | None = None
    ) -> torch.Tensor:
        rows = torch.arange(len(t)) if idx is None else idx
        out = []
        for start in range(0, len(rows), PREDICT_BATCH):
            r = rows[start : start + PREDICT_BATCH]
            out.append(
                network(
                    t.cat[r].to(self.device),
                    t.num[r].to(self.device),
                    t.len[r].to(self.device),
                    None if t.static is None else t.static[r].to(self.device),
                )
            )
        return torch.cat(out) if out else torch.zeros(0)

    # ------------------------------------------------------------------ training
    def train(
        self, matrix: ModelMatrix, labels: Labels, validation: Validation | None = None
    ) -> None:
        y = np.asarray(labels, dtype=int)
        batch = self._sequences(matrix)
        if len(y) != len(matrix):
            raise SequenceModelError("labels and matrix differ in length")
        if len(np.unique(y)) < 2:
            raise SequenceModelError("training data must contain both classes")
        if validation is not None:
            fit_m, fit_y = matrix, y
            val_m, val_y = validation[0], np.asarray(validation[1], dtype=int)
            source = "validation split"
        else:
            cut = round(len(y) * (1 - self.config.holdout_fraction))
            fit_m, fit_y = matrix.take(list(range(cut))), y[:cut]
            val_m, val_y = matrix.take(list(range(cut, len(y)))), y[cut:]
            source = f"latest {self.config.holdout_fraction:.0%} of training rows"
        if len(np.unique(fit_y)) < 2:
            raise SequenceModelError("training data must contain both classes")
        self.definition = batch.definition
        cfg = self.config
        started = time.perf_counter()
        with deterministic(self.seed):
            if self.preprocessor is not None:
                self.preprocessor.fit(fit_m)
            fit_t, val_t = self._tensors(fit_m), self._tensors(val_m)
            static_dim = 0 if fit_t.static is None else int(fit_t.static.shape[1])
            network = SequenceNetwork(self.kind, cfg, batch.definition.length, static_dim)
            fit_batch = self._sequences(fit_m)
            valid = fit_batch.mask()
            values = fit_batch.numeric[valid]
            mean = values.mean(axis=0)
            std = values.std(axis=0)
            network.encoder.numeric_mean.copy_(torch.as_tensor(mean))
            network.encoder.numeric_std.copy_(torch.as_tensor(np.where(std > 0, std, 1.0)))
            network = network.to(self.device)
            positives = float(fit_y.sum())
            weight = (
                (len(fit_y) - positives) / positives if self.imbalance == "class_weight" else 1.0
            )
            rows = (
                oversample_rows(fit_y, self.oversample_ratio, self.seed)
                if self.imbalance == "oversample"
                else np.arange(len(fit_y))
            )
            tensors = {"fit": fit_t, "validation": val_t}
            fit = fit_binary(
                network,
                train_logits=lambda idx: self._logits(network, fit_t, idx),
                split_logits=lambda split: self._logits(network, tensors[split]),
                rows=rows,
                y_fit=fit_y,
                y_val=val_y,
                pos_weight=weight,
                config=cfg,
                seed=self.seed,
                device=self.device,
            )
        self.network = network
        self.train_seconds = time.perf_counter() - started
        self.history = fit.history
        self.training_summary = {
            "epochs_completed": len(fit.history),
            "best_epoch": fit.best_epoch,
            "stopped_early": len(fit.history) < cfg.max_epochs,
            "selection_metric": fit.selection_metric,
            "validation_source": source,
            "validation_rows": len(val_y),
            "validation_positives": int(val_y.sum()),
            "fit_rows": len(fit_y),
            "fit_positives": int(fit_y.sum()),
            "pos_weight": weight,
            "loss": cfg.loss,
            "overfitting_flags": overfitting_flags(fit.history, fit.best_epoch),
        }

    # ------------------------------------------------------------------ inference
    def predict_proba(self, matrix: ModelMatrix) -> Array:
        if self.network is None:
            raise SequenceModelError("model is not trained")
        with deterministic():
            self.network.eval()
            with torch.inference_mode():
                logits = self._logits(self.network, self._tensors(matrix))
            return np.asarray(torch.sigmoid(logits).cpu().double().numpy(), dtype=np.float64)

    def evaluate(
        self, matrix: ModelMatrix, labels: Labels, threshold: float = 0.5
    ) -> EvaluationResult:
        metrics = evaluate_scores(labels, self.predict_proba(matrix), threshold)
        return EvaluationResult(metrics, len(matrix), threshold)

    def attention(self, matrix: ModelMatrix) -> npt.NDArray[np.float64]:
        """Last-block attention from the scored event to each position (Transformer only).

        Research inspection only - attention weights are not explanations."""
        if self.network is None or self.kind != "transformer":
            raise SequenceModelError("attention is only available for a trained transformer")
        t = self._tensors(matrix)
        with deterministic():
            self.network.eval()
            with torch.inference_mode():
                self.network.represent(t.cat, t.num, t.len, keep_attention=True)
        assert self.network.last_attention is not None
        return np.asarray(self.network.last_attention.double().numpy(), dtype=np.float64)

    # ------------------------------------------------------------------ inspection
    def explain(
        self, matrix: ModelMatrix | None = None, labels: Labels | None = None, top_k: int = 12
    ) -> dict[str, Any]:
        """Permutation importance of sequence channels (each channel permuted across rows,
        whole sequences at a time). Inspection only."""
        if self.network is None:
            raise SequenceModelError("model is not trained")
        y = None if labels is None else np.asarray(labels, dtype=int)
        if matrix is None or y is None or len(np.unique(y)) < 2:
            return {
                "method": "sequence channel permutation importance",
                "note": "needs labelled data with both classes",
                "top_features": [],
            }
        batch = self._sequences(matrix)
        static = self._static(matrix)
        network = self.network

        def score(b: SequenceBatch) -> float:
            t = _Tensors(b, static)
            with deterministic():
                network.eval()
                with torch.inference_mode():
                    p = torch.sigmoid(self._logits(network, t)).double().numpy()
            return float(average_precision_score(y, p))

        base = score(batch)
        rng = np.random.default_rng(self.seed)
        scores: dict[str, float] = {}
        channels = [("categorical", k, n) for k, n in enumerate(CATEGORICAL_FEATURES)] + [
            ("numeric", k, n) for k, n in enumerate(NUMERIC_NAMES)
        ]
        for kind, k, name in channels:
            drops = []
            for _ in range(2):
                order = rng.permutation(len(batch))
                cat, num = batch.categorical.copy(), batch.numeric.copy()
                if kind == "categorical":
                    cat[:, :, k] = batch.categorical[order][:, :, k]
                else:
                    num[:, :, k] = batch.numeric[order][:, :, k]
                permuted = SequenceBatch(batch.definition, cat, num, batch.lengths)
                drops.append(base - score(permuted))
            scores[f"seq:{name}"] = float(np.mean(drops))
        ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[:top_k]
        return {
            "method": "sequence channel permutation importance (drop in PR-AUC, 2 seeded "
            "repeats; a channel is permuted across rows for every position)",
            "baseline_pr_auc": base,
            "top_features": [{"feature": f, "importance": s} for f, s in ranked],
        }

    # ------------------------------------------------------------------ persistence
    def _digest_files(self) -> tuple[str, ...]:
        base = (WEIGHTS_FILE, CONFIG_FILE)
        return (*base, PREPROCESSOR_FILE) if self.preprocessor is not None else base

    def manifest(self) -> dict[str, Any]:
        if self.network is None or self.definition is None:
            raise SequenceModelError("model is not trained")
        return {
            "model_name": self.model_name,
            "model_version": self.version,
            "kind": self.kind,
            "algorithm": self.algorithm,
            "input_kind": self.input_kind,
            "feature_version": self.feature_version,
            "sequence": self.definition.to_dict(),
            "sequence_fingerprint": self.definition.fingerprint(),
            "embedding_vocabulary_version": self.definition.version,
            "static_preprocessing": (
                asdict(STATIC_PREPROCESSING) if self.preprocessor is not None else None
            ),
            "preprocessing_version": STATIC_PREPROCESSING.version,
            "hyperparameters": self.hyperparameters,
            "architecture": str(self.network),
            "parameter_count": self.parameter_count,
            "optimizer": "AdamW",
            "seed": self.seed,
            "imbalance": self.imbalance,
            "oversample_ratio": self.oversample_ratio,
            "training": self.training_summary,
            "environment": environment(self.device),
        }

    def save(self, directory: Path) -> str:
        if self.network is None or self.definition is None:
            raise SequenceModelError("model is not trained")
        if directory.exists():
            raise SequenceModelError(
                f"artefact directory {directory} already exists; refusing to overwrite"
            )
        directory.mkdir(parents=True)
        save_state(self.network, directory / WEIGHTS_FILE)
        static_dim = 0 if self.preprocessor is None else len(self.preprocessor.output_columns)
        config = {
            "kind": self.kind,
            "hyperparameters": self.hyperparameters,
            "sequence": self.definition.to_dict(),
            "static_dim": static_dim,
            "seed": self.seed,
            "imbalance": self.imbalance,
            "oversample_ratio": self.oversample_ratio,
            "model_version": self.version,
            "feature_version": self.feature_version,
        }
        (directory / CONFIG_FILE).write_text(json.dumps(config, indent=2, sort_keys=True))
        if self.preprocessor is not None:
            (directory / PREPROCESSOR_FILE).write_text(self.preprocessor.to_json())
        (directory / HISTORY_FILE).write_text(
            json.dumps({"history": self.history, "summary": self.training_summary}, indent=2)
        )
        names = self._digest_files()
        digest = digest_files(directory, names)
        (directory / MANIFEST_FILE).write_text(
            json.dumps({**self.manifest(), "artifact_sha256": digest}, indent=2, sort_keys=True)
        )
        write_hashes(directory, digest, names)
        return digest

    @classmethod
    def load(cls, directory: Path, expected_sha256: str) -> SequenceModel:
        config_path = directory / CONFIG_FILE
        if not config_path.exists():
            raise SequenceModelError(f"{config_path} is missing")
        kind = json.loads(config_path.read_text()).get("kind")
        names = (WEIGHTS_FILE, CONFIG_FILE) + ((PREPROCESSOR_FILE,) if kind == "hybrid-gru" else ())
        verify_digest(directory, names, expected_sha256)  # before reading any weights
        config = json.loads(config_path.read_text())
        model = cls(
            config["kind"],
            config["model_version"],
            seed=config["seed"],
            imbalance=config["imbalance"],
            hyperparameters={**config["hyperparameters"], "device": "cpu"},
            feature_version=config["feature_version"],
            oversample_ratio=config["oversample_ratio"],
        )
        model.definition = SequenceDefinition.from_dict(config["sequence"])
        if model.kind == "hybrid-gru":
            pre = Preprocessor.from_dict(json.loads((directory / PREPROCESSOR_FILE).read_text()))
            if pre.config != STATIC_PREPROCESSING:
                raise SequenceModelError("stored static preprocessing differs from the model")
            if len(pre.output_columns) != config["static_dim"]:
                raise SequenceModelError("stored static width does not match the preprocessing")
            model.preprocessor = pre
        network = SequenceNetwork(
            model.kind, model.config, model.definition.length, config["static_dim"]
        )
        load_state(network, directory / WEIGHTS_FILE)
        network.eval()
        model.network = network
        if (directory / HISTORY_FILE).exists():
            stored = json.loads((directory / HISTORY_FILE).read_text())
            model.history, model.training_summary = stored["history"], stored["summary"]
        return model
