"""The one supervised PyTorch training loop (feed-forward, GRU, Transformer, hybrid).

Every fraud classifier trains through :func:`fit_binary`, so all of them share:

* seeded mini-batch shuffling;
* weighted ``BCEWithLogitsLoss`` (``pos_weight`` = negatives / positives), or focal loss
  for experiments;
* AdamW and gradient-norm clipping;
* per-epoch history: train loss, validation loss, train and validation PR-AUC,
  validation ROC-AUC, learning rate;
* early stopping on validation PR-AUC (validation loss when PR-AUC is undefined), with the
  best checkpoint restored;
* overfitting flags derived from that history.

A model supplies two callables: one for the logits of a batch of training rows (in
training mode), and one for the logits of all rows of a split (in evaluation mode). The
loop never sees the test split.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import numpy as np
import numpy.typing as npt
import torch
import torch.nn.functional as F
from sklearn.metrics import average_precision_score, roc_auc_score
from torch import nn

LOSSES = ("weighted_bce", "focal")


class LoopSettings(Protocol):
    @property
    def batch_size(self) -> int: ...
    @property
    def learning_rate(self) -> float: ...
    @property
    def weight_decay(self) -> float: ...
    @property
    def max_epochs(self) -> int: ...
    @property
    def patience(self) -> int: ...
    @property
    def min_delta(self) -> float: ...
    @property
    def grad_clip(self) -> float: ...
    @property
    def loss(self) -> str: ...
    @property
    def focal_gamma(self) -> float: ...


def fraud_loss(
    logits: torch.Tensor, targets: torch.Tensor, pos_weight: torch.Tensor, config: Any
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


def pr_roc(
    y: npt.NDArray[np.int_], p: npt.NDArray[np.float64]
) -> tuple[float | None, float | None]:
    if 0 < int(y.sum()) < len(y):
        return float(average_precision_score(y, p)), float(roc_auc_score(y, p))
    return None, None


@dataclass
class FitResult:
    history: list[dict[str, Any]]
    best_epoch: int
    selection_metric: str


def fit_binary(
    network: nn.Module,
    *,
    train_logits: Callable[[torch.Tensor], torch.Tensor],
    split_logits: Callable[[str], torch.Tensor],
    rows: npt.NDArray[np.int_],
    y_fit: npt.NDArray[np.int_],
    y_val: npt.NDArray[np.int_],
    pos_weight: float,
    config: LoopSettings,
    seed: int,
    device: torch.device,
    min_batch: int = 1,
) -> FitResult:
    """Train ``network`` in place and restore its best epoch. ``rows`` indexes the fitting
    rows used for mini-batches; it may repeat rows when oversampling."""
    t = torch.as_tensor(y_fit, dtype=torch.float32)
    tv = torch.as_tensor(y_val, dtype=torch.float32, device=device)
    weight = torch.tensor(pos_weight, dtype=torch.float32, device=device)
    optimizer = torch.optim.AdamW(
        network.parameters(), lr=config.learning_rate, weight_decay=config.weight_decay
    )
    order_rows = torch.as_tensor(rows)
    generator = torch.Generator().manual_seed(seed)
    use_pr = 0 < int(y_val.sum()) < len(y_val)
    best_score, best_epoch, stale = -np.inf, 0, 0
    best_state = copy.deepcopy(network.state_dict())
    history: list[dict[str, Any]] = []
    for epoch in range(1, config.max_epochs + 1):
        network.train()
        order = order_rows[torch.randperm(len(order_rows), generator=generator)]
        total = 0.0
        for start in range(0, len(order), config.batch_size):
            batch = order[start : start + config.batch_size]
            if len(batch) < min_batch:
                continue  # e.g. BatchNorm cannot train on a single row
            optimizer.zero_grad()
            loss = fraud_loss(train_logits(batch), t[batch].to(device), weight, config)
            loss.backward()  # type: ignore[no-untyped-call]
            nn.utils.clip_grad_norm_(network.parameters(), config.grad_clip)
            optimizer.step()
            total += float(loss.item()) * len(batch)
        network.eval()
        with torch.inference_mode():
            fit_logits = split_logits("fit")
            val_logits = split_logits("validation")
            val_loss = float(fraud_loss(val_logits, tv, weight, config).item())
        fit_p = torch.sigmoid(fit_logits).cpu().double().numpy()
        val_p = torch.sigmoid(val_logits).cpu().double().numpy()
        val_pr, val_roc = pr_roc(y_val, val_p)
        train_pr, _ = pr_roc(y_fit, fit_p)
        score = val_pr if use_pr and val_pr is not None else -val_loss
        improved = score > best_score + config.min_delta
        history.append(
            {
                "epoch": epoch,
                "train_loss": total / max(1, len(order_rows)),
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
            if stale >= config.patience:
                break
    network.load_state_dict(best_state)
    network.eval()
    return FitResult(history, best_epoch, "validation PR-AUC" if use_pr else "validation loss")


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


def oversample_rows(y: npt.NDArray[np.int_], ratio: float, seed: int) -> npt.NDArray[np.int_]:
    idx = np.arange(len(y))
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    target = int(len(neg) * ratio)
    if len(pos) == 0 or target <= len(pos):
        return idx
    rng = np.random.default_rng(seed)
    return np.concatenate([idx, rng.choice(pos, size=target - len(pos), replace=True)])
