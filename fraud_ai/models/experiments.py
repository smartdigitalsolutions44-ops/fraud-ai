"""Controlled neural-network hyperparameter experiments.

* **Small grid, same data.** A small, explicit grid is trained on exactly the training and
  validation splits the baselines use.
* **Selection on validation only.** Each configuration is scored by its best-epoch
  validation PR-AUC. **The test split is never touched**; no test metric is computed.
* **Every result is stored:** configuration, parameter count, epochs, the selected epoch,
  validation PR-AUC and loss, training time and overfitting flags.
* **Loss experiment.** After the grid, the selected architecture is retrained with focal
  loss, so weighted BCE versus focal loss is *measured* rather than assumed.
* **Nothing is registered.** Train the chosen configuration with
  ``fraud-ai train neural-network`` to create a model version.
"""

from __future__ import annotations

import itertools
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from fraud_ai.models.neural import NeuralConfig, NeuralNetworkModel
from fraud_ai.models.training import PreparedData

EXPERIMENTS_VERSION = "neural-experiments-1.0.0"


@dataclass(frozen=True)
class ExperimentGrid:
    hidden_sizes: tuple[tuple[int, ...], ...] = ((64, 32), (128, 64, 32), (256, 128, 64))
    dropout: tuple[float, ...] = (0.1, 0.3, 0.5)
    learning_rate: tuple[float, ...] = (1e-3, 3e-4)
    weight_decay: tuple[float, ...] = (0.0, 1e-4)
    base: dict[str, Any] = field(default_factory=dict)  # fixed settings (epochs, patience...)
    compare_focal_loss: bool = True

    def configurations(self) -> list[dict[str, Any]]:
        out = []
        for hidden, dropout, lr, wd in itertools.product(
            self.hidden_sizes, self.dropout, self.learning_rate, self.weight_decay
        ):
            out.append(
                {
                    **self.base,
                    "hidden_sizes": list(hidden),
                    "dropout": dropout,
                    "learning_rate": lr,
                    "weight_decay": wd,
                }
            )
        return out

    def describe(self) -> dict[str, Any]:
        return {
            "hidden_sizes": [list(h) for h in self.hidden_sizes],
            "dropout": list(self.dropout),
            "learning_rate": list(self.learning_rate),
            "weight_decay": list(self.weight_decay),
            "fixed": self.base,
            "compare_focal_loss": self.compare_focal_loss,
            "configurations": len(self.configurations()),
        }


def _train_one(
    prepared: PreparedData, hyperparameters: dict[str, Any], seed: int, imbalance: str
) -> dict[str, Any]:
    train_m, train_y = prepared.part("train")
    model = NeuralNetworkModel(
        "experiment",
        seed=seed,
        imbalance=imbalance,
        hyperparameters=hyperparameters,
        feature_version=prepared.matrix.feature_version,
    )
    started = time.perf_counter()
    model.train(train_m, train_y, validation=prepared.part("validation"))
    seconds = time.perf_counter() - started
    summary = model.training_summary
    best = model.history[summary["best_epoch"] - 1] if summary["best_epoch"] else {}
    return {
        "hyperparameters": NeuralConfig.from_dict(hyperparameters).to_dict(),
        "parameter_count": model.parameter_count,
        "epochs_completed": summary["epochs_completed"],
        "best_epoch": summary["best_epoch"],
        "selection_metric": summary["selection_metric"],
        "validation_pr_auc": best.get("validation_pr_auc"),
        "validation_roc_auc": best.get("validation_roc_auc"),
        "validation_loss": best.get("validation_loss"),
        "train_pr_auc": best.get("train_pr_auc"),
        "train_seconds": seconds,
        "overfitting_flags": summary["overfitting_flags"],
    }


def _rank_key(result: dict[str, Any]) -> tuple[float, int, str]:
    # Highest validation PR-AUC; ties go to the smaller network, then a stable order.
    pr = result["validation_pr_auc"]
    return (
        -(pr if pr is not None else -1.0),
        result["parameter_count"],
        str(result["hyperparameters"]),
    )


def run_experiments(
    prepared: PreparedData,
    grid: ExperimentGrid,
    *,
    seed: int = 42,
    imbalance: str = "class_weight",
    progress: Callable[[int, int, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    configs = grid.configurations()
    results = []
    for i, hyperparameters in enumerate(configs, 1):
        result = _train_one(prepared, hyperparameters, seed, imbalance)
        results.append(result)
        if progress is not None:
            progress(i, len(configs), result)
    ranked = sorted(results, key=_rank_key)
    selected = ranked[0]
    loss_experiment = None
    if grid.compare_focal_loss:
        focal = _train_one(
            prepared, {**selected["hyperparameters"], "loss": "focal"}, seed, imbalance
        )
        weighted_pr, focal_pr = selected["validation_pr_auc"], focal["validation_pr_auc"]
        loss_experiment = {
            "weighted_bce": selected,
            "focal": focal,
            "difference_validation_pr_auc": (
                None if weighted_pr is None or focal_pr is None else focal_pr - weighted_pr
            ),
            "note": "same architecture, seed and data; a single run per loss, so small "
            "differences are within seed-to-seed noise",
        }
    summary = prepared.summary()
    return {
        "experiments_version": EXPERIMENTS_VERSION,
        "dataset_fingerprint": prepared.fingerprint,
        "splits": {
            k: {"rows": v["rows"], "positives": v["positives"]}
            for k, v in summary["splits"].items()
        },
        "seed": seed,
        "imbalance": imbalance,
        "grid": grid.describe(),
        "selection": "highest best-epoch validation PR-AUC; ties -> fewer parameters. The "
        "test split is not used.",
        "selected": selected,
        "results": ranked,
        "loss_experiment": loss_experiment,
        "note": "Experiments are not registered. Validation PR-AUC on a small validation "
        "split is noisy; neighbouring configurations within a few hundredths are not "
        "meaningfully different. Data is SYNTHETIC.",
    }
