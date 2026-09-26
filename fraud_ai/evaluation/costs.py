"""Cost-sensitive threshold analysis and risk-band analysis (decision support only).

Costs are **experiment parameters**, not facts: there is no universal cost of fraud or of
customer friction. Nothing here enforces a threshold - the cheapest threshold is reported
as a finding of the experiment, never applied.

Per threshold (flagged = probability >= threshold):

    missed fraud     FN * fraud_loss                (or the transaction amount)
    handling         flagged * action_cost          (manual review or step-up)
    friction         FP * false_positive_friction
    total            missed + handling + friction
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np

from fraud_ai.evaluation.stats import Array, IntArray

DEFAULT_THRESHOLDS: tuple[float, ...] = tuple(round(0.05 * i, 2) for i in range(1, 20))
DEFAULT_BANDS: tuple[float, float] = (0.30, 0.70)


@dataclass(frozen=True)
class CostConfig:
    fraud_loss: float = 500.0
    manual_review_cost: float = 5.0
    step_up_cost: float = 1.0
    false_positive_friction: float = 10.0
    currency: str = "GBP"
    fraud_loss_mode: str = "fixed"  # "fixed" or "amount" (loss = the transaction amount)

    def __post_init__(self) -> None:
        if self.fraud_loss_mode not in {"fixed", "amount"}:
            raise ValueError("fraud_loss_mode must be 'fixed' or 'amount'")
        if (
            min(
                self.fraud_loss,
                self.manual_review_cost,
                self.step_up_cost,
                self.false_positive_friction,
            )
            < 0
        ):
            raise ValueError("costs must not be negative")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _losses(y: IntArray, amounts: Array | None, config: CostConfig) -> Array:
    if config.fraud_loss_mode == "amount":
        if amounts is None:
            raise ValueError("fraud_loss_mode='amount' needs transaction amounts")
        return np.where(y == 1, amounts, 0.0).astype(np.float64)
    return np.where(y == 1, config.fraud_loss, 0.0).astype(np.float64)


def cost_curve(
    y: IntArray,
    p: Array,
    config: CostConfig,
    *,
    amounts: Array | None = None,
    action: str = "review",
    thresholds: Sequence[float] = DEFAULT_THRESHOLDS,
) -> dict[str, Any]:
    y = np.asarray(y, dtype=int)
    losses = _losses(y, amounts, config)
    action_cost = config.manual_review_cost if action == "review" else config.step_up_cost
    rows: list[dict[str, Any]] = []
    for t in (0.0, *thresholds, 1.0000001):
        flagged = p >= t
        tp, fp = int(np.sum(flagged & (y == 1))), int(np.sum(flagged & (y == 0)))
        fn = int(np.sum(~flagged & (y == 1)))
        missed = float(losses[~flagged].sum())
        handling = float(flagged.sum()) * action_cost
        friction = fp * config.false_positive_friction
        total = missed + handling + friction
        rows.append(
            {
                "threshold": min(t, 1.0),
                "label": ("flag everything" if t == 0.0 else "flag nothing" if t > 1 else None),
                "fraud_caught": tp,
                "fraud_missed": fn,
                "false_positives": fp,
                "flagged": int(flagged.sum()),
                "missed_fraud_cost": missed,
                "handling_cost": handling,
                "friction_cost": friction,
                "total_cost": total,
                "cost_per_1000_events": 1000 * total / len(y) if len(y) else None,
            }
        )
    candidates = [r for r in rows if r["label"] is None]
    cheapest = min(candidates, key=lambda r: (r["total_cost"], -r["threshold"]))
    return {
        "action": action,
        "config": config.to_dict(),
        "rows": rows,
        "lowest_cost_threshold": cheapest["threshold"],
        "note": "Decision support only: costs are experiment parameters and the lowest-cost "
        "threshold is NOT applied anywhere.",
    }


def band_analysis(
    y: IntArray,
    p: Array,
    config: CostConfig,
    bands: tuple[float, float] = DEFAULT_BANDS,
    amounts: Array | None = None,
) -> dict[str, Any]:
    """Conceptual low / review / high regions (not rules): population, fraud concentration,
    false-positive and manual-review load."""
    y = np.asarray(y, dtype=int)
    low, high = bands
    if not 0 < low < high < 1:
        raise ValueError("bands must satisfy 0 < low < high < 1")
    losses = _losses(y, amounts, config)
    regions = {"low_risk": p < low, "review": (p >= low) & (p < high), "high_risk": p >= high}
    ranges = {"low_risk": [0.0, low], "review": [low, high], "high_risk": [high, 1.0]}
    total_fraud = int(y.sum())
    out = []
    for name, mask in regions.items():
        n, fraud = int(mask.sum()), int(y[mask].sum())
        legit = n - fraud
        if name == "low_risk":
            cost = float(losses[mask].sum())  # fraud passes unchecked
        elif name == "review":
            cost = n * config.manual_review_cost + legit * config.false_positive_friction
        else:
            cost = n * config.step_up_cost + legit * config.false_positive_friction
        out.append(
            {
                "band": name,
                "range": ranges[name],
                "events": n,
                "population_share": n / len(y) if len(y) else None,
                "fraud": fraud,
                "fraud_rate": fraud / n if n else None,
                "share_of_all_fraud": fraud / total_fraud if total_fraud else None,
                "legitimate_in_band": legit,
                "manual_review_load": n if name == "review" else 0,
                "conceptual_cost": cost,
            }
        )
    return {
        "bands": out,
        "boundaries": list(bands),
        "config": config.to_dict(),
        "note": "Analysis of conceptual regions for a future risk engine - not rules. "
        "review = manual review cost; high_risk = step-up cost; legitimate events "
        "in either incur friction; fraud in low_risk is a loss.",
    }
