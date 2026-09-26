"""Scenario-level evaluation, operational-cohort checks and error analysis.

Segments are defined *explicitly* (below) from the synthetic scenario of the account, the
known fraud type of the label and point-in-time feature values - never from protected
characteristics, which the platform does not hold or infer.

Rules for honest reporting:

* rates are only computed when their denominator exists (fraud-only segments report
  recall/FNR, legitimate-only segments report FPR);
* PR-AUC is only reported with at least ``MIN_CLASS`` examples of *each* class;
* every segment below ``MIN_CLASS`` in a class carries a small-sample note.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import numpy as np

from fraud_ai.evaluation.context import EvaluationContext, ScoredModel, pseudonym
from fraud_ai.evaluation.stats import Array, IntArray, ranking_metrics, wilson_interval
from fraud_ai.features.vector import FraudFeatureVector

MIN_CLASS = 10
Row = tuple[FraudFeatureVector, str, str | None, int]  # vector, scenario, fraud type, label
Predicate = Callable[[FraudFeatureVector, str, str | None, int], bool]


def _num(v: FraudFeatureVector, name: str) -> float | None:
    value = v.values.get(name)
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def _is(v: FraudFeatureVector, name: str) -> bool:
    return v.values.get(name) is True


def large_purchase(v: FraudFeatureVector) -> bool:
    ratio = _num(v, "transaction_vs_median_ratio")
    return _is(v, "unusually_high_transaction") or (ratio is not None and ratio >= 3.0)


def high_velocity(v: FraudFeatureVector) -> bool:
    return (
        (_num(v, "logins_last_1h") or 0) >= 2
        or (_num(v, "failed_logins_last_1h") or 0) >= 1
        or (_num(v, "transactions_last_1h") or 0) >= 1
    )


@dataclass(frozen=True)
class Segment:
    name: str
    description: str
    population: str  # "mixed", "fraud_only" or "legitimate_only"
    predicate: Predicate


def _scenario(name: str) -> Predicate:
    return lambda v, s, t, y: s == name


SEGMENTS: tuple[Segment, ...] = (
    # --- legitimate behaviour (accounts of these scenarios; can still hold fraud) ---
    Segment("normal_customer", "accounts of the 'normal' scenario", "mixed", _scenario("normal")),
    Segment("legitimate_vpn_user", "long-term VPN users", "mixed", _scenario("legitimate_vpn")),
    Segment("house_mover", "customers who move house", "mixed", _scenario("new_home_address")),
    Segment(
        "shared_network_customer",
        "office NAT / carrier CGNAT users",
        "mixed",
        _scenario("shared_network"),
    ),
    Segment(
        "new_legitimate_customer",
        "new accounts with a larger first purchase",
        "mixed",
        _scenario("new_customer"),
    ),
    Segment(
        "large_legitimate_purchase",
        "legitimate purchase >= 3x the customer's median or above their previous maximum",
        "legitimate_only",
        lambda v, s, t, y: y == 0 and large_purchase(v),
    ),
    # --- fraud ---
    Segment(
        "account_takeover",
        "fraud labelled account_takeover",
        "fraud_only",
        lambda v, s, t, y: y == 1 and t == "account_takeover",
    ),
    Segment(
        "stealthy_account_takeover",
        "takeover fraud with no password reset in the last "
        "24h (credential reuse or session hijack)",
        "fraud_only",
        lambda v, s, t, y: (
            y == 1 and t == "account_takeover" and not _is(v, "recent_password_reset")
        ),
    ),
    Segment(
        "new_account_card_fraud",
        "fraud labelled stolen_payment_method",
        "fraud_only",
        lambda v, s, t, y: y == 1 and t == "stolen_payment_method",
    ),
    Segment(
        "friendly_fraud",
        "fraud labelled friendly_fraud (disputed genuine purchases)",
        "fraud_only",
        lambda v, s, t, y: y == 1 and t == "friendly_fraud",
    ),
    Segment(
        "high_velocity_fraud",
        "fraud with >=2 logins or >=1 failed login or >=1 other transaction in the previous hour",
        "fraud_only",
        lambda v, s, t, y: y == 1 and high_velocity(v),
    ),
    Segment(
        "drop_address_fraud",
        "fraud shipped to an address added in the last 24h",
        "fraud_only",
        lambda v, s, t, y: y == 1 and _is(v, "new_address"),
    ),
)

COHORTS: tuple[Segment, ...] = (
    Segment(
        "mobile_network_users",
        "network flagged as mobile carrier",
        "legitimate_only",
        lambda v, s, t, y: _is(v, "mobile_network"),
    ),
    Segment(
        "vpn_users",
        "network flagged as VPN",
        "legitimate_only",
        lambda v, s, t, y: _is(v, "vpn_detected"),
    ),
    Segment(
        "shared_network_users",
        "another account seen on the same network",
        "legitimate_only",
        lambda v, s, t, y: _is(v, "shared_network_flag"),
    ),
    Segment(
        "new_account_users",
        "account younger than 30 days",
        "legitimate_only",
        lambda v, s, t, y: (_num(v, "account_age_days") or 1e9) < 30,
    ),
    Segment(
        "house_movers",
        "house-move scenario or address changed in the last 24h",
        "legitimate_only",
        lambda v, s, t, y: s == "new_home_address" or _is(v, "address_changed_recently"),
    ),
    Segment(
        "high_value_buyers",
        "purchase >= 3x median or above the previous maximum",
        "legitimate_only",
        lambda v, s, t, y: large_purchase(v),
    ),
)


def _rows(ctx: EvaluationContext, split: str) -> list[Row]:
    idx = ctx.indices(split)
    examples = ctx.prepared.dataset.examples
    y = ctx.prepared.y
    return [(examples[i].vector, ctx.scenarios[i], ctx.fraud_types[i], int(y[i])) for i in idx]


def segment_metrics(y: IntArray, p: Array, threshold: float, population: str) -> dict[str, Any]:
    flagged = p >= threshold
    pos, neg = int(y.sum()), int(len(y) - y.sum())
    tp, fp = int(np.sum(flagged & (y == 1))), int(np.sum(flagged & (y == 0)))
    fn = pos - tp
    out: dict[str, Any] = {
        "n": len(y),
        "fraud": pos,
        "legitimate": neg,
        "prevalence": pos / len(y) if len(y) else None,
        "flagged": int(flagged.sum()),
    }
    out["recall"] = tp / pos if pos else None
    out["fnr"] = fn / pos if pos else None
    out["fpr"] = fp / neg if neg else None
    out["precision"] = tp / (tp + fp) if (tp + fp) and population == "mixed" else None
    out["pr_auc"] = (
        ranking_metrics(y, p)["pr_auc"] if pos >= MIN_CLASS and neg >= MIN_CLASS else None
    )
    notes = []
    if population != "legitimate_only" and pos < MIN_CLASS:
        notes.append(f"only {pos} fraud examples: recall/FNR are indicative only")
    if population != "fraud_only" and neg < MIN_CLASS:
        notes.append(f"only {neg} legitimate examples: FPR is indicative only")
    if out["pr_auc"] is None and population == "mixed":
        notes.append(f"PR-AUC omitted (needs >= {MIN_CLASS} of each class)")
    out["notes"] = notes
    if pos:
        out["recall_interval_95"] = wilson_interval(tp, pos)
    if neg:
        out["fpr_interval_95"] = wilson_interval(fp, neg)
    return out


def scenario_report(
    ctx: EvaluationContext, model: ScoredModel, split: str = "test", threshold: float | None = None
) -> dict[str, Any]:
    t = model.threshold if threshold is None else threshold
    rows = _rows(ctx, split)
    p = model.scores[split]
    out = []
    for seg in SEGMENTS:
        mask = np.asarray([seg.predicate(*r) for r in rows], dtype=bool)
        entry = {"segment": seg.name, "description": seg.description, "population": seg.population}
        if not mask.any():
            out.append({**entry, "n": 0, "notes": ["no examples in this split"]})
            continue
        y = np.asarray([r[3] for r, m in zip(rows, mask, strict=True) if m], dtype=int)
        out.append({**entry, **segment_metrics(y, p[mask], t, seg.population)})
    return {"split": split, "threshold": t, "segments": out}


def cohort_report(
    ctx: EvaluationContext,
    model: ScoredModel,
    split: str = "test",
    threshold: float | None = None,
    ratio_flag: float = 2.0,
    min_legitimate: int = 30,
) -> dict[str, Any]:
    """False positive rates of operational cohorts against the global rate.

    A cohort is flagged when its FPR is at least ``ratio_flag`` times the global FPR, at least
    0.5 percentage points higher, and the lower end of its Wilson interval is above the
    global FPR (so noise alone is unlikely). Cohorts are operational (network, account age,
    purchase size) - no protected characteristic is inferred."""
    t = model.threshold if threshold is None else threshold
    rows = _rows(ctx, split)
    p = model.scores[split]
    legit = np.asarray([r[3] == 0 for r in rows], dtype=bool)
    flagged = p >= t
    global_fp, global_n = int(np.sum(flagged & legit)), int(legit.sum())
    global_fpr = global_fp / global_n if global_n else 0.0
    out = []
    for cohort in COHORTS:
        mask = np.asarray([cohort.predicate(*r) for r in rows], dtype=bool) & legit
        n, fp = int(mask.sum()), int(np.sum(flagged & mask))
        fpr = fp / n if n else None
        interval = wilson_interval(fp, n)
        flag = bool(
            fpr is not None
            and interval is not None
            and n >= min_legitimate
            and fpr >= ratio_flag * max(global_fpr, 1e-12)
            and fpr - global_fpr >= 0.005
            and interval[0] > global_fpr
        )
        notes = (
            [] if n >= min_legitimate else [f"only {n} legitimate events: too few to flag reliably"]
        )
        out.append(
            {
                "cohort": cohort.name,
                "description": cohort.description,
                "legitimate_events": n,
                "false_positives": fp,
                "fpr": fpr,
                "fpr_interval_95": interval,
                "ratio_to_global": fpr / global_fpr if fpr is not None and global_fpr else None,
                "flagged_higher_fpr": flag,
                "notes": notes,
            }
        )
    return {
        "split": split,
        "threshold": t,
        "global_fpr": global_fpr,
        "global_legitimate_events": global_n,
        "cohorts": out,
        "method": f"flag if FPR >= {ratio_flag}x global, >= +0.5pp and Wilson lower bound "
        "> global FPR; operational cohorts only (no demographic inference)",
    }


FP_CONTEXT = (
    "vpn_detected",
    "proxy_detected",
    "new_device",
    "new_address",
    "shared_network_flag",
    "mobile_network",
    "account_age_days",
    "unusually_high_transaction",
    "transaction_vs_median_ratio",
    "address_changed_recently",
    "recent_password_reset",
    "network_type",
)
FN_CONTEXT = (
    "device_seen_before",
    "device_age_days",
    "network_seen_before",
    "country_changed",
    "network_type",
    "address_age_days",
    "new_address",
    "transaction_vs_median_ratio",
    "recent_password_reset",
    "rapid_multi_change_count",
    "logins_last_1h",
    "failed_logins_last_1h",
    "transactions_last_24h",
)
FP_FLAGS: dict[str, Callable[[FraudFeatureVector], bool]] = {
    "vpn": lambda v: _is(v, "vpn_detected") or _is(v, "proxy_detected"),
    "new_device": lambda v: _is(v, "new_device"),
    "new_address": lambda v: _is(v, "new_address"),
    "shared_network": lambda v: _is(v, "shared_network_flag"),
    "mobile_network": lambda v: _is(v, "mobile_network"),
    "large_purchase": large_purchase,
    "house_move": lambda v: _is(v, "address_changed_recently"),
    "new_account": lambda v: (_num(v, "account_age_days") or 1e9) < 30,
    "recent_password_reset": lambda v: _is(v, "recent_password_reset"),
}


def _context(v: FraudFeatureVector, names: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in names:
        value = v.get(name)
        out[name] = value if value is not None else f"<{v.missing[name].value}>"
    return out


def error_report(
    ctx: EvaluationContext,
    model: ScoredModel,
    split: str = "test",
    threshold: float | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """False positives and false negatives with pseudonymised ids and context features."""
    t = model.threshold if threshold is None else threshold
    idx = ctx.indices(split)
    rows = _rows(ctx, split)
    p = model.scores[split]
    examples = ctx.prepared.dataset.examples
    fps: list[dict[str, Any]] = []
    fns: list[dict[str, Any]] = []
    for i, (row, prob) in enumerate(zip(rows, p, strict=True)):
        v, scenario, fraud_type, y = row
        base: dict[str, Any] = {
            "ref": pseudonym(examples[idx[i]].event_id),
            "probability": float(prob),
            "scenario": scenario,
        }
        if y == 0 and prob >= t:
            fps.append(
                {
                    **base,
                    "context": _context(v, FP_CONTEXT),
                    "traits": [k for k, fn in FP_FLAGS.items() if fn(v)],
                }
            )
        elif y == 1 and prob < t:
            fns.append({**base, "fraud_type": fraud_type, "context": _context(v, FN_CONTEXT)})
    fps.sort(key=lambda r: -r["probability"])
    fns.sort(key=lambda r: r["probability"])
    legit_vectors = [r[0] for r in rows if r[3] == 0]
    trait_summary: dict[str, dict[str, Any]] = {}
    for trait, fn in FP_FLAGS.items():
        in_fp = sum(trait in r["traits"] for r in fps)
        base_rate = sum(fn(v) for v in legit_vectors) / len(legit_vectors) if legit_vectors else 0
        fp_rate = in_fp / len(fps) if fps else 0.0
        trait_summary[trait] = {
            "false_positives_with_trait": in_fp,
            "share_of_fps": fp_rate,
            "share_of_all_legitimate": base_rate,
            "lift": fp_rate / base_rate if base_rate else None,
        }
    return {
        "split": split,
        "threshold": t,
        "false_positives": {
            "count": len(fps),
            "by_scenario": dict(Counter(r["scenario"] for r in fps)),
            "traits": trait_summary,
            "examples": fps[:limit],
        },
        "false_negatives": {
            "count": len(fns),
            "by_fraud_type": dict(Counter(str(r["fraud_type"]) for r in fns)),
            "by_scenario": dict(Counter(r["scenario"] for r in fns)),
            "examples": fns[:limit],
        },
        "privacy": "refs are one-way pseudonyms of internal event ids; no raw identifiers, IPs, "
        "addresses or payment data are included",
    }
