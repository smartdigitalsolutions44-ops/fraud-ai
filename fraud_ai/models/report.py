"""Human-readable model reports (plain text for the terminal, JSON for tooling).

Every report states that results describe the evaluated dataset; with the bundled
generator that dataset is synthetic.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from fraud_ai.database.models import ModelVersion

SYNTHETIC_NOTE = (
    "Results are measured on the configured held-out test split. With the bundled "
    "generator this data is SYNTHETIC: it says nothing about real-world fraud rates."
)


def _f(value: Any, digits: int = 3) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def comparison_rows(models: Sequence[ModelVersion]) -> list[dict[str, Any]]:
    rows = []
    for m in models:
        test = (m.metrics or {}).get("test", {})
        timings = (m.metrics or {}).get("timings", {})
        rows.append(
            {
                "model": m.model_name,
                "version": m.model_version,
                "dataset": m.training_dataset_version,
                "dataset_fingerprint": m.dataset_fingerprint,
                "feature_version": m.feature_version,
                "train_rows": m.train_rows,
                "validation_rows": m.validation_rows,
                "test_rows": m.test_rows,
                "test_positives": test.get("positives"),
                "pr_auc": test.get("pr_auc"),
                "roc_auc": test.get("roc_auc"),
                "threshold": test.get("threshold"),
                "precision": test.get("precision"),
                "recall": test.get("recall"),
                "f1": test.get("f1"),
                "fpr": test.get("fpr"),
                "train_seconds": timings.get("train_seconds"),
                "p50_latency_ms": timings.get("single_event_p50_ms"),
                "batch_rows_per_second": timings.get("batch_rows_per_second"),
                "warnings": len((m.metrics or {}).get("warnings", [])),
            }
        )
    return rows


def comparison_table(models: Sequence[ModelVersion]) -> str:
    rows = comparison_rows(models)
    datasets = {r["dataset_fingerprint"] for r in rows}
    header = (
        f"{'model':<34}{'PR-AUC':>8}{'ROC-AUC':>9}{'thr':>6}{'prec':>7}{'recall':>8}"
        f"{'F1':>7}{'FPR':>8}{'train s':>9}{'p50 ms':>8}{'rows/s':>10}{'warn':>6}"
    )
    lines = [header, "-" * len(header)]
    for r in rows:
        lines.append(
            f"{r['model'] + '-' + r['version']:<34}{_f(r['pr_auc']):>8}{_f(r['roc_auc']):>9}"
            f"{_f(r['threshold'], 2):>6}{_f(r['precision']):>7}{_f(r['recall']):>8}"
            f"{_f(r['f1']):>7}{_f(r['fpr'], 4):>8}{_f(r['train_seconds'], 2):>9}"
            f"{_f(r['p50_latency_ms'], 2):>8}{_f(r['batch_rows_per_second'], 0):>10}"
            f"{r['warnings']:>6}"
        )
    if rows:
        first = rows[0]
        lines.append("")
        lines.append(
            f"dataset {first['dataset']}  feature version {first['feature_version']}  "
            f"rows train/validation/test = {first['train_rows']}/"
            f"{first['validation_rows']}/{first['test_rows']} "
            f"(test fraud examples: {first['test_positives']})"
        )
    if len(datasets) > 1:
        lines.append(
            "WARNING: these models were trained on DIFFERENT datasets - their metrics "
            "are not directly comparable."
        )
    lines.append(SYNTHETIC_NOTE)
    lines.append(
        "No model is selected automatically: compare PR-AUC, precision/recall at the "
        "operating threshold and the false positive rate together."
    )
    return "\n".join(lines)


def threshold_table(rows: Sequence[dict[str, Any]]) -> str:
    header = (
        f"{'thr':>5}{'prec':>8}{'recall':>8}{'FPR':>9}{'FNR':>8}{'TP':>6}{'FP':>7}"
        f"{'TN':>8}{'FN':>6}"
    )
    lines = [header]
    for r in rows:
        lines.append(
            f"{r['threshold']:>5.2f}{_f(r['precision']):>8}{_f(r['recall']):>8}"
            f"{_f(r['fpr'], 4):>9}{_f(r['fnr']):>8}{r['tp']:>6}{r['fp']:>7}"
            f"{r['tn']:>8}{r['fn']:>6}"
        )
    return "\n".join(lines)


def model_details(m: ModelVersion) -> str:
    metrics = m.metrics or {}
    manifest = m.training_manifest or {}
    lines = [
        f"{m.model_name}-{m.model_version}  ({m.algorithm})  active={m.active}",
        f"trained {m.training_timestamp.isoformat()}  seed {m.random_seed}  "
        f"threshold {m.default_threshold}",
        f"dataset {m.training_dataset_version} ({m.dataset_fingerprint})",
        f"feature version {m.feature_version}  catalogue {m.feature_catalogue_fingerprint}",
        f"preprocessing {m.preprocessing_version}  rows train/val/test "
        f"{m.train_rows}/{m.validation_rows}/{m.test_rows}",
        f"artefact {m.model_path}  sha256 {m.artifact_sha256}",
        f"hyperparameters {m.hyperparameters}",
        f"environment {manifest.get('environment')}",
        "",
        f"{'split':<12}{'n':>7}{'fraud':>7}{'PR-AUC':>8}{'ROC-AUC':>9}{'prec':>7}{'recall':>8}"
        f"{'FPR':>8}",
    ]
    for split in ("train", "validation", "test"):
        s = metrics.get(split, {})
        lines.append(
            f"{split:<12}{s.get('n', 0):>7}{s.get('positives', 0):>7}"
            f"{_f(s.get('pr_auc')):>8}{_f(s.get('roc_auc')):>9}"
            f"{_f(s.get('precision')):>7}{_f(s.get('recall')):>8}"
            f"{_f(s.get('fpr'), 4):>8}"
        )
    for warning in metrics.get("warnings", []):
        lines.append(f"WARNING: {warning}")
    explanation = metrics.get("explanation", {})
    if explanation:
        lines.append("")
        lines.append(f"inspection ({explanation.get('method')}) - not used by any decision:")
        for item in explanation.get("top_features", [])[:8]:
            lines.append(f"  {item['feature']:<42} {item['importance']:+.4f}")
        for label in ("top_positive", "top_negative"):
            for item in explanation.get(label, [])[:6]:
                lines.append(f"  {label[4:]:<9}{item['column']:<50} {item['coefficient']:+.3f}")
    lines.append(SYNTHETIC_NOTE)
    return "\n".join(lines)
