"""Rendering of the feature catalogue (CLI output and FEATURES.md)."""

from __future__ import annotations

import json

from fraud_ai.features.definitions import FeatureSet, get_feature_set

MARKDOWN_BEGIN = "<!-- BEGIN GENERATED FEATURE CATALOGUE -->"
MARKDOWN_END = "<!-- END GENERATED FEATURE CATALOGUE -->"


def catalog_json(version: str | None = None) -> str:
    fs = get_feature_set(version)
    return json.dumps(
        {
            "feature_version": fs.version,
            "fingerprint": fs.fingerprint(),
            "parameters": fs.parameters,
            "features": [d.to_dict() for d in fs.definitions],
        },
        indent=2,
        sort_keys=True,
    )


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def catalog_markdown(version: str | None = None) -> str:
    """Generated catalogue section embedded in FEATURES.md (kept in sync by a test)."""
    fs: FeatureSet = get_feature_set(version)
    out = [
        MARKDOWN_BEGIN,
        "",
        f"Feature version `{fs.version}` - {len(fs.definitions)} features - fingerprint "
        f"`{fs.fingerprint()[:16]}`",
        "",
    ]
    for category in dict.fromkeys(d.category for d in fs.definitions):
        out += [
            f"### {category.value.replace('_', ' ').title()}",
            "",
            "| Feature | Type | Units | Nullable | Applies to | Description | Source | "
            "Missing when | Leakage notes |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for d in fs.by_category(category):
            applies = "both" if len(d.applies_to) == 2 else next(iter(d.applies_to)).value
            desc = d.description + (f" *Why:* {d.rationale}" if d.rationale else "")
            out.append(
                f"| `{d.name}` | {d.dtype.value} | {d.units or ''} | "
                f"{'yes' if d.nullable else 'no'} | {applies} | {_cell(desc)} | "
                f"{_cell(', '.join(f'`{s}`' for s in d.sources))} | {_cell(d.missing_when)} | "
                f"{_cell(d.leakage_notes)} |"
            )
        out.append("")
    out.append(MARKDOWN_END)
    return "\n".join(out)
