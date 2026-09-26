"""The evidence packet: the ONLY input the local LLM ever sees.

* **Items and IDs.** Every fact is an :class:`EvidenceItem` with a stable id (``E1``,
  ``E2``, …). Each item has a section, a machine name, a value and the trusted system
  output it came from.
* **Limitations** come from a controlled list and have their own ids (``L1``, …). The LLM
  can cite them; it cannot invent new ones.
* **Deterministic.** Items are ordered by section, then by a fixed field order, and ids are
  assigned in that order. The canonical JSON and its SHA-256 hash therefore depend only on
  the evidence (tested).
* **Values are scalars.** Booleans, numbers (rounded to 4 d.p.), or short *tokens* that
  match ``[a-z0-9_.:+-]``. There is **no free text**: an unexpected string cannot even be
  constructed, so untrusted event metadata can never reach the model as instructions.

The packet schema is versioned (``EVIDENCE_SCHEMA_VERSION``).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fraud_ai.core.exceptions import FraudAIError

EVIDENCE_SCHEMA_VERSION = "analyst-evidence-1.0.0"
SECTIONS: tuple[str, ...] = (
    "event_summary",
    "model_scores",
    "model_agreement",
    "important_features",
    "temporal_summary",
    "security_summary",
    "transaction_summary",
    "network_summary",
    "device_summary",
    "address_summary",
    "scenario_context",
    "operational_cohorts",
    "label_context",
)
TOKEN = re.compile(r"^[a-z0-9_.:+-]{1,64}$")
NAME = re.compile(r"^[a-z][a-z0-9_.:-]{0,79}$")
EvidenceValue = bool | int | float | str | None


class EvidenceError(FraudAIError):
    """Evidence could not be built or would expose data it must not."""


class EvidencePrivacyError(EvidenceError):
    """The privacy gate rejected the packet."""


class EvidenceItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^E[1-9][0-9]*$")
    section: str
    name: str
    value: EvidenceValue
    source: str

    @field_validator("section")
    @classmethod
    def _section(cls, value: str) -> str:
        if value not in SECTIONS:
            raise ValueError(f"unknown evidence section {value!r}")
        return value

    @field_validator("name", "source")
    @classmethod
    def _name(cls, value: str) -> str:
        if not NAME.match(value):
            raise ValueError(f"evidence names must be machine identifiers, got {value!r}")
        return value

    @field_validator("value")
    @classmethod
    def _value(cls, value: EvidenceValue) -> EvidenceValue:
        if isinstance(value, float):
            return round(value, 4)
        if isinstance(value, str) and not TOKEN.match(value):
            # No free text: only short machine tokens (categories, versions, refs).
            # The value itself is never echoed: it may be exactly what must not leak.
            raise ValueError("evidence value is not an allowed token (free text or identifier)")
        return value


class Limitation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^L[1-9][0-9]*$")
    code: str
    text: str


class EvidencePacket(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = EVIDENCE_SCHEMA_VERSION
    event_ref: str = Field(pattern=r"^ev-[0-9a-f]{16}$")
    event_type: str
    items: tuple[EvidenceItem, ...]
    limitations: tuple[Limitation, ...] = ()

    @model_validator(mode="after")
    def _ids(self) -> EvidencePacket:
        ids = [i.id for i in self.items]
        if ids != [f"E{n}" for n in range(1, len(ids) + 1)]:
            raise ValueError("evidence ids must be E1..En in order")
        lids = [lim.id for lim in self.limitations]
        if lids != [f"L{n}" for n in range(1, len(lids) + 1)]:
            raise ValueError("limitation ids must be L1..Ln in order")
        if len({(i.section, i.name) for i in self.items}) != len(self.items):
            raise ValueError("duplicate evidence item")
        return self

    # ------------------------------------------------------------------ access
    @property
    def ids(self) -> set[str]:
        return {i.id for i in self.items} | {lim.id for lim in self.limitations}

    def item(self, evidence_id: str) -> EvidenceItem | Limitation:
        for item in self.items:
            if item.id == evidence_id:
                return item
        for limitation in self.limitations:
            if limitation.id == evidence_id:
                return limitation
        raise KeyError(evidence_id)

    def get(self, section: str, name: str) -> EvidenceItem | None:
        for item in self.items:
            if item.section == section and item.name == name:
                return item
        return None

    def section(self, name: str) -> list[EvidenceItem]:
        return [i for i in self.items if i.section == name]

    # ------------------------------------------------------------------ canonical form
    def canonical(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_ref": self.event_ref,
            "event_type": self.event_type,
            "evidence": [i.model_dump() for i in self.items],
            "limitations": [lim.model_dump() for lim in self.limitations],
        }

    def canonical_json(self) -> str:
        return json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()

    @classmethod
    def from_canonical(cls, data: dict[str, Any]) -> EvidencePacket:
        return cls(
            schema_version=data["schema_version"],
            event_ref=data["event_ref"],
            event_type=data["event_type"],
            items=tuple(EvidenceItem(**i) for i in data["evidence"]),
            limitations=tuple(Limitation(**lim) for lim in data["limitations"]),
        )

    # ------------------------------------------------------------------ prompt form
    def prompt_data(self) -> dict[str, Any]:
        """The same content in a compact table (one row per item) for the model's context
        window. Lossless: :meth:`from_prompt_data` rebuilds the identical packet."""
        return {
            "schema_version": self.schema_version,
            "event_ref": self.event_ref,
            "event_type": self.event_type,
            "evidence_columns": list(PROMPT_COLUMNS),
            "evidence": [[i.id, i.section, i.name, i.value, i.source] for i in self.items],
            "limitations": [lim.model_dump() for lim in self.limitations],
        }

    @classmethod
    def from_prompt_data(cls, data: dict[str, Any]) -> EvidencePacket:
        return cls.from_canonical(
            data
            | {
                "evidence": [
                    dict(zip(PROMPT_COLUMNS, row, strict=True)) for row in data["evidence"]
                ]
            }
        )


PROMPT_COLUMNS = ("id", "section", "name", "value", "source")


# ---------------------------------------------------------------------- building helper
def assemble(
    event_ref: str,
    event_type: str,
    entries: list[tuple[str, str, EvidenceValue, str]],
    limitations: list[tuple[str, str]],
) -> EvidencePacket:
    """``entries`` are (section, name, value, source), in the builder's fixed order within
    each section; sections are ordered by :data:`SECTIONS` (a stable sort)."""
    ordered = sorted(entries, key=lambda e: SECTIONS.index(e[0]))
    items = tuple(
        EvidenceItem(id=f"E{n}", section=s, name=name, value=value, source=src)
        for n, (s, name, value, src) in enumerate(ordered, 1)
    )
    lims = tuple(
        Limitation(id=f"L{n}", code=code, text=text)
        for n, (code, text) in enumerate(limitations, 1)
    )
    return EvidencePacket(event_ref=event_ref, event_type=event_type, items=items, limitations=lims)
