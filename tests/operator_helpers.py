"""Operator identities for tests (Stage 12): per-operator Ed25519 keys and a registry."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from fraud_ai.trust import keys as tk
from fraud_ai.trust.operators import create_assertion

ROLES = {
    "alice": ["policy_approver"],
    "bob": ["policy_approver"],
    "carol": ["policy_activator"],
    "rita": ["reviewer"],
    "sec": ["security_admin"],
}


@dataclass
class Operators:
    registry: Path
    keys: dict[str, tk.KeyPair] = field(default_factory=dict)
    files: dict[str, Path] = field(default_factory=dict)
    audience: str = "fraud-ai-admin"

    def assertion(self, operator: str, action: str, target: str, **binding: str) -> str:
        return create_assertion(
            self.keys[operator],
            operator,
            action=action,
            target=target,
            binding=binding,
            audience=self.audience,
        )


def make_operators(directory: Path, roles: dict[str, list[str]] | None = None) -> Operators:
    directory.mkdir(parents=True, exist_ok=True)
    ops = Operators(directory / "operators.json")
    entries = []
    for name, granted in (roles or ROLES).items():
        pair = tk.generate()
        path = directory / f"{name}.pem"
        tk.write_private_key(pair, path)
        ops.keys[name], ops.files[name] = pair, path
        entries.append(
            {"id": name, "roles": granted, "public_keys": [tk.encode_public(pair.public)]}
        )
    ops.registry.write_text(json.dumps({"version": 1, "operators": entries}, indent=2))
    return ops
