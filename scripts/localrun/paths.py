"""Where the local tooling keeps things. ``SENTINEL_RUNTIME_DIR`` moves ``.runtime/``
(the end-to-end tests use their own, so they never collide with an interactive session)."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONSOLE = REPO / "sentinel-console"
IS_WINDOWS = os.name == "nt"


@dataclass(frozen=True)
class Runtime:
    root: Path

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    @property
    def pids(self) -> Path:
        return self.root / "pids"

    @property
    def run(self) -> Path:
        """Per-session files (credential copies, control token); removed at shutdown."""
        return self.root / "run"

    @property
    def secrets(self) -> Path:
        """Development secrets, generated once and reused (never committed)."""
        return self.root / "secrets"

    @property
    def state(self) -> Path:
        """Install fingerprints and session markers. Install fingerprints describe this
        checkout, so they stay in the repository's own ``.runtime`` even when
        ``SENTINEL_RUNTIME_DIR`` moves the rest."""
        return REPO / ".runtime" / "state"

    @property
    def dev(self) -> Path:
        """Dev-mode model artefacts."""
        return self.root / "dev"

    def ensure(self) -> None:
        for directory in (self.root, self.logs, self.pids, self.run, self.secrets, self.state):
            directory.mkdir(parents=True, exist_ok=True)
        for private in (self.run, self.secrets):
            private.chmod(0o700)


def runtime() -> Runtime:
    override = os.environ.get("SENTINEL_RUNTIME_DIR")
    return Runtime(Path(override).resolve() if override else REPO / ".runtime")


def venv_python() -> Path:
    """The project virtual environment's interpreter (created by setup-local)."""
    venv = REPO / ".venv"
    return venv / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def python() -> str:
    """The interpreter that runs fraud-ai: the venv when it exists, else this one."""
    candidate = venv_python()
    return str(candidate) if candidate.exists() else sys.executable
