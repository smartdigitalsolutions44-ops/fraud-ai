"""Shared PyTorch plumbing for the neural and anomaly models.

* **Device.** ``"auto"`` uses CUDA when available, otherwise the CPU. Everything works
  without a GPU.
* **Determinism.** Training and inference run inside :func:`deterministic`:
  * seeded generators;
  * ``torch.use_deterministic_algorithms(True)``;
  * one CPU thread;
  * ``CUBLAS_WORKSPACE_CONFIG`` set for CUDA.

  On the CPU this gives bit-identical results for the same seed, data and library version
  (tested). Results can still differ across PyTorch versions, CPU instruction sets, or CPU
  versus GPU, which is why those are recorded with every model.
* **Safe artefacts.** Only ``state_dict`` tensors are saved. They are loaded with
  ``torch.load(weights_only=True)``, and only after the artefact digest has been verified.
  No pickled model object is ever loaded.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import torch
from torch import nn

from fraud_ai.core.exceptions import FraudAIError

HASHES_FILE = "artifact_hashes.json"


class TorchModelError(FraudAIError):
    pass


class TorchArtifactIntegrityError(TorchModelError):
    """An artefact on disk does not match the digest recorded when it was trained."""


def resolve_device(requested: str) -> torch.device:
    if requested == "auto":
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if requested == "cuda" and not torch.cuda.is_available():
        raise TorchModelError("CUDA was requested but is not available")
    if requested not in ("cpu", "cuda"):
        raise TorchModelError(f"unknown device {requested!r} (use auto, cpu or cuda)")
    return torch.device(requested)


@contextmanager
def deterministic(seed: int | None = None) -> Iterator[None]:
    """Deterministic, single-threaded PyTorch for the duration of the block."""
    previous_threads = torch.get_num_threads()
    previous_det = torch.are_deterministic_algorithms_enabled()
    previous_cublas = os.environ.get("CUBLAS_WORKSPACE_CONFIG")
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    if seed is not None:
        torch.manual_seed(seed)
    try:
        yield
    finally:
        torch.set_num_threads(previous_threads)
        torch.use_deterministic_algorithms(previous_det)
        if previous_cublas is None:
            os.environ.pop("CUBLAS_WORKSPACE_CONFIG", None)


def environment(device: torch.device) -> dict[str, Any]:
    return {
        "torch": torch.__version__,
        "device": str(device),
        "cuda_available": torch.cuda.is_available(),
        "deterministic_algorithms": True,
        "cpu_threads": 1,
        "determinism_note": "bit-identical on CPU for the same seed, data and library "
        "versions; may differ across PyTorch versions, CPU instruction sets or CPU vs GPU",
    }


def parameter_count(module: nn.Module) -> int:
    return sum(p.numel() for p in module.parameters())


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_files(directory: Path, names: tuple[str, ...]) -> str:
    lines = "".join(f"{name}:{sha256_file(directory / name)}\n" for name in names)
    return hashlib.sha256(lines.encode()).hexdigest()


def write_hashes(directory: Path, digest: str, names: tuple[str, ...]) -> None:
    files = sorted(p.name for p in directory.iterdir() if p.is_file() and p.name != HASHES_FILE)
    (directory / HASHES_FILE).write_text(
        json.dumps(
            {
                "artifact_sha256": digest,
                "digest_covers": list(names),
                "files": {name: sha256_file(directory / name) for name in files},
            },
            indent=2,
            sort_keys=True,
        )
    )


def verify_digest(directory: Path, names: tuple[str, ...], expected: str) -> None:
    for name in names:
        if not (directory / name).exists():
            raise TorchArtifactIntegrityError(f"{directory / name} is missing")
    actual = digest_files(directory, names)
    if actual != expected:
        raise TorchArtifactIntegrityError(
            f"{directory}: digest {actual[:12]} != recorded {expected[:12]}"
        )


def save_state(module: nn.Module, path: Path) -> None:
    state = {k: v.detach().cpu().contiguous() for k, v in module.state_dict().items()}
    torch.save(state, path)


def load_state(module: nn.Module, path: Path) -> None:
    """Tensors only (``weights_only=True``); the digest must be verified before calling."""
    state = torch.load(path, map_location="cpu", weights_only=True)
    if not isinstance(state, dict):
        raise TorchModelError(f"{path} does not contain a state_dict")
    module.load_state_dict(state, strict=True)
