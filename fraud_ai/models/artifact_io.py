"""Read an artefact directory once, verify the exact bytes, load from those bytes (Stage 11).

Before Stage 11 each loader hashed the files by path and then *reopened* them to
deserialise. Someone able to write to the model directory could swap a file in between
(time of check / time of use). Now:

1. the directory is opened once (``O_DIRECTORY | O_NOFOLLOW``). Every file is opened
   *relative to that handle* with ``O_NOFOLLOW``, checked to be a regular file with
   ``fstat``, and read completely into memory. The total is capped
   (``MAX_ARTIFACT_BYTES``);
2. the registered digest and, where required, the Ed25519 signature
   (:mod:`fraud_ai.models.signing`) are verified against **those bytes**;
3. the loaders deserialise from the same in-memory bytes (``io.BytesIO``). Nothing is read
   from disk again.

Symlinks, sub-directories, device files and oversized artefacts are refused. The digest
formula is unchanged: ``sha256("".join(f"{name}:{sha256(file)}\\n" for name in names))``.
Digests recorded before Stage 11 therefore still verify.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fraud_ai.core.exceptions import FraudAIError

MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024  # 1 GiB per artefact directory
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


class ArtifactReadError(FraudAIError):
    """The artefact directory could not be read safely (never loaded)."""


@dataclass(frozen=True)
class ArtifactBytes:
    directory: Path
    files: dict[str, bytes]
    _hashes: dict[str, str] = field(default_factory=dict, compare=False, repr=False)

    @classmethod
    def read(cls, directory: Path, *, limit: int = MAX_ARTIFACT_BYTES) -> ArtifactBytes:
        try:
            dir_fd = os.open(directory, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        except OSError as exc:
            raise ArtifactReadError(
                f"cannot open artefact directory {directory}: {exc.strerror}"
            ) from None
        files: dict[str, bytes] = {}
        total = 0
        try:
            if not stat.S_ISDIR(os.fstat(dir_fd).st_mode):
                raise ArtifactReadError(f"{directory} is not a directory")
            for name in sorted(os.listdir(dir_fd)):
                try:
                    fd = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=dir_fd)
                except OSError as exc:
                    raise ArtifactReadError(
                        f"{directory / name}: refused ({exc.strerror}); artefacts contain "
                        "regular files only"
                    ) from None
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    os.close(fd)
                    raise ArtifactReadError(f"{directory / name} is not a regular file")
                with os.fdopen(fd, "rb") as handle:
                    total += info.st_size
                    if total > limit:
                        raise ArtifactReadError(f"{directory} exceeds {limit} bytes")
                    data = handle.read(limit - total + info.st_size + 1)
                if len(data) != info.st_size:
                    raise ArtifactReadError(f"{directory / name} changed while being read")
                files[name] = data
        finally:
            os.close(dir_fd)
        return cls(directory, files)

    def has(self, name: str) -> bool:
        return name in self.files

    def data(self, name: str) -> bytes:
        try:
            return self.files[name]
        except KeyError:
            raise ArtifactReadError(f"{self.directory / name} is missing") from None

    def stream(self, name: str) -> io.BytesIO:
        return io.BytesIO(self.data(name))

    def json(self, name: str) -> Any:
        return json.loads(self.data(name))

    def sha256(self, name: str) -> str:
        cached = self._hashes.get(name)
        if cached is None:
            cached = hashlib.sha256(self.data(name)).hexdigest()
            self._hashes[name] = cached
        return cached

    def file_hashes(self) -> dict[str, str]:
        return {name: self.sha256(name) for name in sorted(self.files)}

    def digest(self, names: tuple[str, ...]) -> str:
        lines = "".join(f"{name}:{self.sha256(name)}\n" for name in names)
        return hashlib.sha256(lines.encode()).hexdigest()

    def verify(self, names: tuple[str, ...], expected: str) -> None:
        """Check the recorded digest against the bytes held in memory."""
        for name in names:
            if name not in self.files:
                raise ArtifactReadError(f"{self.directory / name} is missing")
        actual = self.digest(names)
        if actual != expected:
            raise ArtifactDigestError(
                f"{self.directory}: digest {actual[:12]} != recorded {expected[:12]}"
            )


class ArtifactDigestError(ArtifactReadError):
    """The bytes read do not match the digest recorded at training time."""
