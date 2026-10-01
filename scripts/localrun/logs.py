"""Per-service log files in ``.runtime/logs`` with size-based rotation and key redaction.

Children write to a pipe; a thread copies each line here. That lets the file rotate while
the child runs (5 MB, three old files kept) and removes API key material on the way: a
``fak_…`` credential never reaches a log file.
"""

from __future__ import annotations

import re
import threading
import time
from pathlib import Path
from typing import IO

MAX_BYTES = 5 * 1024 * 1024
BACKUPS = 3
_SECRET = re.compile(r"fak_[A-Za-z0-9_.\-]+")


def redact(line: str) -> str:
    return _SECRET.sub("fak_…", line)


def rotate(path: Path, backups: int = BACKUPS) -> None:
    """``x.log`` -> ``x.log.1`` -> … -> ``x.log.<backups>`` (the oldest is dropped)."""
    if not path.exists():
        return
    oldest = path.with_name(f"{path.name}.{backups}")
    oldest.unlink(missing_ok=True)
    for index in range(backups - 1, 0, -1):
        source = path.with_name(f"{path.name}.{index}")
        if source.exists():
            source.replace(path.with_name(f"{path.name}.{index + 1}"))
    path.replace(path.with_name(f"{path.name}.1"))


class LogFile:
    """Append-only, thread-safe, rotating."""

    def __init__(self, path: Path, max_bytes: int = MAX_BYTES) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._handle: IO[str] = path.open("a", encoding="utf-8")

    def write(self, line: str) -> None:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            self._handle.write(f"{stamp} {redact(line.rstrip())}\n")
            self._handle.flush()
            if self._handle.tell() >= self.max_bytes:
                self._handle.close()
                rotate(self.path)
                self._handle = self.path.open("a", encoding="utf-8")

    def close(self) -> None:
        with self._lock:
            self._handle.close()


def pump(stream: IO[bytes], log: LogFile) -> threading.Thread:
    """Copy ``stream`` into ``log`` line by line until EOF (daemon thread)."""

    def run() -> None:
        for raw in iter(stream.readline, b""):
            log.write(raw.decode("utf-8", errors="replace"))
        stream.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def tail(path: Path, lines: int = 15) -> list[str]:
    if not path.exists():
        return []
    with path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        handle.seek(max(0, size - 64 * 1024))
        text = handle.read().decode("utf-8", errors="replace")
    return text.splitlines()[-lines:]
