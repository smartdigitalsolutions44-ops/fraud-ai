"""Processes the tooling started, and only those.

Each started process gets a record in ``.runtime/pids/<name>.json`` holding its PID, its
creation time and its command line. A PID alone is not proof: operating systems reuse
them. A record counts as *ours* only if a process with that PID exists **and** has the
recorded creation time. Anything else is a stale record and is removed, never killed.

Stopping is graceful first: SIGTERM to the process group on POSIX, CTRL_BREAK_EVENT to the
process group on Windows. Only after a timeout are the process and its descendants killed,
and only descendants of a process verified as ours.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import psutil

from localrun.paths import IS_WINDOWS

CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
_CREATE_TIME_TOLERANCE = 1.0  # seconds; creation times are floats with platform rounding


@dataclass(frozen=True)
class Record:
    name: str
    pid: int
    create_time: float
    command: list[str]
    started_at: float

    def path(self, pids: Path) -> Path:
        return pids / f"{self.name}.json"


def spawn_flags() -> dict[str, Any]:
    """Own process group, so a stop signal reaches the child (and its children) only.

    On Windows the child also shares the parent's console (no ``CREATE_NO_WINDOW`` here):
    CTRL_BREAK_EVENT only reaches processes attached to the sender's console. The
    supervisor itself runs in a hidden console (``cli.spawn_supervisor``), so no window
    appears."""
    if IS_WINDOWS:
        return {"creationflags": CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def record(pids: Path, name: str, proc: subprocess.Popen[bytes], command: list[str]) -> Record:
    rec = Record(name, proc.pid, psutil.Process(proc.pid).create_time(), command, time.time())
    tmp = rec.path(pids).with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(rec), indent=2))
    os.replace(tmp, rec.path(pids))
    return rec


def load(pids: Path, name: str) -> Record | None:
    path = pids / f"{name}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return Record(
            name=str(data["name"]),
            pid=int(data["pid"]),
            create_time=float(data["create_time"]),
            command=[str(part) for part in data["command"]],
            started_at=float(data["started_at"]),
        )
    except FileNotFoundError:
        return None
    except (ValueError, KeyError, TypeError):
        path.unlink(missing_ok=True)  # corrupt: treat as stale
        return None


def forget(pids: Path, name: str) -> None:
    (pids / f"{name}.json").unlink(missing_ok=True)


def process(rec: Record) -> psutil.Process | None:
    """The live process for ``rec``, or None when the record is stale (PID gone or reused)."""
    try:
        proc = psutil.Process(rec.pid)
        if abs(proc.create_time() - rec.create_time) > _CREATE_TIME_TOLERANCE:
            return None
        if proc.status() == psutil.STATUS_ZOMBIE:
            return None
        return proc
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def alive(pids: Path, name: str) -> Record | None:
    """The record when its process is still ours and running; stale records are removed."""
    rec = load(pids, name)
    if rec is None:
        return None
    if process(rec) is None:
        forget(pids, name)
        return None
    return rec


def _signal_group(proc: psutil.Process) -> bool:
    """Ask the process group to stop. False when the signal could not be delivered."""
    try:
        if IS_WINDOWS:
            os.kill(proc.pid, signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
            return True
        pgid = os.getpgid(proc.pid)
        if pgid == proc.pid:  # it leads its own group (spawn_flags); signal the group
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.terminate()
        return True
    except (OSError, psutil.Error):
        return False


def stop(rec: Record, timeout: float = 15.0) -> str:
    """Stop the process in ``rec`` if it is ours. Returns what happened."""
    proc = process(rec)
    if proc is None:
        return "not running (stale record removed)"
    try:
        family = proc.children(recursive=True)
    except psutil.Error:
        family = []
    # A signal that cannot be delivered (Windows: a process on another console) is not
    # waited for at length: the forced stop below follows after a short grace period.
    delivered = _signal_group(proc)
    _, alive_ = psutil.wait_procs([proc, *family], timeout=timeout if delivered else 2.0)
    if not alive_:
        return "stopped"
    for leftover in alive_:
        with contextlib.suppress(psutil.Error):
            leftover.kill()
    psutil.wait_procs(alive_, timeout=5)
    return f"stopped (forced after {timeout:.0f}s)"
