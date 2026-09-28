"""Run the real service (``fraud-ai service run``, uvicorn with N worker processes) for
multi-process tests, the staging E2E and the benchmarks."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass
class ServiceProcess:
    base_url: str
    process: subprocess.Popen[bytes]
    log_path: Path

    def log(self) -> str:
        return self.log_path.read_text(errors="replace") if self.log_path.exists() else ""

    def worker_pids(self) -> list[int]:
        """Direct children of the uvicorn supervisor (the worker processes)."""
        pids = []
        for status in Path("/proc").glob("[0-9]*/status"):
            try:
                text = status.read_text()
            except OSError:
                continue
            fields = dict(line.split(":\t", 1) for line in text.splitlines() if ":\t" in line)
            if fields.get("PPid", "").strip() == str(self.process.pid):
                pid = int(status.parent.name)
                cmdline = (status.parent / "cmdline").read_bytes()
                if b"spawn_main" in cmdline and b"resource_tracker" not in cmdline:
                    pids.append(pid)
        return sorted(pids)


def _wait_ready(url: str, proc: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"service exited early with {proc.returncode}")
        try:
            r = httpx.get(f"{url}/v1/ready", timeout=2)
            if r.status_code == 200:
                return
            last = r.text
        except httpx.HTTPError as exc:
            last = type(exc).__name__
        time.sleep(0.3)
    raise RuntimeError(f"service not ready within {timeout}s: {last}")


@contextmanager
def running_service(
    env: dict[str, str], *, workers: int, log_dir: Path, timeout: float = 180.0
) -> Iterator[ServiceProcess]:
    port = free_port()
    full_env = {**os.environ, **env}
    log_path = log_dir / f"service-{port}.log"
    with log_path.open("wb") as log_file:
        proc = subprocess.Popen(  # noqa: S603 - our own CLI, fixed arguments
            [
                sys.executable,
                "-m",
                "fraud_ai",
                "service",
                "run",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--workers",
                str(workers),
            ],
            env=full_env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    service = ServiceProcess(f"http://127.0.0.1:{port}", proc, log_path)
    try:
        _wait_ready(service.base_url, proc, timeout)
        yield service
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=10)
