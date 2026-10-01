"""The background process that owns the API and the console for one local session.

``sentinel-start`` prepares everything that needs the user's attention (dependencies, the
demo world, Docker), then starts this supervisor detached and waits for it to report ready.
The supervisor:

* starts the API, waits for ``/v1/ready``, then starts the console and waits for it;
* writes each child's output to ``.runtime/logs/<name>.log`` (rotating, keys redacted);
* records every child in ``.runtime/pids`` (PID + creation time), and itself as
  ``supervisor``;
* serves a control endpoint on 127.0.0.1 (random port, random 256-bit token kept in a 0600
  file): ``GET /status``, ``POST /shutdown`` and, in Demo mode only, ``POST /reset``. That
  is the same reset protocol the console's RESET DEMO button already uses. A reset stops the
  API, runs the guarded ``fraud-ai demo reset`` (which refuses anything but a demo database)
  and starts the API again;
* on shutdown stops the console, then the API, gracefully, and removes its session files.

Session state goes to ``.runtime/run/state.json`` so ``sentinel-start`` and
``sentinel-status`` can read it without the token.
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import psutil

from localrun import config as cfg
from localrun import logs, modes, procs
from localrun.paths import REPO, Runtime, python

READY_TIMEOUT = {"api": 240.0, "console": 180.0}
LIFELINE = Path(__file__).resolve().with_name("lifeline.py")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def http_status(url: str, timeout: float = 3.0) -> int | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310  # nosec B310 - 127.0.0.1 only
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, OSError, TimeoutError):
        return None


class Supervisor:
    def __init__(self, plan: modes.Plan, rt: Runtime) -> None:
        self.plan = plan
        self.rt = rt
        self.children: dict[str, subprocess.Popen[bytes]] = {}
        self.records: dict[str, procs.Record] = {}
        self.logs: dict[str, logs.LogFile] = {}
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.intentional: set[str] = set()
        self.token = secrets.token_hex(32)
        self.state: dict[str, Any] = {
            "mode": plan.mode,
            "phase": "starting",
            "message": None,
            "api_url": plan.api.url,
            "console_url": plan.console.url,
            "database": plan.database,
            "redis": plan.redis,
            "started_at": _now(),
            "pid": os.getpid(),
            "services": {"api": "stopped", "console": "stopped"},
        }
        self.reset_state: dict[str, Any] = {
            "state": "idle",
            "started_at": None,
            "finished_at": None,
            "message": None,
            "log": [],
        }
        self.log = logs.LogFile(rt.logs / "supervisor.log")

    # ------------------------------------------------------------------ state
    def save(self, **changes: Any) -> None:
        with self.lock:
            self.state.update(changes)
            snapshot = json.dumps(self.state, indent=2)
        tmp = self.rt.run / "state.json.tmp"
        tmp.write_text(snapshot, encoding="utf-8")
        os.replace(tmp, self.rt.run / "state.json")

    def service(self, name: str, status: str) -> None:
        with self.lock:
            self.state["services"][name] = status
        self.save()

    def say(self, message: str) -> None:
        self.log.write(message)

    # ------------------------------------------------------------- children
    def start_child(self, proc: modes.Proc) -> None:
        log_path = self.rt.logs / f"{proc.name}.log"
        logs.rotate(log_path)
        log = logs.LogFile(log_path)
        self.logs[proc.name] = log
        log.write(f"--- starting {proc.name}: {' '.join(proc.command[1:])} ---")
        # The service runs under a lifeline that stops it if this supervisor ever goes away;
        # the pipe on its stdin is never written to, only held open (see lifeline.py).
        command = [python(), str(LIFELINE), *proc.command]
        child = subprocess.Popen(  # noqa: S603  # nosec B603 - our own fixed commands
            command,
            cwd=proc.cwd,
            env=proc.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            **procs.spawn_flags(),
        )
        assert child.stdout is not None
        logs.pump(child.stdout, log)
        self.children[proc.name] = child
        self.records[proc.name] = procs.record(self.rt.pids, proc.name, child, command)
        self.service(proc.name, "starting")
        self.say(f"{proc.name} started (PID {child.pid})")

    def wait_ready(self, proc: modes.Proc) -> None:
        deadline = time.monotonic() + READY_TIMEOUT[proc.name]
        child = self.children[proc.name]
        url = proc.url + proc.health_path
        while time.monotonic() < deadline and not self.stopping.is_set():
            if child.poll() is not None:
                raise RuntimeError(f"{proc.name} exited with code {child.returncode}")
            if http_status(url) == 200:
                self.service(proc.name, "ready")
                self.say(f"{proc.name} ready at {proc.url}")
                return
            time.sleep(0.5)
        raise RuntimeError(
            f"{proc.name} did not become ready within {READY_TIMEOUT[proc.name]:.0f}s"
        )

    def stop_child(self, name: str) -> None:
        rec = self.records.pop(name, None)
        child = self.children.pop(name, None)
        if rec is not None:
            self.intentional.add(name)
            outcome = procs.stop(rec)
            self.say(f"{name} {outcome}")
            procs.forget(self.rt.pids, name)
        if child is not None:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
            if child.stdin is not None:
                child.stdin.close()
        log = self.logs.pop(name, None)
        if log is not None:
            log.write(f"--- {name} stopped ---")
            log.close()
        self.service(name, "stopped")

    # ---------------------------------------------------------------- reset
    def reset_log(self, line: str) -> None:
        text = logs.redact(line.rstrip())
        self.reset_state["log"] = [*self.reset_state["log"], text][-200:]
        self.say(f"[reset] {text}")

    def demo_reset(self) -> None:
        assert self.plan.demo_root is not None
        self.reset_state.update(
            state="stopping", started_at=_now(), finished_at=None, message=None, log=[]
        )
        try:
            self.reset_log("stopping the demo service")
            self.stop_child("api")
            self.reset_state["state"] = "resetting"
            self.reset_log("running the guarded `fraud-ai demo reset` (synthetic world)")
            env = {**modes.base_env(), "DEMO_MODE": "true"}
            command = [
                python(),
                "-m",
                "fraud_ai",
                "demo",
                "reset",
                "--root",
                str(self.plan.demo_root),
            ]
            run = subprocess.Popen(  # noqa: S603  # nosec B603 - our own fixed command
                command, cwd=REPO, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            assert run.stdout is not None
            for raw in iter(run.stdout.readline, b""):
                self.reset_log(raw.decode("utf-8", errors="replace"))
            if run.wait() != 0:
                raise RuntimeError(f"fraud-ai demo reset exited {run.returncode}")
            self.reset_state["state"] = "starting"
            self.plan = modes.demo_plan(cfg.load(), self.rt, self.console_mode())
            modes.write_credentials(self.plan, self.rt)
            self.intentional.discard("api")
            self.start_child(self.plan.api)
            self.wait_ready(self.plan.api)
            self.reset_state.update(state="ready", message="demo world rebuilt")
        except Exception as exc:
            self.reset_state.update(state="failed", message=str(exc))
            self.reset_log(f"reset failed: {exc}")
        finally:
            self.reset_state["finished_at"] = _now()

    def console_mode(self) -> str:
        return self.plan.console.command[2]

    # -------------------------------------------------------------- control
    def serve_control(self) -> ThreadingHTTPServer:
        supervisor = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # quiet
                return

            def reply(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def authorised(self) -> bool:
                expected = f"Bearer {supervisor.token}"
                given = self.headers.get("Authorization", "")
                if secrets.compare_digest(given.encode(), expected.encode()):
                    return True
                self.reply(
                    401,
                    {
                        "error": {
                            "code": "UNAUTHORISED",
                            "message": "bad control token",
                            "status": 401,
                        }
                    },
                )
                return False

            def do_GET(self) -> None:
                if not self.authorised():
                    return
                if self.path == "/status":
                    self.reply(200, supervisor.reset_state)
                elif self.path == "/session":
                    self.reply(200, supervisor.state)
                else:
                    self.reply(404, {"error": {"code": "NOT_FOUND", "status": 404}})

            def do_POST(self) -> None:
                if not self.authorised():
                    return
                if self.path == "/shutdown":
                    self.reply(202, {"state": "stopping"})
                    supervisor.stopping.set()
                elif self.path == "/reset" and supervisor.plan.mode == modes.DEMO:
                    if supervisor.reset_state["state"] in {"stopping", "resetting", "starting"}:
                        self.reply(
                            409,
                            {
                                "error": {
                                    "code": "RESET_IN_PROGRESS",
                                    "status": 409,
                                    "message": "a reset is already running",
                                }
                            },
                        )
                        return
                    threading.Thread(target=supervisor.demo_reset, daemon=True).start()
                    self.reply(202, supervisor.reset_state)
                else:
                    self.reply(404, {"error": {"code": "NOT_FOUND", "status": 404}})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        control = {"url": f"http://127.0.0.1:{server.server_address[1]}", "token": self.token}
        path = self.rt.run / "control.json"
        path.unlink(missing_ok=True)
        cfg.write_private(path, json.dumps(control))
        return server

    # ------------------------------------------------------------------ run
    def install_signals(self) -> None:
        def handler(signum: int, frame: Any) -> None:
            self.stopping.set()

        for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            sig = getattr(signal, name, None)
            if sig is not None:
                signal.signal(sig, handler)

    def run(self) -> int:
        self.rt.ensure()
        procs_dir = self.rt.pids
        me = psutil.Process(os.getpid())
        own = procs.Record("supervisor", me.pid, me.create_time(), me.cmdline(), time.time())
        own.path(procs_dir).write_text(json.dumps(own.__dict__, indent=2))
        self.install_signals()
        server = self.serve_control()
        code = 0
        try:
            self.save(phase="starting")
            if self.plan.credentials is not None:
                modes.write_credentials(self.plan, self.rt)
            if self.plan.mode == modes.DEMO:
                self.plan.console.env["SENTINEL_DEMO_CONTROL_URL"] = (
                    f"http://127.0.0.1:{server.server_address[1]}"
                )
                self.plan.console.env["SENTINEL_DEMO_CONTROL_TOKEN"] = self.token
            for proc in (self.plan.api, self.plan.console):
                if self.stopping.is_set():
                    break
                self.save(phase=f"starting {proc.name}")
                self.start_child(proc)
                self.wait_ready(proc)
            if not self.stopping.is_set():
                self.save(phase="ready", ready_at=_now())
            self.watch()
        except Exception as exc:
            code = 1
            self.say(f"failed: {exc}")
            self.save(phase="failed", message=str(exc))
        finally:
            self.shutdown(server)
        return code

    def watch(self) -> None:
        while not self.stopping.wait(1.0):
            for name, child in list(self.children.items()):
                if child.poll() is None or name in self.intentional:
                    continue
                self.say(f"{name} exited unexpectedly with code {child.returncode}")
                self.records.pop(name, None)
                procs.forget(self.rt.pids, name)
                self.children.pop(name, None)
                self.service(name, f"exited ({child.returncode})")
                if name == "console":
                    self.save(phase="failed", message="the console exited; see console.log")
                    self.stopping.set()
                else:
                    self.save(phase="degraded", message="the API exited; see api.log")

    def shutdown(self, server: ThreadingHTTPServer) -> None:
        if self.state.get("phase") not in {"failed"}:
            self.save(phase="stopping")
        for name in ("console", "api"):
            self.stop_child(name)
        server.shutdown()
        self.say("supervisor stopped")
        self.log.close()
        for name in ("control.json", "credential", "signing-secret", "state.json"):
            (self.rt.run / name).unlink(missing_ok=True)
        procs.forget(self.rt.pids, "supervisor")


def control(rt: Runtime) -> dict[str, str] | None:
    try:
        data = json.loads((rt.run / "control.json").read_text(encoding="utf-8"))
        return {"url": str(data["url"]), "token": str(data["token"])}
    except (OSError, ValueError, KeyError):
        return None


def call(rt: Runtime, method: str, path: str, timeout: float = 5.0) -> tuple[int, Any] | None:
    info = control(rt)
    if info is None:
        return None
    request = urllib.request.Request(  # noqa: S310  # nosec B310 - 127.0.0.1 only
        info["url"] + path, method=method, headers={"Authorization": f"Bearer {info['token']}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosec B310
            return int(response.status), json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        return int(exc.code), None
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return None


def session(rt: Runtime) -> dict[str, Any] | None:
    try:
        return dict(json.loads((rt.run / "state.json").read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None
