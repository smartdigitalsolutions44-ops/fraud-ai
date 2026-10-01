"""The Stage 14 local tooling (scripts/localrun): config, ports, PID safety, logs, modes, and
the guards around reset. Integration of the whole start/stop cycle runs in CI (local-scripts
job) on Linux and Windows."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

psutil = pytest.importorskip("psutil")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from localrun import bootstrap, cli, config, logs, modes, ports, procs  # noqa: E402
from localrun.paths import Runtime  # noqa: E402


@pytest.fixture
def rt(tmp_path: Path) -> Runtime:
    runtime = Runtime(tmp_path / ".runtime")
    for directory in (runtime.root, runtime.logs, runtime.pids, runtime.run, runtime.secrets):
        directory.mkdir(parents=True, exist_ok=True)
    return runtime


# ------------------------------------------------------------------ config
def test_parse_env_ignores_comments_and_strips_quotes() -> None:
    text = "# comment\nA=1\n\nB = 'two words'\nC=\"x=y\"\nnot a line\n"
    assert config.parse_env(text) == {"A": "1", "B": "two words", "C": "x=y"}


def test_local_file_is_created_once_and_never_overwritten(tmp_path: Path) -> None:
    example, local = tmp_path / "example", tmp_path / "local"
    example.write_text("SENTINEL_API_PORT=8080\n")
    assert config.ensure_local_file(local, example) is True
    local.write_text("SENTINEL_API_PORT=9999\n")
    assert config.ensure_local_file(local, example) is False
    assert local.read_text() == "SENTINEL_API_PORT=9999\n"


def test_settings_validate_ports(tmp_path: Path) -> None:
    local = tmp_path / "local"
    local.write_text("SENTINEL_API_PORT=nope\nSENTINEL_CONSOLE_PORT=80\n")
    settings = config.load(local)
    with pytest.raises(config.ConfigError, match="not a port"):
        settings.port("SENTINEL_API_PORT")
    with pytest.raises(config.ConfigError, match="between"):
        settings.port("SENTINEL_CONSOLE_PORT")
    assert config.load(tmp_path / "missing").port("SENTINEL_API_PORT") == 8080


def test_dev_secrets_are_generated_once_and_kept(rt: Runtime) -> None:
    first = config.dev_secrets(rt)
    assert set(config.DEV_SECRET_KEYS) <= set(first)
    path = rt.secrets / "dev.env"
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0
    assert config.dev_secrets(rt) == first  # a second setup never rotates a DB password
    # a key added in a later version is filled in without touching the existing ones
    text = path.read_text().replace(f"REDIS_PASSWORD={first['REDIS_PASSWORD']}\n", "")
    path.unlink()
    config.write_private(path, text)
    again = config.dev_secrets(rt)
    assert again["POSTGRES_PASSWORD"] == first["POSTGRES_PASSWORD"]
    assert again["REDIS_PASSWORD"] and again["REDIS_PASSWORD"] != first["REDIS_PASSWORD"]


# ------------------------------------------------------------------- ports
def test_port_in_use_is_detected_and_named_but_never_freed() -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        assert not ports.is_free(port)
        assert ports.is_listening(port)
        message = ports.busy_message(port, "SENTINEL_API_PORT")
        assert f"port {port}" in message and "SENTINEL_API_PORT" in message
        assert "Nothing was stopped" in message
        who = ports.owner(port)
        assert who.pid in (None, os.getpid())  # None where the OS hides other users' sockets
    assert ports.is_free(port)


# ------------------------------------------------------------- processes
def _sleeper() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], **procs.spawn_flags()
    )


def test_record_and_stop_only_our_process(rt: Runtime) -> None:
    child = _sleeper()
    try:
        rec = procs.record(rt.pids, "api", child, ["sleeper"])
        assert procs.alive(rt.pids, "api") == rec
        assert procs.stop(rec, timeout=10).startswith("stopped")
        assert child.wait(timeout=10) is not None
    finally:
        child.kill()


def test_reused_pid_is_stale_and_never_signalled(rt: Runtime) -> None:
    # This test process is alive, but the record's creation time is not its own: a reused PID.
    rec = procs.Record("api", os.getpid(), 1.0, ["x"], time.time())
    rec.path(rt.pids).write_text(json.dumps(rec.__dict__))
    assert procs.alive(rt.pids, "api") is None
    assert not rec.path(rt.pids).exists()
    assert procs.stop(rec) == "not running (stale record removed)"


def test_corrupt_or_missing_records_are_harmless(rt: Runtime) -> None:
    (rt.pids / "console.json").write_text("{not json")
    assert procs.load(rt.pids, "console") is None
    assert not (rt.pids / "console.json").exists()
    assert procs.alive(rt.pids, "nothing") is None


def test_stop_escalates_when_the_process_ignores_the_signal(rt: Runtime) -> None:
    if os.name == "nt":
        pytest.skip("POSIX signal handling")
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', flush=True); time.sleep(60)",
        ],
        stdout=subprocess.PIPE,
        **procs.spawn_flags(),
    )
    try:
        assert child.stdout is not None and child.stdout.readline().strip() == b"ready"
        rec = procs.record(rt.pids, "api", child, ["stubborn"])
        assert "forced" in procs.stop(rec, timeout=1)
        assert child.wait(timeout=10) is not None
    finally:
        child.kill()


def test_lifeline_stops_its_service_when_the_supervisor_disappears(tmp_path: Path) -> None:
    """A service must never outlive its supervisor (found when a test runner killed it)."""
    lifeline = Path(__file__).resolve().parents[1] / "scripts" / "localrun" / "lifeline.py"
    marker = tmp_path / "pid"
    service = f"import os, time; open({str(marker)!r}, 'w').write(str(os.getpid())); time.sleep(60)"
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, str(lifeline), sys.executable, "-c", service],
        stdin=subprocess.PIPE,
        **procs.spawn_flags(),
    )
    try:
        deadline = time.monotonic() + 30
        while not marker.exists() or not marker.read_text():
            assert time.monotonic() < deadline, "the service did not start"
            time.sleep(0.1)
        service_pid = int(marker.read_text())
        assert psutil.pid_exists(service_pid)
        assert proc.stdin is not None
        proc.stdin.close()  # what the OS does when the supervisor dies
        proc.wait(timeout=20)
        try:
            gone = psutil.Process(service_pid)
            gone.wait(timeout=15)
        except psutil.NoSuchProcess:
            pass  # already reaped: it stopped
        assert not psutil.pid_exists(service_pid)
    finally:
        proc.kill()


# -------------------------------------------------------------------- logs
def test_logs_redact_keys_and_rotate(tmp_path: Path) -> None:
    path = tmp_path / "api.log"
    log = logs.LogFile(path, max_bytes=200)
    log.write("Authorization: Bearer fak_abc123.SECRETPART done")
    assert "fak_abc123" not in path.read_text() and "fak_…" in path.read_text()
    for index in range(20):
        log.write(f"line {index} " + "x" * 40)
    log.close()
    assert path.with_name("api.log.1").exists()
    assert not path.with_name("api.log.4").exists()  # at most three old files
    assert logs.tail(path, 2)


# ------------------------------------------------------------------- modes
def test_mode_names() -> None:
    assert modes.parse_mode("Demo") == modes.DEMO
    assert modes.parse_mode("StagingLike") == modes.STAGING
    with pytest.raises(modes.ModeError):
        modes.parse_mode("production")


def test_modes_never_inherit_a_database_or_state_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://real-production/db")
    monkeypatch.setenv("REDIS_URL", "redis://elsewhere")
    monkeypatch.setenv("DEMO_MODE", "true")
    env = modes.base_env()
    assert "DATABASE_URL" not in env and "REDIS_URL" not in env and "DEMO_MODE" not in env


def test_demo_plan_uses_the_demo_world_and_marks_redis_not_used(
    rt: Runtime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "demo world"  # a path with a space
    root.mkdir()
    (root / "catalogue.json").write_text("{}")
    (root / "demo.env").write_text(f"DATABASE_URL=sqlite:///{root / 'fraud_ai_demo.db'}\n")
    monkeypatch.setenv("SENTINEL_DEMO_ROOT", str(root))
    monkeypatch.setenv("DATABASE_URL", "postgresql://not-this-one")
    plan = modes.demo_plan(config.load(tmp_path / "none"), rt)
    assert plan.redis == "NOT USED"
    assert plan.api.env["DATABASE_URL"].endswith("fraud_ai_demo.db")
    assert plan.api.env["DEMO_MODE"] == "true"
    assert plan.console.env["SENTINEL_DEMO_MODE"] == "true"
    assert plan.api.env["SERVICE_HOST"] == "127.0.0.1"


def test_demo_plan_refuses_a_missing_world(
    rt: Runtime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENTINEL_DEMO_ROOT", str(tmp_path / "empty"))
    with pytest.raises(modes.ModeError, match="no demo world"):
        modes.demo_plan(config.load(tmp_path / "none"), rt)


# ------------------------------------------------------------------- reset
def test_reset_requires_the_exact_phrase(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SENTINEL_RUNTIME_DIR", str(tmp_path / "rt"))
    called: list[bool] = []
    monkeypatch.setattr(cli.bootstrap, "demo_world", lambda *a, **k: called.append(True))
    assert cli.main(["reset", "--confirm", "reset demo"]) == 1
    assert cli.main(["reset", "--confirm", "yes"]) == 1
    monkeypatch.setattr(sys, "stdin", open(os.devnull))  # noqa: SIM115
    assert cli.main(["reset"]) == 2  # non-interactive without --confirm: refused
    assert called == []
    assert cli.main(["reset", "--confirm", "RESET DEMO"]) == 0
    assert called == [True]


def test_demo_reset_goes_through_the_guard(tmp_path: Path) -> None:
    """The tooling only ever calls the guarded CLI; the guard refuses a non-demo database."""
    env = {
        **modes.base_env(),
        "DEMO_MODE": "true",
        "DATABASE_URL": f"sqlite:///{tmp_path / 'customers.db'}",
    }
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fraud_ai", "demo", "reset", "--root", str(tmp_path / "w")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode != 0
    assert "points elsewhere" in result.stderr + result.stdout


def test_failed_quiet_step_shows_stdout_and_keeps_the_full_log(tmp_path: Path) -> None:
    # next build prints its type errors on stdout and only a summary on stderr
    script = "import sys; print('src/x.ts:1:1 Type error: boom'); sys.exit('Failed to type check.')"
    log = tmp_path / "logs" / "build.log"
    with pytest.raises(bootstrap.SetupError) as failure:
        bootstrap.run([sys.executable, "-c", script], quiet=True, log=log)
    message = str(failure.value)
    assert "Type error: boom" in message
    assert "Failed to type check." in message
    assert str(log) in message
    assert "Type error: boom" in log.read_text(encoding="utf-8")


def test_status_reads_the_service_without_httpx(monkeypatch: pytest.MonkeyPatch) -> None:
    # setup installs .[postgres,local], which has no httpx: status must use the stdlib
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            code = 200 if self.path == "/v1/ready" else 404
            body = json.dumps({"status": "ready" if code == 200 else "missing"}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    monkeypatch.setitem(sys.modules, "httpx", None)  # importing httpx now fails
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        assert cli.api_get(base, "/v1/ready", None) == (200, {"status": "ready"})
        assert cli.api_get(base, "/v1/other", None) == (404, {"status": "missing"})
    finally:
        server.shutdown()
        server.server_close()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = probe.getsockname()[1]
    assert cli.api_get(f"http://127.0.0.1:{closed}", "/v1/ready", None) == (None, None)


def test_console_modules_never_differ_only_in_case() -> None:
    # Windows (NTFS) and macOS resolve "./Nav" and "./nav" to the same file: a component
    # Nav.tsx beside a module nav.ts broke the Windows build. Keep module names unique
    # ignoring case and extension, in every console directory.
    console = Path(__file__).resolve().parents[1] / "sentinel-console"
    clashes = []
    for directory in ("src", "tests", "e2e"):
        for folder, _dirs, files in os.walk(console / directory):
            seen: dict[str, str] = {}
            for name in files:
                stem = name.split(".")[0].lower()
                if stem in seen and seen[stem].split(".")[0] != name.split(".")[0]:
                    clashes.append(f"{folder}: {seen[stem]} / {name}")
                seen.setdefault(stem, name)
    assert clashes == []
