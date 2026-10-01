"""``setup``, ``start``, ``stop``, ``status`` and ``reset``: what the wrapper scripts run."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any

from localrun import bootstrap, modes, ports, ui
from localrun import config as cfg
from localrun.paths import IS_WINDOWS, REPO, Runtime, python, runtime

RESET_PHRASE = "RESET DEMO"
STAGING_DIR = REPO / "deploy" / "staging"
STAGING_COMPOSE = STAGING_DIR / "docker-compose.staging.yml"


# =================================================================== setup
def cmd_setup(args: argparse.Namespace) -> int:
    rt = runtime()
    rt.ensure()
    ui.heading("SENTINEL setup")
    created = cfg.ensure_local_file()
    ui.line(
        "ok", "sentinel.local.env " + ("created from the example" if created else "kept (yours)")
    )
    ui.line("ok", f"runtime directory {rt.root}")
    ui.line("ok", f"Python {sys.version.split()[0]} ({python()})")
    ui.line("ok", f"backend: {bootstrap.python_deps(rt, force=args.force)}")
    ui.line("ok", bootstrap.check_node())
    ui.line("ok", f"console dependencies: {bootstrap.console_deps(rt, force=args.force)}")
    ui.line("ok", f"console production build: {bootstrap.console_build(rt, force=args.force)}")
    usable, docker = bootstrap.docker_state()
    if args.docker and not usable:
        raise bootstrap.SetupError(docker)
    ui.line("ok" if usable else "info", docker)
    ui.banner(
        "Setup complete. Next:",
        [
            ("Windows", r".\scripts\sentinel-start.ps1 -Mode Demo"),
            ("Linux/macOS", "./scripts/sentinel-start.sh --mode demo"),
        ],
    )
    return 0


# =================================================================== start
def require_installed(rt: Runtime) -> None:
    probe = subprocess.run(  # noqa: S603  # nosec B603
        [python(), "-c", "import fraud_ai, psutil"], capture_output=True, check=False
    )
    if probe.returncode != 0:
        raise bootstrap.SetupError("the backend is not installed: run setup-local first")
    if not bootstrap.console_deps_current(rt):
        raise bootstrap.SetupError(
            "console dependencies are missing or out of date: run setup-local"
        )


def check_ports(pairs: list[tuple[int, str]]) -> None:
    for port, setting in pairs:
        if not ports.is_free(port):
            raise bootstrap.SetupError(ports.busy_message(port, setting))


def report_preflight(result: dict[str, Any], mode: str) -> None:
    if "error" in result:
        raise bootstrap.SetupError(f"pre-launch check failed: {result['error']}")
    database = result.get("database")
    if database != "ok":
        hint = "" if mode == modes.DEMO else " (is the Docker PostgreSQL container healthy?)"
        raise bootstrap.SetupError(f"database {database}{hint}")
    ui.line("ok", "database reachable")
    if result.get("migrations") != "ok":
        raise bootstrap.SetupError(
            f"database migrations {result.get('migrations')}: "
            + ("run sentinel-reset-demo" if mode == modes.DEMO else "run `fraud-ai db migrate`")
        )
    ui.line("ok", "migrations current")
    if result.get("policy") in (None, "missing"):
        raise bootstrap.SetupError("no active risk policy in the database")
    ui.line("ok", f"active policy {result['policy']}")
    models: dict[str, str] = result.get("models") or {}
    for ref, outcome in models.items():
        if outcome != "ok":
            raise bootstrap.SetupError(f"model {ref} refused: {outcome}")
        ui.line("ok", f"model {ref}: artefact present, digest and signature verified")


def spawn_supervisor(
    mode: str, console_mode: str | None, rt: Runtime, *, foreground: bool
) -> subprocess.Popen[bytes]:
    command = [python(), str(REPO / "scripts" / "sentinel.py"), "supervise", "--mode", mode]
    if console_mode:
        command += ["--console", console_mode]
    out = (rt.logs / "supervisor.out").open("ab")
    kwargs: dict[str, Any] = {
        "cwd": REPO,
        "stdin": subprocess.DEVNULL,
        "stdout": out,
        "stderr": subprocess.STDOUT,
    }
    if IS_WINDOWS:
        from localrun.procs import CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW

        kwargs["creationflags"] = CREATE_NEW_PROCESS_GROUP | (0 if foreground else CREATE_NO_WINDOW)
    else:
        kwargs["start_new_session"] = not foreground
    return subprocess.Popen(command, **kwargs)  # noqa: S603  # nosec B603 - our own script


def wait_session(rt: Runtime, child: subprocess.Popen[bytes], timeout: float) -> dict[str, Any]:
    from localrun import supervisor as sup

    shown: set[str] = set()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = sup.session(rt) or {}
        for name, status in (state.get("services") or {}).items():
            key = f"{name}:{status}"
            if key not in shown and status in {"starting", "ready"}:
                shown.add(key)
                label = {"api": "fraud API", "console": "SENTINEL console"}[name]
                ui.line(
                    "ok" if status == "ready" else "step",
                    f"{label} {'ready' if status == 'ready' else 'starting ...'}",
                )
        if state.get("phase") in {"ready", "failed"}:
            return state
        if child.poll() is not None:
            return {
                **state,
                "phase": "failed",
                "message": state.get("message") or f"supervisor exited ({child.returncode})",
            }
        time.sleep(0.4)
    return {"phase": "failed", "message": f"not ready after {timeout:.0f}s"}


def print_tail(rt: Runtime) -> None:
    from localrun import logs

    for name in ("api", "console", "supervisor"):
        lines = logs.tail(rt.logs / f"{name}.log", 12)
        if lines:
            print(ui.paint(f"\n  last lines of {rt.logs / (name + '.log')}:", "dim"))
            for text in lines:
                print(f"    {text}")


def open_browser(url: str, args: argparse.Namespace, settings: cfg.Settings) -> None:
    if args.no_browser or os.environ.get("CI") or not settings.flag("SENTINEL_OPEN_BROWSER"):
        return
    with contextlib.suppress(webbrowser.Error):
        webbrowser.open(url)


def cmd_start(args: argparse.Namespace) -> int:
    from localrun import procs
    from localrun import supervisor as sup

    rt = runtime()
    rt.ensure()
    mode = modes.parse_mode(args.mode)
    settings = cfg.load()
    started = time.monotonic()
    if mode == modes.STAGING:
        return start_staging(args)
    ui.heading(
        f"SENTINEL: starting {'DEMO MODE (synthetic data)' if mode == modes.DEMO else 'Dev mode'}"
    )
    running = procs.alive(rt.pids, "supervisor")
    if running is not None:
        state = sup.session(rt) or {}
        if state.get("mode") != mode:
            raise bootstrap.SetupError(
                f"a {state.get('mode', 'SENTINEL')} session is already running: "
                "run sentinel-stop first"
            )
        ui.line("ok", f"already running: {state.get('console_url')}")
        return 0
    for name in ("api", "console"):  # left behind by a session that did not stop cleanly
        leftover = procs.alive(rt.pids, name)
        if leftover is not None:
            ui.line(
                "warn", f"{name} from an earlier session was still running: {procs.stop(leftover)}"
            )
        procs.forget(rt.pids, name)
    require_installed(rt)
    ui.line("ok", "backend and console dependencies installed")
    check_ports(
        [
            (settings.port("SENTINEL_API_PORT"), "SENTINEL_API_PORT"),
            (settings.port("SENTINEL_CONSOLE_PORT"), "SENTINEL_CONSOLE_PORT"),
        ]
    )
    ui.line(
        "ok",
        f"ports {settings.get('SENTINEL_API_PORT')} (API) and "
        f"{settings.get('SENTINEL_CONSOLE_PORT')} (console) free",
    )
    console_mode = args.console or ("start" if mode == modes.DEMO else "dev")
    if console_mode == "start":
        ui.line("ok", f"console build: {bootstrap.console_build(rt)}")
    if mode == modes.DEMO:
        ui.line("ok", f"demo world {bootstrap.demo_world(settings, rebuild=args.reset)}")
        plan = modes.demo_plan(settings, rt, console_mode)
        ui.line("info", "Redis: NOT USED in Demo mode (single process, in-memory state)")
    else:
        prepare_dev(settings, rt)
        plan = modes.dev_plan(settings, rt, console_mode)
    report_preflight(bootstrap.preflight(plan.api.env), mode)
    child = spawn_supervisor(mode, console_mode, rt, foreground=args.foreground)
    state = wait_session(rt, child, args.timeout)
    if state.get("phase") != "ready":
        ui.line("fail", f"start failed: {state.get('message')}")
        print_tail(rt)
        stop_session(rt, quiet=True)
        return 1
    elapsed = time.monotonic() - started
    url = plan.console.url
    ui.banner(
        f"SENTINEL is ready ({elapsed:.0f}s)",
        [
            ("Open", url),
            (
                "Mode",
                "DEMO MODE, synthetic data only"
                if mode == modes.DEMO
                else "Dev (development profile)",
            ),
            ("API", plan.api.url),
            ("Database", plan.database),
            ("Redis", plan.redis),
            ("Logs", str(rt.logs)),
            (
                "Stop",
                r".\scripts\sentinel-stop.ps1" if IS_WINDOWS else "./scripts/sentinel-stop.sh",
            ),
        ],
    )
    open_browser(url, args, settings)
    if args.foreground:
        return wait_foreground(rt, child)
    return 0


def wait_foreground(rt: Runtime, child: subprocess.Popen[bytes]) -> int:
    import signal

    def request_stop(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    for name in ("SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            signal.signal(sig, request_stop)
    try:
        return child.wait()
    except KeyboardInterrupt:
        ui.line("step", "stopping ...")
        stop_session(rt, quiet=True)
        return 0


def prepare_dev(settings: cfg.Settings, rt: Runtime) -> None:
    usable, docker = bootstrap.docker_state()
    if not usable:
        raise bootstrap.SetupError(f"Dev mode needs Docker: {docker}")
    ui.line("ok", docker)
    cfg.dev_secrets(rt)
    if not bootstrap.dev_containers_running(settings, rt):
        check_ports(
            [
                (settings.port("SENTINEL_PG_PORT"), "SENTINEL_PG_PORT"),
                (settings.port("SENTINEL_REDIS_PORT"), "SENTINEL_REDIS_PORT"),
            ]
        )
        ui.line("step", "starting PostgreSQL 16 and Redis 7 (Docker, compose.local.yml) ...")
        bootstrap.compose(settings, rt, "up", "-d", "--wait", quiet=True)
        (rt.state / "dev-containers.json").write_text(
            json.dumps({"project": modes.COMPOSE_PROJECT})
        )
    ui.line(
        "ok",
        f"PostgreSQL on 127.0.0.1:{settings.get('SENTINEL_PG_PORT')} and Redis on "
        f"127.0.0.1:{settings.get('SENTINEL_REDIS_PORT')} (Docker)",
    )
    for item in bootstrap.dev_bootstrap(settings, rt):
        ui.line("ok", item)


def staging_command() -> list[str]:
    bash = shutil.which("bash")
    if not bash:
        raise bootstrap.SetupError(
            "StagingLike runs deploy/staging/stack.sh, which needs bash (Git for Windows "
            "includes it: add Git\\bin to PATH, or use WSL)"
        )
    return [bash, str(STAGING_DIR / "stack.sh")]


def start_staging(args: argparse.Namespace) -> int:
    ui.heading("SENTINEL: starting StagingLike (the existing deploy/staging stack)")
    usable, docker = bootstrap.docker_state()
    if not usable:
        raise bootstrap.SetupError(f"StagingLike needs Docker: {docker}. Nothing was started.")
    ui.line("ok", docker)
    command = staging_command()
    ui.line(
        "step",
        "deploy/staging/stack.sh up (Vault, PostgreSQL, Redis, object-lock anchors, "
        "the signed service image; the first run takes a while) ...",
    )
    bootstrap.run([*command, "up"], cwd=STAGING_DIR)
    rt = runtime()
    (rt.state / "staging.json").write_text(json.dumps({"compose": str(STAGING_COMPOSE)}))
    ui.banner(
        "StagingLike is up",
        [
            ("Service", "https://127.0.0.1:8443 (TLS proxy; host staging.fraud-ai.test)"),
            ("Checks", "bash deploy/staging/stack.sh check"),
            (
                "Console",
                "not started: staging issues no analyst key automatically (see LOCAL_SETUP.md)",
            ),
            (
                "Stop",
                r".\scripts\sentinel-stop.ps1" if IS_WINDOWS else "./scripts/sentinel-stop.sh",
            ),
        ],
    )
    return 0


# ==================================================================== stop
def stop_session(rt: Runtime, *, quiet: bool = False) -> list[str]:
    from localrun import procs
    from localrun import supervisor as sup

    outcomes: list[str] = []
    rec = procs.alive(rt.pids, "supervisor")
    if rec is not None:
        sup.call(rt, "POST", "/shutdown")
        proc = procs.process(rec)
        if proc is not None:
            try:
                proc.wait(timeout=40)
                outcomes.append("SENTINEL session stopped")
            except Exception:
                outcomes.append(f"supervisor {procs.stop(rec)}")
        procs.forget(rt.pids, "supervisor")
    for name in ("console", "api"):  # left behind only if the supervisor died
        leftover = procs.alive(rt.pids, name)
        if leftover is not None:
            outcomes.append(f"{name} {procs.stop(leftover)}")
        procs.forget(rt.pids, name)
    for name in ("control.json", "credential", "signing-secret", "state.json"):
        (rt.run / name).unlink(missing_ok=True)
    if not quiet:
        for text in outcomes:
            ui.line("ok", text)
    return outcomes


def save_container_logs(settings: cfg.Settings, rt: Runtime) -> None:
    for service, name in (("postgres", "postgres.log"), ("redis", "redis.log")):
        try:
            out = bootstrap.compose(
                settings, rt, "logs", "--no-color", "--tail", "2000", service, quiet=True
            ).stdout
        except bootstrap.SetupError:
            continue
        from localrun import logs

        logs.rotate(rt.logs / name)
        (rt.logs / name).write_text(out, encoding="utf-8")


def cmd_stop(args: argparse.Namespace) -> int:
    rt = runtime()
    rt.ensure()
    settings = cfg.load()
    ui.heading("SENTINEL: stopping")
    outcomes = stop_session(rt)
    dev_marker = rt.state / "dev-containers.json"
    if dev_marker.exists():
        usable, docker = bootstrap.docker_state()
        if usable:
            save_container_logs(settings, rt)
            bootstrap.compose(settings, rt, "stop", quiet=True)
            ui.line("ok", "Dev PostgreSQL and Redis containers stopped (data kept)")
            outcomes.append("containers")
            dev_marker.unlink()
        else:
            ui.line("warn", f"could not stop the Dev containers: {docker}")
    staging_marker = rt.state / "staging.json"
    if staging_marker.exists():
        docker_bin = shutil.which("docker") or "docker"
        bootstrap.run(
            [docker_bin, "compose", "-f", str(STAGING_COMPOSE), "--profile", "ops", "stop"],
            cwd=STAGING_DIR,
            quiet=True,
        )
        ui.line("ok", "StagingLike stack stopped (data kept; `stack.sh down` deletes it)")
        outcomes.append("staging")
        staging_marker.unlink()
    if not outcomes:
        ui.line("info", "nothing was running (no SENTINEL processes or containers found)")
    return 0


# ================================================================== status
def api_get(base: str, path: str, creds: Path | None) -> tuple[int | None, Any]:
    """GET from the local service with the standard library (setup installs no httpx)."""
    import urllib.error
    import urllib.request

    headers: dict[str, str] = {}
    if creds is not None:
        from fraud_ai.service.signatures import sign_v2

        data = json.loads(creds.read_text(encoding="utf-8"))
        ts = int(time.time())
        bare, _, query = path.partition("?")
        headers = {
            "Authorization": f"Bearer {data['credential']}",
            "X-Fraud-Timestamp": str(ts),
            "X-Fraud-Signature": sign_v2(data["signing_secret"], "GET", bare, ts, b"", query=query),
        }
    request = urllib.request.Request(base + path, headers=headers)  # noqa: S310 - http(s) only
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310  # nosec B310
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
    except (urllib.error.URLError, OSError):
        return None, None
    try:
        return status, json.loads(body)
    except ValueError:
        return status, None


def cmd_status(args: argparse.Namespace) -> int:
    from localrun import procs
    from localrun import supervisor as sup

    rt = runtime()
    rt.ensure()
    settings = cfg.load()
    report: dict[str, Any] = {}
    rec = procs.alive(rt.pids, "supervisor")
    state = sup.session(rt) if rec else None
    mode = (state or {}).get("mode")
    report["session"] = (state or {}).get("phase", "stopped") if rec else "stopped"
    report["mode"] = mode
    api_url = (state or {}).get(
        "api_url"
    ) or f"http://127.0.0.1:{settings.get('SENTINEL_API_PORT')}"
    console_url = (state or {}).get("console_url") or (
        f"http://127.0.0.1:{settings.get('SENTINEL_CONSOLE_PORT')}"
    )
    code, ready = api_get(api_url, "/v1/ready", None)
    checks = (ready or {}).get("checks", {}) if isinstance(ready, dict) else {}
    report["api"] = {
        "url": api_url,
        "status": "ONLINE" if code == 200 else ("DEGRADED" if code == 503 else "OFFLINE"),
        "checks": checks,
    }
    console_code = sup.http_status(console_url + "/api/session")
    report["console"] = {
        "url": console_url,
        "status": "ONLINE" if console_code == 200 else "OFFLINE",
    }
    if mode == modes.DEV or (rt.state / "dev-containers.json").exists():
        report["postgres"] = (
            "ONLINE" if ports.is_listening(settings.port("SENTINEL_PG_PORT")) else "OFFLINE"
        )
        report["redis"] = (
            "ONLINE" if ports.is_listening(settings.port("SENTINEL_REDIS_PORT")) else "OFFLINE"
        )
    else:
        report["postgres"] = (
            "NOT USED (Demo: SQLite demo database)" if mode == modes.DEMO else "NOT USED"
        )
        report["redis"] = "NOT USED"
    creds = None
    if mode == modes.DEMO:
        creds = settings.demo_root / "demo-credentials.json"
    elif mode == modes.DEV:
        creds = rt.secrets / "dev-credentials.json"
    system: dict[str, Any] = {}
    if code is not None and creds is not None and creds.exists():
        sys_code, body = api_get(api_url, "/v1/analyst/system", creds)
        if sys_code == 200 and isinstance(body, dict):
            system = body
    policy = system.get("policy") or {}
    report["policy"] = policy.get("policy_version") or ("unknown" if code else "OFFLINE")
    report["models"] = [
        {
            "ref": m.get("ref"),
            "role": m.get("role"),
            "loaded": m.get("loaded"),
            "signature_verified": (m.get("signature") or {}).get("matches_artifact"),
        }
        for m in system.get("models") or []
    ]
    report["demo_mode"] = mode == modes.DEMO
    llm = system.get("llm") or {}
    report["llm"] = (
        (
            ("available" if llm.get("available") else "unavailable")
            + (
                " (reference template, not an LLM)"
                if llm.get("reference_template")
                else f" ({llm.get('runtime')})"
                if llm.get("runtime")
                else ""
            )
        )
        if llm
        else ("unknown" if code else "OFFLINE")
    )
    report["logs"] = str(rt.logs)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print_status(report)
    return 0


def print_status(r: dict[str, Any]) -> None:
    def mark(value: str) -> str:
        word = str(value).split(" ")[0]
        style = {
            "ONLINE": "ok",
            "ready": "ok",
            "DEGRADED": "warn",
            "degraded": "warn",
            "OFFLINE": "fail",
            "stopped": "dim",
            "failed": "fail",
        }.get(word, "")
        return ui.paint(str(value), style) if style else str(value)

    ui.heading("SENTINEL status")
    rows = [
        ("Session", mark(r["session"]) + (f" ({r['mode']})" if r["mode"] else "")),
        ("Demo mode", "yes, synthetic data only" if r["demo_mode"] else "no"),
        ("API", f"{mark(r['api']['status'])}  {r['api']['url']}"),
        ("Console", f"{mark(r['console']['status'])}  {r['console']['url']}"),
        ("PostgreSQL", mark(r["postgres"])),
        ("Redis", mark(r["redis"])),
        ("Active policy", r["policy"]),
    ]
    for model in r["models"]:
        verified = "signature verified" if model["signature_verified"] else "signature NOT verified"
        rows.append(
            (f"Model ({model['role']})", f"{model['ref']}  loaded={model['loaded']}  {verified}")
        )
    rows += [("LLM", r["llm"]), ("Logs", r["logs"])]
    width = max(len(k) for k, _ in rows) + 2
    for key, value in rows:
        print(f"  {ui.paint(key.ljust(width), 'dim')}{value}")
    failing = {k: v for k, v in r["api"]["checks"].items() if v not in {"ok", "not_required"}}
    if failing:
        print(ui.paint("  readiness: " + ", ".join(f"{k}={v}" for k, v in failing.items()), "warn"))
    print()


# =================================================================== reset
def cmd_reset(args: argparse.Namespace) -> int:
    from localrun import procs
    from localrun import supervisor as sup

    rt = runtime()
    rt.ensure()
    settings = cfg.load()
    ui.heading("SENTINEL: reset the demo world")
    print(f"  This deletes and rebuilds the SYNTHETIC demo world in {settings.demo_root}.")
    print("  It goes through the guarded `fraud-ai demo reset`, which refuses any database that")
    print("  is not a demo database. Analyst resolutions made in the demo are lost.")
    confirm = args.confirm
    if confirm is None:
        if not sys.stdin.isatty():
            raise bootstrap.SetupError(f'not confirmed: pass --confirm "{RESET_PHRASE}"')
        try:
            confirm = input(f"\n  Type {RESET_PHRASE} to continue: ")
        except EOFError:  # Windows reports NUL as a terminal: stdin can still be empty
            raise bootstrap.SetupError(f'not confirmed: pass --confirm "{RESET_PHRASE}"') from None
    if confirm.strip() != RESET_PHRASE:
        ui.line("warn", "not confirmed; nothing was changed")
        return 1
    running = procs.alive(rt.pids, "supervisor")
    state = sup.session(rt) if running else None
    if state and state.get("mode") == modes.DEMO:
        reply = sup.call(rt, "POST", "/reset")
        if reply is None or reply[0] not in (202, 409):
            raise bootstrap.SetupError("the running session did not accept the reset")
        seen = 0
        while True:
            time.sleep(1)
            status = sup.call(rt, "GET", "/status")
            body = status[1] if status else None
            if not isinstance(body, dict):
                continue
            for text in body.get("log", [])[seen:]:
                print(f"    {text}")
            seen = len(body.get("log", []))
            if body.get("state") in {"ready", "failed"}:
                ok = body["state"] == "ready"
                ui.line("ok" if ok else "fail", body.get("message") or body["state"])
                return 0 if ok else 1
    if state is not None:
        raise bootstrap.SetupError("a Dev session is running: the demo reset only applies to Demo")
    bootstrap.demo_world(settings, rebuild=True)
    ui.line("ok", "demo world rebuilt")
    return 0


# ========================================================== internal parts
def cmd_supervise(args: argparse.Namespace) -> int:
    from localrun.supervisor import Supervisor

    rt = runtime()
    rt.ensure()
    plan = modes.plan_for(modes.parse_mode(args.mode), cfg.load(), rt, args.console)
    return Supervisor(plan, rt).run()


def cmd_preflight(args: argparse.Namespace) -> int:
    from localrun import preflight

    preflight.main()
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="SENTINEL local tooling")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("setup", help="install or update everything (safe to repeat)")
    s.add_argument("--docker", action="store_true", help="fail if Docker is not usable")
    s.add_argument("--force", action="store_true", help="reinstall even if current")
    s.set_defaults(func=cmd_setup)
    s = sub.add_parser("start", help="start SENTINEL")
    s.add_argument("--mode", default="demo", help="demo (default) | dev | staginglike")
    s.add_argument("--console", choices=["start", "dev"], help="console server (default by mode)")
    s.add_argument("--reset", action="store_true", help="Demo: rebuild the demo world first")
    s.add_argument("--foreground", action="store_true", help="stay attached; Ctrl+C stops")
    s.add_argument("--no-browser", action="store_true", help="do not open the browser")
    s.add_argument("--timeout", type=float, default=420.0, help="seconds to wait for ready")
    s.set_defaults(func=cmd_start)
    s = sub.add_parser("stop", help="stop what SENTINEL started (nothing else)")
    s.set_defaults(func=cmd_stop)
    s = sub.add_parser("status", help="show every component")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)
    s = sub.add_parser("reset", help="rebuild the demo world (guarded, confirmed)")
    s.add_argument("--confirm", help=f'non-interactive confirmation: exactly "{RESET_PHRASE}"')
    s.set_defaults(func=cmd_reset)
    s = sub.add_parser("supervise", help=argparse.SUPPRESS)
    s.add_argument("--mode", required=True)
    s.add_argument("--console", choices=["start", "dev"])
    s.set_defaults(func=cmd_supervise)
    s = sub.add_parser("preflight", help=argparse.SUPPRESS)
    s.set_defaults(func=cmd_preflight)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (bootstrap.SetupError, modes.ModeError, cfg.ConfigError) as exc:
        ui.line("fail", str(exc))
        return 2
    except KeyboardInterrupt:
        return 130
