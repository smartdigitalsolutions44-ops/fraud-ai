"""Install and prepare: dependencies (only when they changed), the console build, the demo
world (through the guarded reset), Docker for Dev mode, and the one-off Dev bootstrap.

Fingerprints in ``.runtime/state`` record what was installed from which lockfile, so a
second ``setup-local`` skips work that is already current.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

from localrun import config as cfg
from localrun import modes, ui
from localrun.paths import CONSOLE, IS_WINDOWS, REPO, Runtime, python

NODE_MIN = (20, 9)  # sentinel-console/package.json "engines"; CI uses Node 22
PYTHON_MIN = (3, 11)  # pyproject.toml requires-python; CI uses 3.11
PYTHON_EXTRAS = "postgres,local"
TORCH_CPU_INDEX = "https://download.pytorch.org/whl/cpu"
BUILD_INPUTS = ("src", "public", "next.config.ts", "tsconfig.json", "package-lock.json")


class SetupError(Exception):
    """A prerequisite is missing or a step failed (the message says what to do)."""


# ------------------------------------------------------------------ helpers
def fingerprint(paths: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        if path.is_dir():
            files = sorted(p for p in path.rglob("*") if p.is_file())
        elif path.exists():
            files = [path]
        else:
            continue
        for file in files:
            digest.update(file.relative_to(REPO).as_posix().encode())
            digest.update(hashlib.sha256(file.read_bytes()).digest())
    return digest.hexdigest()


def stamp_matches(rt: Runtime, name: str, value: str) -> bool:
    path = rt.state / f"{name}.sha256"
    return path.exists() and path.read_text().strip() == value


def write_stamp(rt: Runtime, name: str, value: str) -> None:
    (rt.state / f"{name}.sha256").write_text(value + "\n")


def run(
    command: list[str], *, cwd: Path = REPO, env: dict[str, str] | None = None, quiet: bool = False
) -> subprocess.CompletedProcess[str]:
    """Run a command, streaming its output unless ``quiet``. Raises SetupError on failure."""
    result = subprocess.run(  # noqa: S603  # nosec B603 - fixed commands, no shell
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=quiet,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()[-8:] if quiet else []
        raise SetupError(
            f"`{' '.join(Path(command[0]).name if i == 0 else c for i, c in enumerate(command))}` "
            f"failed (exit {result.returncode})"
            + ("\n    " + "\n    ".join(detail) if detail else "")
        )
    return result


def version_tuple(text: str) -> tuple[int, ...]:
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not match:
        return ()
    return tuple(int(part) for part in match.groups() if part is not None)


def npm_command() -> str:
    found = shutil.which("npm.cmd" if IS_WINDOWS else "npm") or shutil.which("npm")
    if not found:
        raise SetupError("npm is not on PATH: install Node.js 22 LTS (it includes npm)")
    return found


# ----------------------------------------------------------- prerequisites
def check_node() -> str:
    node = shutil.which("node")
    if not node:
        raise SetupError("Node.js is not installed: install Node.js 22 LTS from nodejs.org")
    version = run([node, "--version"], quiet=True).stdout.strip()
    if version_tuple(version)[:2] < NODE_MIN:
        raise SetupError(
            f"Node.js {version} is too old: SENTINEL needs >= 20.9 (22 LTS recommended)"
        )
    npm = run([npm_command(), "--version"], quiet=True).stdout.strip()
    return f"Node.js {version}, npm {npm}"


def docker_state() -> tuple[bool, str]:
    """(usable, description). Never raises."""
    docker = shutil.which("docker")
    if not docker:
        return False, "Docker is not installed (only Dev and StagingLike need it)"
    try:
        info = subprocess.run(  # noqa: S603  # nosec B603
            [docker, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "Docker did not answer (is Docker Desktop running?)"
    if info.returncode != 0:
        return False, "Docker is installed but not running: start Docker Desktop"
    compose = subprocess.run(  # noqa: S603  # nosec B603
        [docker, "compose", "version", "--short"], capture_output=True, text=True, check=False
    )
    if compose.returncode != 0:
        return False, "Docker Compose v2 is missing (`docker compose`): update Docker Desktop"
    return True, f"Docker {info.stdout.strip()}, Compose {compose.stdout.strip()}"


# ------------------------------------------------------------------- setup
def torch_index() -> list[str]:
    """CPU-only PyTorch on Linux, as CI and the Dockerfile do (PyPI's Linux wheel pulls in
    several GB of CUDA libraries a laptop demo never uses). Windows and macOS wheels on PyPI
    are already CPU-only. ``SENTINEL_TORCH_INDEX_URL`` overrides it; empty disables it."""
    url = os.environ.get("SENTINEL_TORCH_INDEX_URL", TORCH_CPU_INDEX)
    if not url or not sys.platform.startswith("linux"):
        return []
    return ["--extra-index-url", url]


def python_deps(rt: Runtime, force: bool = False) -> str:
    stamp = fingerprint([REPO / "pyproject.toml"])
    probe = subprocess.run(  # noqa: S603  # nosec B603
        [python(), "-c", "import fraud_ai, psutil, psycopg"], capture_output=True, check=False
    )
    if not force and probe.returncode == 0 and stamp_matches(rt, "python-deps", stamp):
        return "already current"
    ui.line("step", f"installing the backend (pip install -e .[{PYTHON_EXTRAS}]) ...")
    command = [python(), "-m", "pip", "install", "--disable-pip-version-check", "-q"]
    command += torch_index()
    run([*command, "-e", f".[{PYTHON_EXTRAS}]"])
    write_stamp(rt, "python-deps", stamp)
    return "installed"


def console_deps(rt: Runtime, force: bool = False) -> str:
    lock = CONSOLE / "package-lock.json"
    stamp = fingerprint([lock])
    installed = (CONSOLE / "node_modules" / "next" / "package.json").exists()
    if not force and installed and stamp_matches(rt, "console-deps", stamp):
        return "already current"
    ui.line("step", "installing the console (npm ci) ...")
    run([npm_command(), "ci", "--no-audit", "--no-fund"], cwd=CONSOLE, quiet=True)
    write_stamp(rt, "console-deps", stamp)
    (rt.state / "console-build.sha256").unlink(missing_ok=True)
    return "installed"


def console_deps_current(rt: Runtime) -> bool:
    return (CONSOLE / "node_modules" / "next" / "package.json").exists() and stamp_matches(
        rt, "console-deps", fingerprint([CONSOLE / "package-lock.json"])
    )


def console_build(rt: Runtime, force: bool = False) -> str:
    stamp = fingerprint([CONSOLE / name for name in BUILD_INPUTS])
    built = (CONSOLE / ".next" / "BUILD_ID").exists()
    if not force and built and stamp_matches(rt, "console-build", stamp):
        return "already current"
    ui.line("step", "building the console (next build, about a minute) ...")
    env = {**os.environ, "NEXT_TELEMETRY_DISABLED": "1"}
    run([npm_command(), "run", "build", "--silent"], cwd=CONSOLE, env=env, quiet=True)
    write_stamp(rt, "console-build", stamp)
    return "built"


# -------------------------------------------------------------------- demo
def demo_world(settings: cfg.Settings, *, rebuild: bool) -> str:
    root = settings.demo_root
    if (root / "catalogue.json").exists() and not rebuild:
        return f"present ({root})"
    reason = "rebuilding" if rebuild else "first run: building"
    ui.line(
        "step",
        f"{reason} the synthetic demo world with the guarded `fraud-ai demo reset` "
        "(trains and signs two models; a few minutes) ...",
    )
    env = {**modes.base_env(), "DEMO_MODE": "true"}
    run([python(), "-m", "fraud_ai", "demo", "reset", "--root", str(root)], env=env)
    return f"built ({root})"


def preflight(env: dict[str, str]) -> dict[str, object]:
    script = REPO / "scripts" / "sentinel.py"
    result = subprocess.run(  # noqa: S603  # nosec B603
        [python(), str(script), "preflight"],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    try:
        return dict(json.loads(result.stdout.strip().splitlines()[-1]))
    except (ValueError, IndexError):
        return {"error": (result.stderr or result.stdout).strip()[-800:]}


# --------------------------------------------------------------------- dev
def compose(
    settings: cfg.Settings, rt: Runtime, *args: str, quiet: bool = False
) -> subprocess.CompletedProcess[str]:
    secrets = cfg.dev_secrets(rt)
    env = {
        **os.environ,
        "SENTINEL_PG_PASSWORD": secrets["POSTGRES_PASSWORD"],
        "SENTINEL_REDIS_PASSWORD": secrets["REDIS_PASSWORD"],
        "SENTINEL_PG_PORT": str(settings.port("SENTINEL_PG_PORT")),
        "SENTINEL_REDIS_PORT": str(settings.port("SENTINEL_REDIS_PORT")),
    }
    docker = shutil.which("docker") or "docker"
    command = [docker, "compose", "-p", modes.COMPOSE_PROJECT, "-f", str(modes.COMPOSE_FILE), *args]
    return run(command, env=env, quiet=quiet)


def dev_containers_running(settings: cfg.Settings, rt: Runtime) -> bool:
    try:
        out = compose(settings, rt, "ps", "--status", "running", "-q", quiet=True).stdout
    except SetupError:
        return False
    return len(out.split()) >= 2


def dev_bootstrap(settings: cfg.Settings, rt: Runtime) -> list[str]:
    """Migrate; first run only: seed a small synthetic world, sign its models, issue the
    console's API key. Returns what was done."""
    done: list[str] = []
    rt.dev.mkdir(parents=True, exist_ok=True)
    keys = rt.secrets / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    keys.chmod(0o700)
    model_key, public = keys / "model.pem", keys / "model.pub"
    if not model_key.exists():
        out = run(
            [
                python(),
                "-m",
                "fraud_ai",
                "keys",
                "generate",
                "--purpose",
                "model",
                "--out",
                str(model_key),
            ],
            quiet=True,
        ).stdout
        match = re.search(r"public key\s+(\S+)", out)
        if not match:
            raise SetupError("could not read the generated model public key")
        public.write_text(match.group(1) + "\n")
        done.append("generated the Dev model-signing key")
    env = modes.dev_service_env(settings, rt)
    run([python(), "-m", "fraud_ai", "db", "migrate"], env=env, quiet=True)
    done.append("database migrated")
    marker = rt.dev / "world.json"
    if not marker.exists():
        ui.line(
            "step",
            "first Dev run: seeding a small synthetic world and training two signed "
            "models (a few minutes) ...",
        )
        run(
            [
                python(),
                str(REPO / "scripts" / "bootstrap_world.py"),
                "--models",
                str(rt.dev / "models"),
                "--kinds",
                "gradient-boosting,logistic",
                "--sign-key",
                str(model_key),
            ],
            env=env,
        )
        marker.write_text(json.dumps({"bootstrapped": True}) + "\n")
        done.append("synthetic Dev world created")
    credentials = rt.secrets / "dev-credentials.json"
    if not credentials.exists():
        command = [
            python(),
            "-m",
            "fraud_ai",
            "service-key",
            "create",
            "--name",
            "sentinel-console-dev",
            "--show-signing-secret",
        ]
        for scope in modes.DEV_SCOPES:
            command += ["--scope", scope]
        out = run(command, env=env, quiet=True).stdout
        credential = re.search(r"^credential\s+(\S+)", out, re.MULTILINE)
        signing = re.search(r"^signing\s+(\S+)", out, re.MULTILINE)
        if not credential or not signing:
            raise SetupError("could not read the console API key from `service-key create`")
        cfg.write_private(
            credentials,
            json.dumps({"credential": credential.group(1), "signing_secret": signing.group(1)}),
        )
        done.append("issued the console's Dev API key")
    return done
