# Local setup: SENTINEL on your machine (Stage 14)

Three steps from a fresh clone to the analyst console on the synthetic demo world. Windows 11
with PowerShell is the primary target; Linux and macOS use the `.sh` equivalents of every
command. Docker is **not** needed for the demo.

```powershell
git clone https://github.com/smartdigitalsolutions44-ops/fraud-ai.git
cd fraud-ai
.\scripts\setup-local.ps1
.\scripts\sentinel-start.ps1 -Mode Demo
```

```bash
git clone https://github.com/smartdigitalsolutions44-ops/fraud-ai.git
cd fraud-ai
./scripts/setup-local.sh
./scripts/sentinel-start.sh --mode demo
```

`sentinel-start` prints the URL (http://127.0.0.1:3000) and opens it in your browser. Stop
everything with `sentinel-stop`.

**Windows, first time only:** PowerShell refuses to run scripts until you allow it for your
account. Run this once (it allows local scripts and signed downloaded ones), then the
commands above:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Or run any script without changing the policy:
`powershell -ExecutionPolicy Bypass -File .\scripts\setup-local.ps1`.

## 1. Prerequisites

The versions are the ones CI tests and the project declares; nothing newer is needed.

| Tool | Version | Where it comes from | Needed for |
|---|---|---|---|
| Git | any recent | | cloning |
| Python | **3.11** (3.12 and 3.13 accepted) | `pyproject.toml` `requires-python >=3.11`; CI uses 3.11 | everything |
| Node.js | **22 LTS** (at least 20.9) | `sentinel-console/package.json` `engines`; CI uses 22 | the console |
| npm | the one bundled with Node 22 (10.x) | no separate pin | the console |
| Docker Desktop | with Compose v2 (`docker compose`) | no minimum pinned anywhere | Dev and StagingLike modes only |
| PostgreSQL | **16** | CI and `compose.local.yml` use `postgres:16` | Dev mode without Docker (section 7) |
| Redis | **7** (tested on 7.0) | CI uses the runner's `redis-server`; `compose.local.yml` uses `redis:7-alpine` | Dev mode without Docker (section 7) |
| bash | Git for Windows includes it | `deploy/staging/stack.sh` | StagingLike only |

Windows: install Python from python.org and tick **"Add python.exe to PATH"** (the Microsoft
Store alias is skipped by setup). Install Node.js 22 LTS from nodejs.org.

## 2. Commands

| Windows | Linux / macOS | What it does |
|---|---|---|
| `.\scripts\setup-local.ps1` | `./scripts/setup-local.sh` | install or update everything (safe to repeat) |
| `.\scripts\sentinel-start.ps1 -Mode Demo` | `./scripts/sentinel-start.sh --mode demo` | start SENTINEL |
| `.\scripts\sentinel-status.ps1` | `./scripts/sentinel-status.sh` | show every component |
| `.\scripts\sentinel-stop.ps1` | `./scripts/sentinel-stop.sh` | stop what SENTINEL started |
| `.\scripts\sentinel-reset-demo.ps1` | `./scripts/sentinel-reset-demo.sh` | rebuild the demo world (asks you to type RESET DEMO) |

Useful options:
* `sentinel-start`: `-NoBrowser` / `--no-browser`, `-Reset` / `--reset` (rebuild the demo
  world first), `-Foreground` / `--foreground` (stay attached; Ctrl+C stops everything).
* `sentinel-status`: `-Json` / `--json`.
* `sentinel-reset-demo`: `-Confirmation "RESET DEMO"` / `--confirm "RESET DEMO"` for a
  non-interactive reset.
* `setup-local`: `-Docker` / `--docker` (fail if Docker is not usable), `-Force` / `--force`
  (reinstall even if current).

All of them are thin wrappers: the logic lives once, in `scripts/localrun/` (Python), so the
PowerShell and shell versions behave identically.

## 3. What setup does (and does not)

1. Checks Git, Python 3.11+, Node 20.9+ and npm, with a fix for each failure.
2. Creates `.venv` if it does not exist (never recreates an existing one).
3. Installs the backend into it (`pip install -e .[postgres,local]`; on Linux, CPU-only
   PyTorch from the PyTorch index, as CI and the Dockerfile do), only when `pyproject.toml`
   changed since the last install.
4. Installs the console (`npm ci`) only when `package-lock.json` changed, and builds it
   (`next build`) only when its sources changed.
5. Creates `sentinel.local.env` from `sentinel.local.env.example` **once**; it never
   overwrites your copy.
6. Creates `.runtime/` (logs, process records, session files, Dev secrets).
7. Reports whether Docker is usable (only Dev and StagingLike need it).

It never deletes data, never touches a database, and never regenerates a secret. Running it
twice does nothing the second time ("already current" for each step).

## 4. Modes

| | Demo (default) | Dev | StagingLike |
|---|---|---|---|
| Data | the synthetic demo world | a small synthetic world | the staging stack's synthetic world |
| Database | SQLite `data/demo/fraud_ai_demo.db` | PostgreSQL 16 in Docker | PostgreSQL in Docker (least-privilege roles) |
| Shared state | in-memory; **Redis NOT USED** | Redis 7 in Docker | Redis in Docker |
| Docker | not needed | required | required (plus bash) |
| Console | production build, DEMO MODE | `next dev` (hot reload) | not started (see below) |
| Resolutions | signed with the demo reviewer's key (DEMO MODE only) | your own signed operator assertion | n/a |
| Security settings | the demo world's own `demo.env` (signed v2 requests, signed models, operator authentication) | development profile; signed v2 requests and signed models; operator authentication **off** (the console says so) | the staging profile, unchanged |

No mode changes a security setting behind your back: each one's environment is listed in
`scripts/localrun/modes.py`, and the console's start-up screen and System page show the
result (for example Dev's "operator authentication off" is reported as DEGRADED trust).

**Demo** builds its world on first start through the existing, guarded `fraud-ai demo
reset`, which refuses anything but a `*_demo.db` database whose first audit event is the
demo marker. PostgreSQL-backed demo worlds are not offered: the demo builder targets SQLite
only, and supporting both would not be a small change.

**Dev** generates its secrets once into `.runtime/secrets/dev.env` (0600, git-ignored) and
reuses them, so restarting never changes a password the Docker volume was initialised with.
On first start it migrates the database, seeds a small synthetic world with two models
signed by a Dev-only key, and issues the console's API key. PostgreSQL and Redis listen on
127.0.0.1 only, on ports 55432 and 56379 (not 5432/6379, so a local install never
collides). `sentinel-stop` stops the containers and keeps the data; to delete it:
`docker compose -p sentinel-local down -v`.

**StagingLike** runs the existing `deploy/staging/stack.sh up` unchanged (Vault, PostgreSQL
with least-privilege roles, Redis, Object Lock anchors, the signed image) and refuses with a
clear message when Docker or bash is missing. The staging stack issues no analyst API key on
its own, so the console is not started; use `stack.sh check` and the service at
https://127.0.0.1:8443. `sentinel-stop` stops the stack and keeps its data
(`stack.sh down` deletes it). See [DEPLOYMENT.md](DEPLOYMENT.md).

## 5. What `sentinel-start` checks before it says "ready"

In order, failing with a message that says what to do:

1. the backend and console dependencies are installed and current (else: run setup);
2. the ports are free; a busy port is reported with the program holding it (PID and name
   where the OS shows it), and **nothing is stopped**; choose another port in
   `sentinel.local.env`;
3. the console's production build is current (rebuilt automatically if its sources changed);
4. Demo: the demo world exists (built through the guarded reset if not); Dev: Docker is
   running, PostgreSQL and Redis are healthy;
5. the database answers and its schema is at the migration head;
6. a risk policy is active;
7. every model in the deployment (primary and shadow) loads, which verifies its artefact
   digest **and its signature** exactly as the service will;
8. the API answers `/v1/ready` and the console answers, before the URL is printed.

The console then shows its own start-up sequence: seven lines, each tied to a real check
(see [sentinel-console/README.md](sentinel-console/README.md)).

## 6. Processes, logs and ports

* **Only what it started.** Every process gets a record in `.runtime/pids/` with its PID,
  its creation time and its command line. A record counts only if a process with that PID
  *and* that creation time exists; anything else is a stale record and is removed, never
  signalled. Unrelated `python`, `node`, `postgres`, `redis` processes and Docker containers
  are never touched. Containers are addressed only by their compose project
  (`sentinel-local`, or the staging file).
* **Graceful stop.** The supervisor asks each service to stop (SIGTERM to its process
  group on Linux and macOS, CTRL_BREAK on Windows), waits, and only then forces it.
* **Nothing outlives a crash.** Each service runs under a small lifeline
  (`scripts/localrun/lifeline.py`) that stops it if the supervisor disappears for any
  reason, including being killed. The next start also clears verified leftovers.
* **Logs** are in `.runtime/logs/`: `api.log`, `console.log`, `supervisor.log`, and in Dev
  mode `postgres.log` and `redis.log` (written when the containers stop). They rotate at
  5 MB, keeping three old files. API keys are redacted before anything is written.
* **Ports** (all on 127.0.0.1) are set in `sentinel.local.env`: API 8080, console 3000, and
  in Dev PostgreSQL 55432 and Redis 56379. `SENTINEL_OPEN_BROWSER=false` stops the browser
  opening.
* Paths with spaces work: every path the scripts use is quoted, and CI runs the Windows
  scripts from a checkout path containing spaces.

## 7. Without Docker: your own PostgreSQL and Redis

The Demo mode needs neither. For a Dev-like setup on an existing local PostgreSQL 16 and
Redis 7, run the pieces yourself (the tooling deliberately does not automate every possible
installation):

```bash
# once: a role and a database (scripts/dev_postgres.sh does this on Linux)
export DATABASE_URL=postgresql+psycopg://fraud_ai:<password>@127.0.0.1:5432/fraud_ai
export STATE_BACKEND=redis REDIS_URL=redis://127.0.0.1:6379/0
export PSEUDONYMISATION_KEY=<random> SERVICE_SIGNING_MASTER_KEY=<random>
.venv/bin/python -m fraud_ai db migrate
.venv/bin/python scripts/bootstrap_world.py --models .runtime/own/models
.venv/bin/python -m fraud_ai service-key create --name console --scope analyst:read \
  --scope review:read --scope review:write --scope investigation:write --show-signing-secret
.venv/bin/python -m fraud_ai service run          # http://127.0.0.1:8080
# second terminal: the console, with the key printed above
cd sentinel-console
FRAUD_API_BASE_URL=http://127.0.0.1:8080 FRAUD_API_CREDENTIAL=<credential> \
  FRAUD_API_SIGNING_SECRET=<signing> npm run dev
```

On Windows use `$env:NAME = "value"` and `.venv\Scripts\python.exe`. See
[DEPLOYMENT.md](DEPLOYMENT.md) for every setting.

## 8. Optional local LLM

Analyst assistance uses the deterministic reference template by default, and the console
labels it as such. To use a local model, install Ollama, pull a model, and set
`LOCAL_LLM_RUNTIME`, `LOCAL_LLM_MODEL` and `LOCAL_LLM_ENDPOINT` in `sentinel.local.env`
(commented examples are in the file). The tooling passes them to the service; it does not
start Ollama. The LLM never scores or decides; if it is unavailable, case review still
works. See [LLM_ANALYST.md](LLM_ANALYST.md).

## 9. Windows-specific security note

Two backend checks use operating-system features that Windows Python does not have. Stage 14
adds narrow Windows-only branches (Linux, macOS and Docker run exactly the code they ran
before); the trade-off is documented in [TRUST_CHAIN.md](TRUST_CHAIN.md#windows-stage-14):

* **Private key files:** the "not readable by group or others (chmod 600)" check is skipped
  on Windows, because the permission bits Windows Python reports do not describe NTFS access
  control. NTFS permissions (normally your user profile) are the control there. Every other
  check remains: a regular file, no symlink or junction, no hard link, the size limit and
  the format.
* **Model artefacts:** Windows cannot open files relative to one directory handle, so files
  are opened by path after refusing links, junctions and hard links, and the opened file is
  checked to be the file inspected. The window between that check and the open is narrower
  but not closed (the POSIX guarantee is stronger); the digest and Ed25519 signature checks
  on the bytes actually read are unchanged, so any change to content is still refused.

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `running scripts is disabled on this system` | PowerShell's execution policy: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once (see the top of this file). |
| `Python 3.11 or newer is required` | Install Python 3.11 from python.org with "Add python.exe to PATH" ticked, open a **new** terminal, run setup again. |
| `Node.js vX is too old` / `Node.js is not installed` | Install Node.js 22 LTS, open a new terminal, run setup again. |
| `Dev mode needs Docker: ... not running` | Start Docker Desktop and wait until it says "running". Demo mode does not need Docker. |
| `StagingLike needs Docker` or `needs bash` | Start Docker Desktop; on Windows add `C:\Program Files\Git\bin` to PATH (or use WSL). |
| `port 8080 is already in use by <program> (PID n)` | Stop that program yourself, or set `SENTINEL_API_PORT` (or `SENTINEL_CONSOLE_PORT`, `SENTINEL_PG_PORT`, `SENTINEL_REDIS_PORT`) in `sentinel.local.env`. SENTINEL never stops other programs. |
| `database unreachable` (Dev) | `docker compose -p sentinel-local ps` should show PostgreSQL healthy; see `.runtime/logs/postgres.log` after a stop. |
| Redis DEGRADED / `Redis unreachable` (Dev) | `docker compose -p sentinel-local ps`; the service reports shared state as failed until Redis answers. Demo mode does not use Redis. |
| `model ... refused: ModelSignatureError` | A model artefact or its signature changed. Demo: run `sentinel-reset-demo`. Dev: delete `.runtime/dev/` (its models and marker) and start again. |
| `database migrations outdated` | Demo: `sentinel-reset-demo`. Dev: `fraud-ai db migrate` with the Dev environment (start does this). |
| Setup hangs on `Retrying … /whl/cpu/…` (Linux) | Your network blocks `download.pytorch.org`, where setup gets the CPU-only PyTorch wheel. Set the environment variable `SENTINEL_TORCH_INDEX_URL` to a reachable mirror of that index, or to an empty value to use PyPI's PyTorch (a much larger download, with CUDA libraries). Windows and macOS do not use this index. |
| `console dependencies are missing or out of date` | `package-lock.json` changed (for example after `git pull`): run setup again. |
| The console shows OFFLINE | The fraud service is not answering: `sentinel-status`, then `.runtime/logs/api.log`. |
| `start failed` | The last lines of each log are printed; the full logs are in `.runtime/logs/`. |
| Anything else after a crash | `sentinel-stop` cleans up whatever is left (only processes SENTINEL recorded). |

## 11. Time to demo

Measured on the Linux development container (8 vCPU) for this release; Windows and Linux
fresh-checkout timings from CI are recorded in [DEMO.md](DEMO.md#5-time-to-demo).

| | Time |
|---|---|
| `setup-local` on a fresh copy (Python packages already cached locally) | 66 to 79 s |
| `setup-local` again (nothing to do) | 0.5 s |
| First `sentinel-start` (builds the demo world: seeds, trains and signs two models) | 201 to 223 s |
| `sentinel-start` with the world present | 6 to 14 s |
| `sentinel-stop` | about 4 s |
