#!/usr/bin/env node
/**
 * `npm run demo`: the SENTINEL console on the synthetic demo world, in the foreground.
 *
 * Stage 14: a thin wrapper over the shared local tooling (`scripts/sentinel.py start --mode demo
 * --foreground`), so `npm run demo`, `sentinel-start` and the end-to-end tests all use one
 * implementation: the guarded `fraud-ai demo reset`, the supervisor that runs the API and the
 * console, its RESET DEMO control endpoint (127.0.0.1, random token), logs in .runtime/logs.
 * Ctrl+C (or SIGTERM) stops everything it started, through `sentinel.py stop`.
 *
 * Options (environment, unchanged from Stage 13): DEMO_ROOT (default ../data/demo),
 * PYTHON (default: the repository's .venv, else python3/python), FRAUD_API_PORT (8080),
 * CONSOLE_PORT (3000), CONSOLE_MODE (start | dev; default dev), DEMO_RESET_ON_START=true
 * to rebuild the world first (used by the end-to-end tests). SENTINEL_RUNTIME_DIR moves
 * .runtime (the end-to-end tests use their own).
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const windows = process.platform === "win32";

function python() {
  if (process.env.PYTHON) return process.env.PYTHON;
  const venv = path.join(repoRoot, ".venv", windows ? "Scripts/python.exe" : "bin/python");
  if (existsSync(venv)) return venv;
  return windows ? "python" : "python3";
}

const env = { ...process.env };
if (process.env.DEMO_ROOT) env.SENTINEL_DEMO_ROOT = path.resolve(process.env.DEMO_ROOT);
if (process.env.FRAUD_API_PORT) env.SENTINEL_API_PORT = process.env.FRAUD_API_PORT;
if (process.env.CONSOLE_PORT) env.SENTINEL_CONSOLE_PORT = process.env.CONSOLE_PORT;

const entry = path.join(repoRoot, "scripts", "sentinel.py");
const args = [entry, "start", "--mode", "demo", "--foreground", "--no-browser"];
args.push("--console", process.env.CONSOLE_MODE === "start" ? "start" : "dev");
if (process.env.DEMO_RESET_ON_START === "true") args.push("--reset");

const child = spawn(python(), args, { cwd: repoRoot, env, stdio: "inherit" });
let stopping = false;

function stop(code) {
  if (stopping) return;
  stopping = true;
  // `stop` only touches processes this tooling recorded (PID + creation time), on every OS.
  spawnSync(python(), [entry, "stop"], { cwd: repoRoot, env, stdio: "inherit" });
  child.kill();
  process.exit(code);
}

process.on("SIGINT", () => stop(130));
process.on("SIGTERM", () => stop(143));
if (windows) process.on("SIGBREAK", () => stop(143));
child.on("exit", (code) => {
  if (!stopping) process.exit(code ?? 1);
});
