#!/usr/bin/env node
/**
 * `npm run demo`: the SENTINEL console on the synthetic demo world.
 *
 *   1. runs the existing, guarded `fraud-ai demo reset` if no demo world exists;
 *   2. starts `fraud-ai demo start` (the real service, 127.0.0.1:8080);
 *   3. starts the console (127.0.0.1:3000) in DEMO MODE, with the demo API key passed
 *      through 0600 files that only the console server reads;
 *   4. serves a local control endpoint (127.0.0.1, random port, random bearer token) that the
 *      console's RESET DEMO button reaches through its server route. A reset stops the
 *      service, runs `fraud-ai demo reset` (which refuses anything but a demo database), and
 *      starts the service again. There is no other way in: no database access from here.
 *
 * Options (environment): DEMO_ROOT (default ../data/demo), PYTHON (default python3),
 * FRAUD_API_PORT (8080), CONSOLE_PORT (3000), CONSOLE_MODE (dev | start; start needs `npm run build`),
 * DEMO_RESET_ON_START=true to rebuild the world first (used by the end-to-end tests).
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const consoleDir = path.resolve(here, "..");
const repoRoot = path.resolve(consoleDir, "..");
const demoRoot = path.resolve(process.env.DEMO_ROOT || path.join(repoRoot, "data", "demo"));
const python = process.env.PYTHON || "python3";
const apiPort = Number(process.env.FRAUD_API_PORT || 8080);
const consolePort = Number(process.env.CONSOLE_PORT || 3000);
const consoleMode = process.env.CONSOLE_MODE === "start" ? "start" : "dev";
const token = randomBytes(32).toString("hex");
const runtime = mkdtempSync(path.join(tmpdir(), "sentinel-demo-"));
const credentialFile = path.join(runtime, "credential");
const secretFile = path.join(runtime, "signing-secret");

const state = { state: "idle", started_at: null, finished_at: null, message: null, log: [] };
let service = null;
let consoleProc = null;
let busy = false;

function log(line) {
  const text = String(line).replace(/fak_[A-Za-z0-9_.-]+/g, "fak_…"); // never echo a key
  state.log.push(text);
  if (state.log.length > 200) state.log.shift();
  process.stdout.write(`[demo] ${text}\n`);
}

function demoEnv() {
  return { ...process.env, DEMO_MODE: "true", PYTHONUNBUFFERED: "1" };
}

function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(python, ["-m", "fraud_ai", ...args], { cwd: repoRoot, env: demoEnv() });
    const forward = (chunk) => String(chunk).split("\n").filter(Boolean).forEach(log);
    child.stdout.on("data", forward);
    child.stderr.on("data", forward);
    child.on("error", reject);
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`fraud-ai ${args.join(" ")} exited ${code}`))));
  });
}

function writeCredentials() {
  const creds = JSON.parse(readFileSync(path.join(demoRoot, "demo-credentials.json"), "utf8"));
  writeFileSync(credentialFile, creds.credential, { mode: 0o600 });
  writeFileSync(secretFile, creds.signing_secret, { mode: 0o600 });
}

async function waitReady(timeoutMs = 120_000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    try {
      const res = await fetch(`http://127.0.0.1:${apiPort}/v1/ready`);
      if (res.status === 200) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("the demo service did not become ready");
}

async function startService() {
  state.state = "starting";
  service = spawn(python, ["-m", "fraud_ai", "demo", "start", "--root", demoRoot, "--port", String(apiPort)], {
    cwd: repoRoot,
    env: demoEnv(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  const forward = (chunk) => String(chunk).split("\n").filter(Boolean).forEach((l) => process.stdout.write(`[api] ${l.replace(/fak_[A-Za-z0-9_.-]+/g, "fak_…")}\n`));
  service.stdout.on("data", forward);
  service.stderr.on("data", forward);
  const proc = service;
  proc.on("exit", (code) => {
    if (service === proc) {
      service = null;
      if (!busy) {
        state.state = "failed";
        state.message = `the demo service exited (${code})`;
        log(state.message);
      }
    }
  });
  await waitReady();
  writeCredentials();
  state.state = "ready";
  log(`demo service ready on http://127.0.0.1:${apiPort}`);
}

function stopService() {
  return new Promise((resolve) => {
    const proc = service;
    if (!proc) return resolve();
    service = null;
    const timer = setTimeout(() => proc.kill("SIGKILL"), 10_000);
    proc.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    proc.kill("SIGTERM");
  });
}

async function reset() {
  busy = true;
  state.started_at = new Date().toISOString();
  state.finished_at = null;
  state.message = null;
  state.log = [];
  try {
    state.state = "stopping";
    log("stopping the demo service");
    await stopService();
    state.state = "resetting";
    log("running the guarded `fraud-ai demo reset` (synthetic world, deterministic seed)");
    await run(["demo", "reset", "--root", demoRoot]);
    await startService();
    state.message = "demo world rebuilt";
  } catch (err) {
    state.state = "failed";
    state.message = err instanceof Error ? err.message : String(err);
    log(`reset failed: ${state.message}`);
  } finally {
    state.finished_at = new Date().toISOString();
    busy = false;
  }
}

function control() {
  const server = createServer((req, res) => {
    const reply = (status, body) => {
      res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      res.end(JSON.stringify(body));
    };
    if (req.headers.authorization !== `Bearer ${token}`) {
      return reply(401, { error: { code: "UNAUTHORISED", message: "bad control token", status: 401 } });
    }
    if (req.method === "GET" && req.url === "/status") return reply(200, state);
    if (req.method === "POST" && req.url === "/reset") {
      if (busy) return reply(409, { error: { code: "RESET_IN_PROGRESS", message: "a reset is already running", status: 409 } });
      void reset();
      return reply(202, state);
    }
    return reply(404, { error: { code: "NOT_FOUND", message: "unknown control route", status: 404 } });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

function cleanup() {
  consoleProc?.kill("SIGTERM");
  service?.kill("SIGTERM");
  rmSync(runtime, { recursive: true, force: true });
}

async function main() {
  process.on("SIGINT", () => {
    cleanup();
    process.exit(130);
  });
  process.on("SIGTERM", () => {
    cleanup();
    process.exit(143);
  });
  const fresh = process.env.DEMO_RESET_ON_START === "true";
  if (fresh || !existsSync(path.join(demoRoot, "catalogue.json"))) {
    state.state = "resetting";
    log(`${fresh ? "DEMO_RESET_ON_START" : `no demo world in ${demoRoot}`}: running the guarded \`fraud-ai demo reset\``);
    await run(["demo", "reset", "--root", demoRoot]);
  }
  await startService();
  const server = await control();
  const { port } = server.address();
  const next = path.join(consoleDir, "node_modules", ".bin", "next");
  consoleProc = spawn(next, [consoleMode, "-p", String(consolePort), "-H", "127.0.0.1"], {
    cwd: consoleDir,
    stdio: "inherit",
    env: {
      ...process.env,
      FRAUD_API_BASE_URL: `http://127.0.0.1:${apiPort}`,
      FRAUD_API_CREDENTIAL_FILE: credentialFile,
      FRAUD_API_SIGNING_SECRET_FILE: secretFile,
      SENTINEL_ENVIRONMENT: "demo",
      SENTINEL_DEMO_MODE: "true",
      SENTINEL_DEMO_ROOT: demoRoot,
      SENTINEL_DEMO_CONTROL_URL: `http://127.0.0.1:${port}`,
      SENTINEL_DEMO_CONTROL_TOKEN: token,
      SENTINEL_OPERATOR_ID: "rita",
      SENTINEL_OPERATOR_KEY_FILE: path.join(demoRoot, "keys", "operator-rita.pem"),
    },
  });
  consoleProc.on("exit", (code) => {
    cleanup();
    process.exit(code ?? 0);
  });
  log(`SENTINEL console (DEMO MODE): http://127.0.0.1:${consolePort}`);
}

main().catch((err) => {
  log(err instanceof Error ? err.message : String(err));
  cleanup();
  process.exit(1);
});
