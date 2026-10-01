import path from "node:path";

import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end tests against the real fraud-ai service on a freshly reset synthetic demo world.
 * `scripts/demo.mjs` (the shared Stage 14 tooling: `scripts/sentinel.py start --mode demo`) runs
 * the guarded `fraud-ai demo reset`, starts the service and serves the production build of the
 * console in DEMO MODE. Run `setup-local` first (it installs and builds).
 */
const API_PORT = Number(process.env.E2E_API_PORT || 8181);
const PORT = Number(process.env.E2E_CONSOLE_PORT || 3100);
const DEMO_ROOT = process.env.E2E_DEMO_ROOT || path.resolve(__dirname, "..", "data", "demo-e2e");

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: Boolean(process.env.CI),
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    viewport: { width: 1600, height: 1000 },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1600, height: 1000 } } }],
  webServer: {
    command: "node scripts/demo.mjs",
    url: `http://127.0.0.1:${PORT}/api/session`,
    timeout: 15 * 60_000, // a fresh demo world takes a few minutes to build
    reuseExistingServer: false,
    // SIGTERM lets scripts/demo.mjs run `sentinel.py stop`; a bare kill would leave the
    // supervisor's services to their lifelines (they still stop, a little later)
    gracefulShutdown: { signal: "SIGTERM", timeout: 30_000 },
    stdout: "pipe",
    stderr: "pipe",
    env: {
      DEMO_ROOT,
      // E2E_REUSE_WORLD=1 skips the rebuild when the world is known to be untouched
      DEMO_RESET_ON_START: process.env.E2E_REUSE_WORLD === "1" ? "false" : "true",
      FRAUD_API_PORT: String(API_PORT),
      CONSOLE_PORT: String(PORT),
      CONSOLE_MODE: "start",
      // its own runtime directory, so a test run never collides with an interactive session
      SENTINEL_RUNTIME_DIR: path.resolve(__dirname, "..", ".runtime", "e2e"),
      ...(process.env.PYTHON ? { PYTHON: process.env.PYTHON } : {}),
    },
  },
});
