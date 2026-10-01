import "server-only";

import { readFileSync } from "node:fs";

/**
 * Server-side configuration. Read from the environment of the Next.js server process only.
 * None of these values is ever sent to the browser: the client sees `publicSession()`.
 *
 *   FRAUD_API_BASE_URL            the fraud-ai service, e.g. http://127.0.0.1:8080
 *   FRAUD_API_CREDENTIAL(_FILE)   the console's API key (fak_….secret)
 *   FRAUD_API_SIGNING_SECRET(_FILE) its request-signing secret (v2 HMAC)
 *   FRAUD_API_TIMEOUT_MS          default request timeout (10 000)
 *   SENTINEL_ENVIRONMENT          label shown in the UI (e.g. "staging")
 *   SENTINEL_DEMO_MODE            "true" only for the deterministic demo world
 *   SENTINEL_DEMO_ROOT            the demo world directory (catalogue.json)
 *   SENTINEL_DEMO_CONTROL_URL/TOKEN  the local demo supervisor (scripts/demo.mjs)
 *   SENTINEL_OPERATOR_ID / SENTINEL_OPERATOR_KEY_FILE  DEMO ONLY: the demo reviewer's key
 *   SENTINEL_OPERATOR_AUDIENCE    operator assertion audience (default fraud-ai-admin)
 */
export interface ServerConfig {
  baseUrl: string;
  credential: string | null;
  signingSecret: string | null;
  timeoutMs: number;
  environment: string;
  demoMode: boolean;
  demoRoot: string | null;
  demoControlUrl: string | null;
  demoControlToken: string | null;
  operatorId: string | null;
  operatorKeyFile: string | null;
  operatorAudience: string;
  problems: string[];
}

function secret(name: string): string | null {
  const direct = process.env[name];
  if (direct && direct.trim()) return direct.trim();
  const file = process.env[`${name}_FILE`];
  if (file) {
    try {
      const value = readFileSync(file, "utf8").trim();
      return value || null;
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Read on every call (cheap: environment plus two small files) so that a rotated credential
 * file, for example after a demo reset, takes effect without restarting the console.
 */
export function serverConfig(): ServerConfig {
  const problems: string[] = [];
  const demoMode = process.env.SENTINEL_DEMO_MODE === "true";
  const credential = secret("FRAUD_API_CREDENTIAL");
  const signingSecret = secret("FRAUD_API_SIGNING_SECRET");
  if (!credential) problems.push("FRAUD_API_CREDENTIAL is not configured");
  if (!signingSecret) problems.push("FRAUD_API_SIGNING_SECRET is not configured");
  let operatorKeyFile = process.env.SENTINEL_OPERATOR_KEY_FILE || null;
  const operatorId = process.env.SENTINEL_OPERATOR_ID || null;
  if (operatorKeyFile && !demoMode) {
    // A server-held operator key would let anyone using the console act as that person.
    // That is acceptable only for the synthetic demo; elsewhere analysts sign their own.
    problems.push("SENTINEL_OPERATOR_KEY_FILE is ignored outside DEMO MODE");
    operatorKeyFile = null;
  }
  const baseUrl = (process.env.FRAUD_API_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
  const timeout = Number(process.env.FRAUD_API_TIMEOUT_MS || "10000");
  return {
    baseUrl,
    credential,
    signingSecret,
    timeoutMs: Number.isFinite(timeout) && timeout > 0 ? timeout : 10000,
    environment: process.env.SENTINEL_ENVIRONMENT || (demoMode ? "demo" : "unlabelled"),
    demoMode,
    demoRoot: demoMode ? process.env.SENTINEL_DEMO_ROOT || null : null,
    demoControlUrl: demoMode ? process.env.SENTINEL_DEMO_CONTROL_URL || null : null,
    demoControlToken: demoMode ? process.env.SENTINEL_DEMO_CONTROL_TOKEN || null : null,
    operatorId: operatorKeyFile ? operatorId : null,
    operatorKeyFile,
    operatorAudience: process.env.SENTINEL_OPERATOR_AUDIENCE || "fraud-ai-admin",
    problems,
  };
}
