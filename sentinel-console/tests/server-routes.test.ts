// @vitest-environment node
/**
 * The console's server routes: secrets stay server-side, the proxy refuses everything not
 * allow-listed, and every demo control is refused outside DEMO MODE.
 */
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { POST as demoReset } from "@/app/api/demo/reset/route";
import { POST as demoPlay } from "@/app/api/demo/scenarios/[label]/play/route";
import { GET as demoScenarios } from "@/app/api/demo/scenarios/route";
import { GET as demoStatus } from "@/app/api/demo/status/route";
import { GET as proxyGet, POST as proxyPost } from "@/app/api/fraud/[...path]/route";
import { POST as resolve } from "@/app/api/reviews/[reviewId]/resolve/route";
import { GET as session } from "@/app/api/session/route";

const CREDENTIAL = "fak_testkey.not-a-real-secret-value";
const SECRET = "signing-secret-not-real";
const REVIEW = "3f0c2c1e-0000-4000-8000-000000000001";
const ORIGIN = { Origin: "http://console.test", Host: "console.test" };

const ENV_KEYS = [
  "FRAUD_API_BASE_URL",
  "FRAUD_API_CREDENTIAL",
  "FRAUD_API_SIGNING_SECRET",
  "SENTINEL_DEMO_MODE",
  "SENTINEL_DEMO_ROOT",
  "SENTINEL_DEMO_CONTROL_URL",
  "SENTINEL_DEMO_CONTROL_TOKEN",
  "SENTINEL_OPERATOR_ID",
  "SENTINEL_OPERATOR_KEY_FILE",
];
let saved: Record<string, string | undefined>;
let backend: ReturnType<typeof vi.fn>;

function operatorKey(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-routes-"));
  const file = path.join(dir, "rita.pem");
  writeFileSync(file, generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  return file;
}

function demoRoot(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-demo-"));
  writeFileSync(
    path.join(dir, "catalogue.json"),
    JSON.stringify({ synthetic: true, seed: 1, users: 200, missing_cases: [], note: "", cases: [{ label: "manual_review", title: "t", story: "s", scenario: "normal", expected_decision: "MANUAL_REVIEW", expected_reasons: [], relaxed_match: false, prelude: [], event: { event_id: "e1", event_type: "TRANSACTION_CREATED" } }] }),
  );
  return dir;
}

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.FRAUD_API_BASE_URL = "http://backend.test";
  process.env.FRAUD_API_CREDENTIAL = CREDENTIAL;
  process.env.FRAUD_API_SIGNING_SECRET = SECRET;
  backend = vi.fn(async () => Response.json({ ok: true }));
  vi.stubGlobal("fetch", backend);
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  vi.unstubAllGlobals();
});

const ctx = <T,>(params: T) => ({ params: Promise.resolve(params) });

describe("session", () => {
  it("never reveals the credential, the signing secret or key paths", async () => {
    process.env.SENTINEL_DEMO_MODE = "true";
    process.env.SENTINEL_OPERATOR_ID = "rita";
    process.env.SENTINEL_OPERATOR_KEY_FILE = "/secret/path/rita.pem";
    const text = await (await session()).text();
    expect(text).not.toContain(CREDENTIAL);
    expect(text).not.toContain("not-a-real-secret");
    expect(text).not.toContain(SECRET);
    expect(text).not.toContain("/secret/path");
    expect(JSON.parse(text)).toMatchObject({ demo_mode: true, backend_configured: true, operator: { mode: "demo_key", operator_id: "rita" } });
  });

  it("ignores a server-held operator key outside DEMO MODE", async () => {
    process.env.SENTINEL_OPERATOR_KEY_FILE = "/any/key.pem";
    const body = await (await session()).json();
    expect(body.operator.mode).toBe("assertion");
    expect(body.problems.join(" ")).toContain("ignored outside DEMO MODE");
  });
});

describe("fraud proxy", () => {
  it("signs allowed requests server-side and relays the answer", async () => {
    const res = await proxyGet(new Request("http://console.test/api/fraud/analyst/feed?limit=5"), ctx({ path: ["analyst", "feed"] }));
    expect(res.status).toBe(200);
    const [url, init] = backend.mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("http://backend.test/v1/analyst/feed?limit=5");
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${CREDENTIAL}`);
    expect(headers["X-Fraud-Signature"]).toMatch(/^v2=[0-9a-f]{64}$/);
    expect(await res.text()).not.toContain(CREDENTIAL);
  });

  it("refuses routes that are not allow-listed without calling the service", async () => {
    const res = await proxyPost(new Request("http://console.test/api/fraud/score", { method: "POST", headers: ORIGIN, body: "{}" }), ctx({ path: ["score"] }));
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe("ROUTE_NOT_ALLOWED");
    expect(backend).not.toHaveBeenCalled();
  });

  it("refuses cross-origin POSTs", async () => {
    const res = await proxyPost(
      new Request(`http://console.test/api/fraud/assessments/${REVIEW}/investigate`, { method: "POST", headers: { Origin: "http://evil.test", Host: "console.test" }, body: "{}" }),
      ctx({ path: ["assessments", REVIEW, "investigate"] }),
    );
    expect(res.status).toBe(403);
    expect(backend).not.toHaveBeenCalled();
  });

  it("reports an unconfigured console instead of calling the service", async () => {
    delete process.env.FRAUD_API_CREDENTIAL;
    const res = await proxyGet(new Request("http://console.test/api/fraud/analyst/system"), ctx({ path: ["analyst", "system"] }));
    expect(res.status).toBe(500);
    expect((await res.json()).error.code).toBe("BACKEND_NOT_CONFIGURED");
  });

  it("reports an unreachable service as 503", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("connect ECONNREFUSED"))));
    const res = await proxyGet(new Request("http://console.test/api/fraud/analyst/system"), ctx({ path: ["analyst", "system"] }));
    expect(res.status).toBe(503);
    expect((await res.json()).error.code).toBe("BACKEND_UNREACHABLE");
  });

  it("keeps /v1/ready's checks when it answers 503", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ status: "not_ready", api_version: "x", checks: { database: "failed" } }, { status: 503 })));
    const res = await proxyGet(new Request("http://console.test/api/fraud/ready"), ctx({ path: ["ready"] }));
    expect(res.status).toBe(503);
    expect((await res.json()).checks.database).toBe("failed");
  });
});

describe("review resolution", () => {
  const req = (body: unknown, headers: Record<string, string> = ORIGIN) =>
    new Request(`http://console.test/api/reviews/${REVIEW}/resolve`, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify(body) });

  it("accepts only the supported outcomes", async () => {
    const res = await resolve(req({ resolution: "delete" }), ctx({ reviewId: REVIEW }));
    expect(res.status).toBe(422);
    expect(backend).not.toHaveBeenCalled();
  });

  it("refuses cross-origin requests", async () => {
    const res = await resolve(req({ resolution: "fraud" }, { Origin: "http://evil.test", Host: "console.test" }), ctx({ reviewId: REVIEW }));
    expect(res.status).toBe(403);
  });

  it("outside DEMO MODE sends no server-made assertion (the analyst must sign)", async () => {
    process.env.SENTINEL_OPERATOR_ID = "rita";
    process.env.SENTINEL_OPERATOR_KEY_FILE = operatorKey();
    vi.stubGlobal("fetch", (backend = vi.fn(async () => Response.json({ error: { code: "OPERATOR_AUTH_REQUIRED", message: "x" } }, { status: 401 }))));
    const res = await resolve(req({ resolution: "fraud" }), ctx({ reviewId: REVIEW }));
    expect(res.status).toBe(401);
    const headers = (backend.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(headers["X-Fraud-Operator-Assertion"]).toBeUndefined();
  });

  it("in DEMO MODE signs a demo reviewer assertion bound to this review and resolution", async () => {
    process.env.SENTINEL_DEMO_MODE = "true";
    process.env.SENTINEL_OPERATOR_ID = "rita";
    process.env.SENTINEL_OPERATOR_KEY_FILE = operatorKey();
    await resolve(req({ resolution: "legitimate" }), ctx({ reviewId: REVIEW }));
    const headers = (backend.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    const claims = JSON.parse(Buffer.from(headers["X-Fraud-Operator-Assertion"]!.split(".")[1]!, "base64url").toString());
    expect(claims).toMatchObject({ sub: "rita", act: "review.resolve", tgt: REVIEW, bnd: { resolution: "legitimate" } });
  });
});

describe("demo controls are DEMO MODE only", () => {
  const confirm = () => new Request("http://console.test/api/demo/reset", { method: "POST", headers: { ...ORIGIN, "Content-Type": "application/json" }, body: JSON.stringify({ confirm: "RESET DEMO" }) });

  it("refuses reset, status, scenarios and play outside DEMO MODE", async () => {
    process.env.SENTINEL_DEMO_ROOT = demoRoot();
    process.env.SENTINEL_DEMO_CONTROL_URL = "http://supervisor.test";
    process.env.SENTINEL_DEMO_CONTROL_TOKEN = "t";
    expect((await demoReset(confirm())).status).toBe(403);
    expect((await demoStatus()).status).toBe(403);
    expect((await demoScenarios()).status).toBe(403);
    expect((await demoPlay(new Request("http://console.test/x", { method: "POST", headers: ORIGIN }), ctx({ label: "manual_review" }))).status).toBe(403);
    expect(backend).not.toHaveBeenCalled();
  });

  it("requires the typed confirmation phrase", async () => {
    process.env.SENTINEL_DEMO_MODE = "true";
    const res = await demoReset(new Request("http://console.test/api/demo/reset", { method: "POST", headers: ORIGIN, body: JSON.stringify({ confirm: "yes" }) }));
    expect(res.status).toBe(422);
    expect(backend).not.toHaveBeenCalled();
  });

  it("refuses a cross-origin reset", async () => {
    process.env.SENTINEL_DEMO_MODE = "true";
    const res = await demoReset(new Request("http://console.test/api/demo/reset", { method: "POST", headers: { Origin: "http://evil.test", Host: "console.test" }, body: JSON.stringify({ confirm: "RESET DEMO" }) }));
    expect(res.status).toBe(403);
  });

  it("in DEMO MODE without the supervisor, says how to enable it", async () => {
    process.env.SENTINEL_DEMO_MODE = "true";
    const res = await demoReset(confirm());
    expect(res.status).toBe(503);
    expect((await res.json()).error.code).toBe("DEMO_CONTROL_UNAVAILABLE");
  });

  it("in DEMO MODE forwards to the supervisor with its token", async () => {
    process.env.SENTINEL_DEMO_MODE = "true";
    process.env.SENTINEL_DEMO_CONTROL_URL = "http://supervisor.test";
    process.env.SENTINEL_DEMO_CONTROL_TOKEN = "control-token";
    vi.stubGlobal("fetch", (backend = vi.fn(async () => Response.json({ state: "stopping", log: [] }, { status: 202 }))));
    const res = await demoReset(confirm());
    expect(res.status).toBe(202);
    const [url, init] = backend.mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("http://supervisor.test/reset");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer control-token");
  });

  it("refuses a catalogue that is not marked synthetic", async () => {
    process.env.SENTINEL_DEMO_MODE = "true";
    const dir = mkdtempSync(path.join(tmpdir(), "sentinel-demo-"));
    writeFileSync(path.join(dir, "catalogue.json"), JSON.stringify({ synthetic: false, cases: [] }));
    process.env.SENTINEL_DEMO_ROOT = dir;
    expect((await demoScenarios()).status).toBe(503);
  });
});
