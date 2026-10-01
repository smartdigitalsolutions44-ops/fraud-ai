import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { deriveChecks, overall } from "@/features/system/checks";
import { ApiError } from "@/lib/api/client";
import * as S from "@/lib/api/schemas";

const load = <T,>(name: string, schema: { parse: (v: unknown) => T }) => schema.parse(JSON.parse(readFileSync(path.join(__dirname, "fixtures", `${name}.json`), "utf8")));
const ready = load("ready", S.Ready);
const system = load("system", S.System);
const session = load("session", S.Session);
const state = (checks: ReturnType<typeof deriveChecks>, id: string) => checks.find((c) => c.id === id)?.state;

describe("start-up checks (never faked)", () => {
  it("are all CHECKING before any answer", () => {
    const c = deriveChecks({});
    expect(c.every((x) => x.state === "checking")).toBe(true);
    expect(overall(c)).toBe("checking");
  });

  it("reflect the demo service: Redis not used, audit anchor missing is DEGRADED", () => {
    const c = deriveChecks({ ready, system, session });
    expect(state(c, "database")).toBe("online");
    expect(state(c, "shared_state")).toBe("not_used");
    expect(state(c, "policy")).toBe("online");
    expect(state(c, "model")).toBe("online");
    expect(state(c, "signatures")).toBe("online");
    expect(state(c, "audit")).toBe("degraded"); // this world has no external anchor yet
    expect(state(c, "analyst")).toBe("online");
    expect(overall(c)).toBe("degraded");
  });

  it("marks everything from readiness OFFLINE when the service is unreachable", () => {
    const err = new ApiError(0, "NETWORK_ERROR", "down", "unavailable");
    const c = deriveChecks({ readyError: err, systemError: err, session });
    for (const id of ["database", "shared_state", "policy", "model", "signatures", "audit", "analyst"]) expect(state(c, id)).toBe("offline");
    expect(overall(c)).toBe("offline");
  });

  it("shows a failed database and a failed Redis", () => {
    const c = deriveChecks({ ready: { ...ready, status: "not_ready", checks: { ...ready.checks, database: "failed", shared_state: "failed" } }, system, session });
    expect(state(c, "database")).toBe("offline");
    expect(state(c, "shared_state")).toBe("offline");
    expect(overall(c)).toBe("offline");
  });

  it("marks outdated migrations as a DEGRADED database", () => {
    const c = deriveChecks({ ready: { ...ready, checks: { ...ready.checks, migrations: "outdated" } }, system, session });
    expect(state(c, "database")).toBe("degraded");
  });

  it("reports a missing analyst:read scope as permission denied", () => {
    const c = deriveChecks({ ready, session, systemError: new ApiError(403, "INSUFFICIENT_SCOPE", "no", "forbidden") });
    expect(c.find((x) => x.id === "analyst")?.detail).toContain("permission denied");
    expect(state(c, "analyst")).toBe("offline");
  });

  it("flags a signature that does not match the artefact", () => {
    const models = system.models.map((m) => (m.role === "primary" ? { ...m, signature: { ...m.signature!, matches_artifact: false } } : m));
    expect(state(deriveChecks({ ready, session, system: { ...system, models } }), "signatures")).toBe("offline");
  });

  it("flags a broken audit chain", () => {
    const audit = { ...system.audit, chain: { verified: false, events: 10, reason: "hash mismatch at 4" } };
    expect(state(deriveChecks({ ready, session, system: { ...system, audit } }), "audit")).toBe("offline");
  });

  it("is operational only when every check is online or not used", () => {
    const audit = { ...system.audit, anchor: { anchor_number: 1, sequence: 4, anchored_at: "2026-09-30T21:30:00Z", age_minutes: 1, events_since: 0, key_id: "ed25519:x", store: "file" } };
    expect(overall(deriveChecks({ ready, session, system: { ...system, audit } }))).toBe("operational");
  });
});
