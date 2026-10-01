import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { ApiError, apiGet, apiPost, describeError, kindFor } from "@/lib/api/client";

const Shape = z.object({ ok: z.literal(true) });

function respond(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

afterEach(() => vi.unstubAllGlobals());

describe("API client", () => {
  it("parses a valid response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => respond(200, { ok: true, extra: 1 })));
    await expect(apiGet("/api/x", Shape)).resolves.toEqual({ ok: true });
  });

  it("rejects an unexpected shape instead of rendering a guess", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => respond(200, { ok: "yes" })));
    const err = await apiGet("/api/x", Shape).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("SCHEMA_MISMATCH");
    expect((err as ApiError).kind).toBe("schema");
  });

  it("retries a transient GET failure, then succeeds", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(respond(503, { error: { code: "BACKEND_UNREACHABLE", message: "down" } })).mockResolvedValueOnce(respond(200, { ok: true }));
    vi.stubGlobal("fetch", fetch);
    await expect(apiGet("/api/x", Shape)).resolves.toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("never retries a POST (not idempotent)", async () => {
    const fetch = vi.fn(async () => respond(503, { error: { code: "BACKEND_UNREACHABLE", message: "down" } }));
    vi.stubGlobal("fetch", fetch);
    await expect(apiPost("/api/x", Shape, {})).rejects.toMatchObject({ kind: "unavailable" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("does not retry client errors", async () => {
    const fetch = vi.fn(async () => respond(403, { error: { code: "INSUFFICIENT_SCOPE", message: "no" } }));
    vi.stubGlobal("fetch", fetch);
    await expect(apiGet("/api/x", Shape)).rejects.toMatchObject({ kind: "forbidden", code: "INSUFFICIENT_SCOPE" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("reports a network failure as unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("failed"))));
    await expect(apiGet("/api/x", Shape, { retries: 0 })).rejects.toMatchObject({ kind: "unavailable", code: "NETWORK_ERROR" });
  });

  it("times out", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url: string, init: RequestInit) =>
          new Promise((_, reject) => init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))),
      ),
    );
    await expect(apiGet("/api/x", Shape, { retries: 0, timeoutMs: 20 })).rejects.toMatchObject({ kind: "timeout" });
  });

  it("carries Retry-After for rate limits", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => respond(429, { error: { code: "RATE_LIMITED", message: "slow down" } }, { "Retry-After": "7" })));
    const err = (await apiGet("/api/x", Shape).catch((e: unknown) => e)) as ApiError;
    expect(err.kind).toBe("rate_limited");
    expect(describeError(err).detail).toContain("retry in 7s");
  });

  it.each([
    [401, "UNAUTHORISED", "unauthorised"],
    [403, "INSUFFICIENT_SCOPE", "forbidden"],
    [404, "NOT_FOUND", "not_found"],
    [409, "ALREADY_RESOLVED", "conflict"],
    [429, "RATE_LIMITED", "rate_limited"],
    [503, "LLM_UNAVAILABLE", "llm_unavailable"],
    [504, "LLM_TIMEOUT", "llm_unavailable"],
    [502, "INVESTIGATION_FAILED", "llm_unavailable"],
    [503, "BACKEND_UNREACHABLE", "unavailable"],
    [503, "BACKEND_TIMEOUT", "timeout"],
    [500, "INTERNAL", "server"],
  ])("maps %i %s to %s", (status, code, kind) => {
    expect(kindFor(status, code)).toBe(kind);
  });

  it("names the LLM failure plainly", () => {
    expect(describeError(new ApiError(503, "LLM_UNAVAILABLE", "x", "llm_unavailable")).title).toBe("Local analyst model unavailable");
  });
});
