/** The TypeScript v2 signer must match the Python service byte for byte. The vectors were
 * produced by fraud_ai.service.signatures (tests/fixtures/signing-vectors.json). */
import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { TimestampAllocator, canonicalTarget, parseQsl, signV2 } from "@/lib/server/signing";

const fixture = JSON.parse(readFileSync(path.join(__dirname, "fixtures", "signing-vectors.json"), "utf8")) as {
  secret: string;
  vectors: Array<{ method: string; path: string; query: string; ts: number; body: string; target: string; signature: string }>;
};

describe("v2 request signing", () => {
  it.each(fixture.vectors)("$method $path?$query matches Python", (v) => {
    expect(canonicalTarget(v.path, v.query)).toBe(v.target);
    expect(signV2(fixture.secret, v.method, v.path, v.ts, Buffer.from(v.body, "utf8"), v.query)).toBe(v.signature);
  });

  it("parses queries like Python's parse_qsl(keep_blank_values=True)", () => {
    expect(parseQsl("a=1&b=&c&d=x+y&e=%2F")).toEqual([
      ["a", "1"],
      ["b", ""],
      ["c", ""],
      ["d", "x y"],
      ["e", "/"],
    ]);
  });

  it("changes when any bound part changes", () => {
    const base = signV2("s", "GET", "/v1/x", 1, Buffer.alloc(0), "a=1");
    expect(signV2("s", "POST", "/v1/x", 1, Buffer.alloc(0), "a=1")).not.toBe(base);
    expect(signV2("s", "GET", "/v1/y", 1, Buffer.alloc(0), "a=1")).not.toBe(base);
    expect(signV2("s", "GET", "/v1/x", 2, Buffer.alloc(0), "a=1")).not.toBe(base);
    expect(signV2("s", "GET", "/v1/x", 1, Buffer.from("{}"), "a=1")).not.toBe(base);
    expect(signV2("s", "GET", "/v1/x", 1, Buffer.alloc(0), "a=2")).not.toBe(base);
  });
});

describe("timestamp allocator (the service refuses a replayed signature)", () => {
  it("never hands out the same timestamp twice for the same request", () => {
    const t = new TimestampAllocator();
    const seen = new Set<number>();
    for (let i = 0; i < 50; i++) seen.add(t.next("GET /v1/analyst/feed"));
    expect(seen.size).toBe(50);
  });
  it("stays within the service's clock-skew window", () => {
    const t = new TimestampAllocator(120);
    const now = Math.floor(Date.now() / 1000);
    for (let i = 0; i < 100; i++) expect(Math.abs(t.next("k") - now)).toBeLessThanOrEqual(120);
  });
});
