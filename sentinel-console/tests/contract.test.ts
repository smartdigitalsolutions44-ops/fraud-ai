/**
 * Contract: responses captured from the running demo service (synthetic data) must parse
 * with the console's schemas. If the backend changes a shape, this fails before the UI does.
 */
import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import * as S from "@/lib/api/schemas";

const fixture = (name: string): unknown => JSON.parse(readFileSync(path.join(__dirname, "fixtures", `${name}.json`), "utf8"));

const CASES: Array<[string, { safeParse: (v: unknown) => { success: boolean; error?: unknown } }]> = [
  ["health", S.Health],
  ["ready", S.Ready],
  ["session", S.Session],
  ["feed", S.Feed],
  ["queue", S.Queue],
  ["summary", S.Summary],
  ["system", S.System],
  ["case", S.Case],
  ["search", S.Search],
  ["scenarios", S.DemoScenarios],
];

describe("backend contract", () => {
  it.each(CASES)("%s parses", (name, schema) => {
    const result = schema.safeParse(fixture(name));
    if (!result.success) console.error(JSON.stringify(result.error, null, 2).slice(0, 2000));
    expect(result.success).toBe(true);
  });

  it("rejects an unknown shape instead of guessing", () => {
    const feed = fixture("feed") as { items: Array<Record<string, unknown>> };
    const broken = { ...feed, items: [{ ...feed.items[0], decision: 42 }] };
    expect(S.Feed.safeParse(broken).success).toBe(false);
  });

  it("fixtures carry no credentials", () => {
    for (const [name] of CASES) {
      const text = readFileSync(path.join(__dirname, "fixtures", `${name}.json`), "utf8");
      expect(text).not.toMatch(/fak_[A-Za-z0-9]/);
      expect(text).not.toMatch(/PRIVATE KEY|signing_secret/);
    }
  });
});
