import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { DEFAULT_FILTERS, applyFilters, reasonOptions } from "@/features/queue/filters";
import { Queue, type QueueItemT } from "@/lib/api/schemas";

const base = Queue.parse(JSON.parse(readFileSync(path.join(__dirname, "fixtures", "queue.json"), "utf8"))).items[0]!;
const now = Date.parse("2026-10-01T12:00:00Z");
const item = (over: Partial<QueueItemT>): QueueItemT => ({ ...base, ...over });
const items = [
  item({ review_id: "aaaaaaaa-0000-4000-8000-000000000001", priority: 3, created_at: "2026-10-01T11:30:00Z", decision: "MANUAL_REVIEW", reason_codes: ["SCORE_BAND_HIGH"] }),
  item({ review_id: "bbbbbbbb-0000-4000-8000-000000000002", priority: 1, created_at: "2026-09-29T10:00:00Z", decision: "TEMPORARY_BLOCK", reason_codes: ["ATO_RESET_NEW_DEVICE_HIGH_VALUE"] }),
  item({ review_id: "cccccccc-0000-4000-8000-000000000003", priority: 2, created_at: "2026-10-01T09:00:00Z", reason_codes: ["FALLBACK_POLICY_UNAVAILABLE"], authentication: { attempts: 1, latest_result: "FAILED", method: "otp", completed: true } }),
];

describe("review queue filters", () => {
  it("sorts by priority (1 first), then oldest", () => {
    expect(applyFilters(items, DEFAULT_FILTERS, now).map((i) => i.priority)).toEqual([1, 2, 3]);
  });
  it("sorts newest and oldest", () => {
    expect(applyFilters(items, { ...DEFAULT_FILTERS, sort: "newest" }, now)[0]!.priority).toBe(3);
    expect(applyFilters(items, { ...DEFAULT_FILTERS, sort: "oldest" }, now)[0]!.priority).toBe(1);
  });
  it("filters by decision, reason, age and step-up", () => {
    expect(applyFilters(items, { ...DEFAULT_FILTERS, decision: "TEMPORARY_BLOCK" }, now)).toHaveLength(1);
    expect(applyFilters(items, { ...DEFAULT_FILTERS, reason: "SCORE_BAND_HIGH" }, now)).toHaveLength(1);
    expect(applyFilters(items, { ...DEFAULT_FILTERS, age: "lt1h" }, now)).toHaveLength(1);
    expect(applyFilters(items, { ...DEFAULT_FILTERS, age: "gt24h" }, now)).toHaveLength(1);
    expect(applyFilters(items, { ...DEFAULT_FILTERS, auth: "failed" }, now)).toHaveLength(1);
  });
  it("searches by ID prefix only, ignoring dashes and case", () => {
    expect(applyFilters(items, { ...DEFAULT_FILTERS, id: "BBBBBBBB-00" }, now)).toHaveLength(1);
    // a non-ID string is not used as a filter at all (nothing personal is ever searchable)
    expect(applyFilters(items, { ...DEFAULT_FILTERS, id: "alice smith" }, now)).toHaveLength(3);
  });
  it("lists reason codes present", () => {
    expect(reasonOptions(items)).toContain("ATO_RESET_NEW_DEVICE_HIGH_VALUE");
  });
});
