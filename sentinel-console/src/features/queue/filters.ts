import type { QueueItemT } from "@/lib/api/schemas";
import { ageSeconds } from "@/lib/format";

export type SortKey = "priority" | "newest" | "oldest";
export type AgeFilter = "any" | "lt1h" | "lt24h" | "gt24h";
export type AuthFilter = "any" | "none" | "pending" | "passed" | "failed";

export interface QueueFilters {
  decision: string;
  reason: string;
  age: AgeFilter;
  auth: AuthFilter;
  id: string;
  sort: SortKey;
}

export const DEFAULT_FILTERS: QueueFilters = { decision: "", reason: "", age: "any", auth: "any", id: "", sort: "priority" };

/** Safe identifiers only: hex (with optional dashes). Anything else is ignored, never sent. */
export const ID_FILTER = /^[0-9a-f-]{1,36}$/i;

function authBucket(i: QueueItemT): AuthFilter {
  const r = i.authentication.latest_result?.toLowerCase() ?? null;
  if (i.authentication.attempts === 0 && !r) return "none";
  if (r === "success" || r === "authenticated") return "passed";
  if (r === null || r === "pending") return "pending";
  return "failed"; // failed, expired, cancelled, timeout, unavailable
}

/** Client-side narrowing of the list the service returned (at most 500 items). */
export function applyFilters(items: QueueItemT[], f: QueueFilters, now = Date.now()): QueueItemT[] {
  const id = f.id.trim().toLowerCase().replace(/-/g, "");
  const out = items.filter((i) => {
    if (f.decision && i.decision !== f.decision) return false;
    if (f.reason && !i.reason_codes.includes(f.reason)) return false;
    if (f.auth !== "any" && authBucket(i) !== f.auth) return false;
    if (f.age !== "any") {
      const s = ageSeconds(i.created_at, now);
      if (f.age === "lt1h" && s >= 3600) return false;
      if (f.age === "lt24h" && s >= 86_400) return false;
      if (f.age === "gt24h" && s < 86_400) return false;
    }
    if (id && ID_FILTER.test(f.id.trim())) {
      const ids = [i.review_id, i.assessment_id, i.event_id].map((v) => v.replace(/-/g, "").toLowerCase());
      if (!ids.some((v) => v.startsWith(id))) return false;
    }
    return true;
  });
  const t = (i: QueueItemT) => new Date(i.created_at).getTime();
  out.sort((a, b) => {
    if (f.sort === "newest") return t(b) - t(a);
    if (f.sort === "oldest") return t(a) - t(b);
    return a.priority - b.priority || t(a) - t(b); // 1 is most urgent; then oldest first
  });
  return out;
}

export function reasonOptions(items: QueueItemT[]): string[] {
  return [...new Set(items.flatMap((i) => i.reason_codes))].sort();
}
