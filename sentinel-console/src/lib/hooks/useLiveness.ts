"use client";

import type { UseQueryResult } from "@tanstack/react-query";

import { usePageVisible } from "./useVisibility";
import { useNow } from "./useNow";

export type Liveness = "live" | "stale" | "offline" | "paused" | "loading";

/**
 * Whether data on screen is current. Data older than three poll intervals, or kept after a
 * failed poll, is "stale" and must be shown as such; it never looks live.
 */
export function useLiveness(query: Pick<UseQueryResult, "dataUpdatedAt" | "isError" | "data" | "isPending">, intervalMs: number) {
  const visible = usePageVisible();
  const now = useNow(1000);
  let state: Liveness;
  if (query.isPending && !query.data) state = "loading";
  else if (!visible) state = "paused";
  else if (query.isError && !query.data) state = "offline";
  else if (query.isError || now - query.dataUpdatedAt > intervalMs * 3) state = "stale";
  else state = "live";
  return { state, updatedAt: query.dataUpdatedAt, ageMs: query.dataUpdatedAt ? now - query.dataUpdatedAt : null };
}
