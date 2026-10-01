"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, apiGet, apiPost } from "./client";
import * as S from "./schemas";

/**
 * React Query hooks: one per console view. Polling intervals follow the brief (health 10s,
 * queue and feed 5s, summary 10s); polling pauses while the tab is hidden
 * (refetchIntervalInBackground: false) and a failed poll keeps the last data but marks it
 * stale, so old data never looks live.
 */
export const POLL = { health: 10_000, queue: 5_000, feed: 5_000, summary: 10_000, system: 30_000, demo: 1_500 } as const;

export const keys = {
  session: ["session"] as const,
  health: ["health"] as const,
  ready: ["ready"] as const,
  system: ["system"] as const,
  summary: (hours: number) => ["summary", hours] as const,
  feed: (limit: number, decision?: string) => ["feed", limit, decision ?? "all"] as const,
  queue: (status: string) => ["queue", status] as const,
  case: (id: string) => ["case", id] as const,
  search: (q: string) => ["search", q] as const,
  demoScenarios: ["demo", "scenarios"] as const,
  demoStatus: ["demo", "status"] as const,
};

const poll = (ms: number) => ({ refetchInterval: ms, refetchIntervalInBackground: false });

export function useSession() {
  return useQuery({ queryKey: keys.session, queryFn: () => apiGet("/api/session", S.Session), staleTime: 60_000 });
}

export function useHealth() {
  return useQuery({ queryKey: keys.health, queryFn: () => apiGet("/api/fraud/health", S.Health, { retries: 0, timeoutMs: 5_000 }), ...poll(POLL.health) });
}

/** /v1/ready answers 503 with its checks when not ready; both are data, not errors. */
export function useReady() {
  return useQuery({
    queryKey: keys.ready,
    queryFn: () => apiGet("/api/fraud/ready", S.Ready, { retries: 0, timeoutMs: 8_000 }),
    ...poll(POLL.health),
  });
}

export function useSystem() {
  return useQuery({ queryKey: keys.system, queryFn: () => apiGet("/api/fraud/analyst/system", S.System, { timeoutMs: 20_000 }), ...poll(POLL.system) });
}

export function useSummary(hours = 24) {
  return useQuery({ queryKey: keys.summary(hours), queryFn: () => apiGet("/api/fraud/analyst/summary", S.Summary, { query: { hours } }), ...poll(POLL.summary) });
}

export function useFeed(limit = 100, decision?: string, paused = false) {
  return useQuery({
    queryKey: keys.feed(limit, decision),
    queryFn: () => apiGet("/api/fraud/analyst/feed", S.Feed, { query: { limit, decision } }),
    ...poll(POLL.feed),
    refetchInterval: paused ? false : POLL.feed,
  });
}

export function useQueue(status: "open" | "resolved" | "needs_more_information" | "all" = "open") {
  return useQuery({
    queryKey: keys.queue(status),
    queryFn: () => apiGet("/api/fraud/analyst/reviews", S.Queue, { query: { status, limit: 500 } }),
    ...poll(POLL.queue),
  });
}

export function useCase(assessmentId: string | null) {
  return useQuery({
    queryKey: keys.case(assessmentId ?? ""),
    queryFn: () => apiGet(`/api/fraud/analyst/cases/${assessmentId}`, S.Case, { timeoutMs: 20_000 }),
    enabled: Boolean(assessmentId),
    retry: (count, err) => !(err instanceof ApiError && err.kind === "not_found") && count < 1,
  });
}

export const SEARCH_PATTERN = /^[0-9a-fA-F-]{8,36}$/;

export function useSearch(q: string) {
  const trimmed = q.trim();
  return useQuery({
    queryKey: keys.search(trimmed),
    queryFn: () => apiGet("/api/fraud/analyst/search", S.Search, { query: { q: trimmed }, retries: 0 }),
    enabled: SEARCH_PATTERN.test(trimmed) && trimmed.replace(/-/g, "").length >= 8,
    staleTime: 10_000,
  });
}

export function useInvestigate(assessmentId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationKey: ["investigate", assessmentId],
    mutationFn: () => apiPost(`/api/fraud/assessments/${assessmentId}/investigate`, S.Investigation, {}, { timeoutMs: 190_000 }),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.case(assessmentId) }),
  });
}

export type Resolution = "legitimate" | "fraud" | "needs_more_information";

export function useResolve(reviewId: string, assessmentId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationKey: ["resolve", reviewId],
    mutationFn: (vars: { resolution: Resolution; note?: string; assertion?: string }) =>
      apiPost(`/api/reviews/${reviewId}/resolve`, S.ReviewDetail, vars, { timeoutMs: 20_000 }),
    onSettled: async () => {
      await Promise.all([
        qc.invalidateQueries({ queryKey: keys.case(assessmentId) }),
        qc.invalidateQueries({ queryKey: ["queue"] }),
        qc.invalidateQueries({ queryKey: ["feed"] }),
        qc.invalidateQueries({ queryKey: ["summary"] }),
      ]);
    },
  });
}

export function useDemoScenarios(enabled: boolean) {
  return useQuery({ queryKey: keys.demoScenarios, queryFn: () => apiGet("/api/demo/scenarios", S.DemoScenarios), enabled, ...poll(15_000) });
}

export function usePlayScenario() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (label: string) => apiPost(`/api/demo/scenarios/${encodeURIComponent(label)}/play`, S.DemoPlay, {}, { timeoutMs: 120_000 }),
    onSettled: () => qc.invalidateQueries(),
  });
}

export function useDemoStatus(enabled: boolean, fast: boolean) {
  return useQuery({ queryKey: keys.demoStatus, queryFn: () => apiGet("/api/demo/status", S.DemoStatus, { retries: 0 }), enabled, ...poll(fast ? POLL.demo : 10_000) });
}

export function useDemoReset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiPost("/api/demo/reset", S.DemoStatus, { confirm: "RESET DEMO" }, { timeoutMs: 15_000 }),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.demoStatus }),
  });
}
