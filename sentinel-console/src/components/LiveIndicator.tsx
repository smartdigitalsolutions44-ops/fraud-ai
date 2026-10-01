"use client";

import type { Liveness } from "@/lib/hooks/useLiveness";

const TEXT: Record<Liveness, string> = {
  live: "Live",
  stale: "Stale",
  offline: "Offline",
  paused: "Paused",
  loading: "Loading",
};

/** "Live · 3s" / "Stale · last update 2m ago": the freshness of a polled view. */
export function LiveIndicator({ state, ageMs }: { state: Liveness; ageMs: number | null }) {
  const seconds = ageMs === null ? null : Math.round(ageMs / 1000);
  const when = seconds === null ? "" : seconds < 60 ? `${seconds}s ago` : `${Math.round(seconds / 60)}m ago`;
  return (
    <span className="flex" style={{ gap: 6, fontSize: "var(--text-xs)" }} role="status" aria-live="polite">
      <span className="live-dot" data-state={state === "live" ? undefined : state === "loading" ? "paused" : state} aria-hidden="true" />
      <span className={state === "stale" ? "text-amber" : state === "offline" ? "text-red" : "muted"}>
        {TEXT[state]}
        {when && state !== "loading" ? <span className="faint"> · {state === "stale" ? `last update ${when}` : when}</span> : null}
      </span>
    </span>
  );
}
