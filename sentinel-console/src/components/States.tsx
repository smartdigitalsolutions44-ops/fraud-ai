"use client";

import type { CSSProperties, ReactNode } from "react";

import { describeError } from "@/lib/api/client";

import { Icon } from "./Icon";

export function Skeleton({ width = "100%", height = 12, style }: { width?: number | string; height?: number; style?: CSSProperties }) {
  return <span className="skeleton" aria-hidden="true" style={{ width, height, ...style }} />;
}

export function SkeletonRows({ rows = 6, label = "Loading" }: { rows?: number; label?: string }) {
  return (
    <div role="status" aria-label={label} style={{ display: "grid", gap: 10, padding: 16 }}>
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} height={14} width={`${92 - ((i * 17) % 35)}%`} />
      ))}
    </div>
  );
}

const HINTS: Record<string, string> = {
  unavailable: "The fraud service or the console server did not answer. Data shown elsewhere may be out of date.",
  timeout: "The service took too long to answer. It may be under load; try again shortly.",
  unauthorised: "The console's API credential was not accepted. Check the server configuration.",
  forbidden: "The console's API key does not have the scope for this view.",
  not_found: "Nothing with this identifier exists.",
  rate_limited: "Too many requests. Polling will resume automatically.",
  llm_unavailable: "Scoring, decisions and the rest of the case are unaffected.",
  schema: "The service answered with a shape this console does not understand, so nothing was rendered from it.",
  conflict: "The item changed since it was loaded. Reload it before acting.",
  invalid: "The request was refused as invalid.",
  server: "The service reported an error.",
};

export function ErrorState({ error, onRetry, compact }: { error: unknown; onRetry?: () => void; compact?: boolean }) {
  const { title, detail, kind } = describeError(error);
  const tone = kind === "llm_unavailable" || kind === "rate_limited" || kind === "not_found" ? "amber" : "red";
  return (
    <div className="state" data-tone={tone} role="alert">
      <Icon name="alert" className={`state-icon text-${tone}`} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="state-title">{title}</div>
        {!compact ? <div className="muted">{HINTS[kind]}</div> : null}
        <div className="faint mono" style={{ marginTop: 4, overflowWrap: "anywhere" }}>
          {detail}
        </div>
      </div>
      {onRetry ? (
        <button type="button" className="btn btn-sm" onClick={onRetry}>
          <Icon name="refresh" /> Retry
        </button>
      ) : null}
    </div>
  );
}

export function Notice({ tone = "blue", title, children, icon = "info" }: { tone?: "blue" | "amber" | "red"; title?: ReactNode; children: ReactNode; icon?: "info" | "alert" | "lock" }) {
  return (
    <div className="state" data-tone={tone}>
      <Icon name={icon} className={`state-icon text-${tone}`} />
      <div style={{ minWidth: 0 }}>
        {title ? <div className="state-title">{title}</div> : null}
        <div className="muted">{children}</div>
      </div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
