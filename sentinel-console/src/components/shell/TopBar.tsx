"use client";

import { usePathname } from "next/navigation";

import { Icon } from "@/components/Icon";
import type { Overall } from "@/features/system/checks";
import type { SessionT } from "@/lib/api/schemas";

import { titleFor } from "./nav";

const OVERALL: Record<Overall, { label: string; tone: string; glyph: string }> = {
  checking: { label: "Checking", tone: "blue", glyph: "…" },
  operational: { label: "Operational", tone: "green", glyph: "●" },
  degraded: { label: "Degraded", tone: "amber", glyph: "◐" },
  offline: { label: "Offline", tone: "red", glyph: "○" },
};

export function TopBar({ session, overall, onPalette }: { session?: SessionT; overall: Overall; onPalette: () => void }) {
  const pathname = usePathname();
  const o = OVERALL[overall];
  const operator = session?.operator;
  return (
    <header className="topbar">
      <div className="topbar-title">
        <h1>{titleFor(pathname)}</h1>
        <span className="faint topbar-hide-sm" style={{ fontSize: "var(--text-xs)" }}>
          SENTINEL — Fraud Intelligence &amp; Response
        </span>
      </div>
      <div className="topbar-spacer" />
      <div className="topbar-group">
        {session?.demo_mode ? (
          <span className="demo-ribbon" title="Synthetic demo world: no real customer data">
            DEMO MODE · SYNTHETIC DATA
          </span>
        ) : null}
        <span className="badge tone-neutral topbar-hide-sm" title="Environment reported by the console server">
          ENV {session?.environment ?? "—"}
        </span>
        <span className={`badge tone-${o.tone}`} role="status" aria-label={`System status: ${o.label}`} data-testid="system-status">
          <span className="badge-glyph" aria-hidden="true">
            {o.glyph}
          </span>
          {o.label}
        </span>
        <button type="button" className="btn btn-sm btn-ghost" onClick={onPalette} aria-keyshortcuts="Control+K Meta+K">
          <Icon name="search" />
          <span className="topbar-hide-sm">Search / commands</span>
          <kbd>Ctrl K</kbd>
        </button>
        <span className="flex topbar-hide-sm" style={{ fontSize: "var(--text-xs)" }} title={operator?.note}>
          <Icon name="user" />
          {operator?.mode === "demo_key" ? (
            <span>
              <span className="mono">{operator.operator_id}</span> <span className="text-amber">· demo reviewer</span>
            </span>
          ) : (
            <span className="muted">Analyst · signed assertion per action</span>
          )}
        </span>
      </div>
    </header>
  );
}
