"use client";

import { useState } from "react";

import type { CaseT } from "@/lib/api/schemas";

import { Badge } from "./Badge";
import { Panel } from "./Panel";

type Scalar = string | number | boolean | null;

export function formatValue(v: Scalar | undefined): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(3).replace(/0+$/, "").replace(/\.$/, "");
  return v;
}

const SEVERITY: Record<string, "red" | "orange" | "amber" | "neutral"> = { critical: "red", high: "red", medium: "orange", low: "amber" };

/**
 * Why the policy decided what it did: the reason codes on the assessment (described by the
 * service's catalogue) and the rules it evaluated, with the stored evidence for each. Nothing
 * here is inferred by the console; an undescribed code says so.
 */
export function EvidencePanel({ reasons, rules }: { reasons: CaseT["reasons"]; rules: CaseT["rules"] }) {
  const [showAll, setShowAll] = useState(false);
  const matched = rules.filter((r) => r.matched);
  const other = rules.filter((r) => !r.matched);
  return (
    <Panel title="Reasons and rule evidence" id="evidence" flush note="Reason codes and rule evidence as stored on the assessment. Rules that did not match are listed for completeness.">
      <ul className="evidence-list" aria-label="Reason codes">
        {reasons.length ? (
          reasons.map((r) => (
            <li key={r.code} className="evidence-item">
              <div className="evidence-line">
                <span className="chip">{r.code}</span>
              </div>
              <span className={r.description ? "muted" : "faint"} style={{ fontSize: "var(--text-sm)" }}>
                {r.description ?? "No description in the service's reason catalogue."}
              </span>
            </li>
          ))
        ) : (
          <li className="evidence-item faint">No reason codes on this assessment.</li>
        )}
      </ul>
      <div className="label" style={{ padding: "var(--space-3) var(--space-4) 0" }}>
        Rules · {matched.length} matched of {rules.length} evaluated
      </div>
      <ul className="evidence-list" aria-label="Rules">
        {[...matched, ...(showAll ? other : [])].map((r, i) => (
          <li key={`${r.rule_id}-${i}`} className="evidence-item">
            <div className="evidence-line">
              <span className="mono faint">{r.rule_id ?? "—"}</span>
              {r.reason_code ? <span className="chip">{r.reason_code}</span> : null}
              {r.matched ? (
                <Badge tone={SEVERITY[r.severity ?? ""] ?? "neutral"} glyph="●">
                  Matched · {r.severity ?? "—"}
                </Badge>
              ) : r.evaluated === false ? (
                <Badge tone="neutral" glyph="?">
                  Not evaluated
                </Badge>
              ) : (
                <Badge tone="neutral" glyph="○">
                  Not matched
                </Badge>
              )}
            </div>
            {r.description ? <span className="muted" style={{ fontSize: "var(--text-sm)" }}>{r.description}</span> : null}
            {Object.keys(r.evidence).length ? (
              <dl className="kv" style={{ fontSize: "var(--text-xs)", marginTop: 4 }}>
                {Object.entries(r.evidence).map(([k, v]) => (
                  <Pair key={k} k={k} v={formatValue(v)} />
                ))}
              </dl>
            ) : null}
            {r.missing.length ? <span className="text-amber" style={{ fontSize: "var(--text-xs)" }}>Missing inputs: {r.missing.join(", ")}</span> : null}
          </li>
        ))}
        {!matched.length && !showAll ? <li className="evidence-item faint" style={{ fontSize: "var(--text-sm)" }}>No rule matched this event.</li> : null}
      </ul>
      {other.length ? (
        <div style={{ padding: "var(--space-2) var(--space-4) var(--space-3)" }}>
          <button type="button" className="btn btn-sm btn-ghost" onClick={() => setShowAll((s) => !s)} aria-expanded={showAll}>
            {showAll ? "Hide" : "Show"} {other.length} rules that did not match
          </button>
        </div>
      ) : null}
    </Panel>
  );
}

function Pair({ k, v }: { k: string; v: string }) {
  return (
    <>
      <dt className="mono">{k}</dt>
      <dd className="mono">{v}</dd>
    </>
  );
}

const GROUP_TITLE: Record<string, string> = { device: "Device", network: "Network", behaviour: "Behaviour" };
const GROUP_NOTE: Record<string, string> = {
  device: "Device history on this account at the time of the event.",
  network: "VPN, proxy, Tor and datacentre addresses are signals, not proof of fraud: many genuine customers use them.",
  behaviour: "Behaviour relative to this account's own history, from the stored feature snapshot.",
};

/** Curated indicators from the stored feature snapshot, grouped; values are verbatim. */
export function IndicatorPanel({ group, indicators }: { group: "device" | "network" | "behaviour"; indicators: CaseT["indicators"] }) {
  const items = indicators.filter((i) => i.group === group);
  return (
    <Panel title={GROUP_TITLE[group]} id={`indicators-${group}`} flush note={GROUP_NOTE[group]}>
      {items.length ? (
        <div className="indicator-grid">
          {items.map((i) => (
            <div key={i.name} className="indicator" title={i.name}>
              <span className="faint" style={{ fontSize: "var(--text-xs)" }}>
                {i.label}
              </span>
              <span className="indicator-value">{i.missing ? <span className="text-amber">missing ({i.missing})</span> : formatValue(i.value)}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty">No stored {group} indicators for this event.</div>
      )}
    </Panel>
  );
}
