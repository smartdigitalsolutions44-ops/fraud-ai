"use client";

import { useState } from "react";

import type { CaseT } from "@/lib/api/schemas";

import { categoryLabel, reasonCategory, reasonTitle, scoreBand } from "@/lib/reasons";

import { Badge } from "./Badge";
import { Panel } from "./Panel";
import { RiskBadge } from "./RiskBadge";

type Scalar = string | number | boolean | null;

export function formatValue(v: Scalar | undefined): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(3).replace(/0+$/, "").replace(/\.$/, "");
  return v;
}

const SEVERITY: Record<string, { tone: "red" | "orange" | "amber" | "neutral"; label: string }> = {
  critical: { tone: "red", label: "Critical" },
  high: { tone: "red", label: "High" },
  medium: { tone: "orange", label: "Medium" },
  low: { tone: "amber", label: "Low" },
};

/** Severity exactly as stored: the rule's own severity, or the band a SCORE_BAND_* code names. */
function Severity({ code, rule }: { code: string; rule?: CaseT["rules"][number] }) {
  const band = scoreBand(code);
  if (band) return <RiskBadge level={band} />;
  const s = rule?.severity ? SEVERITY[rule.severity] : undefined;
  if (s) {
    return (
      <Badge tone={s.tone} glyph="●" title="Severity set by the rule in the active policy">
        {s.label} severity
      </Badge>
    );
  }
  return (
    <Badge tone="neutral" glyph="·" title="The policy does not grade this reason">
      Not graded
    </Badge>
  );
}

/**
 * Why the policy decided what it did. Each reason code on the assessment is shown with a
 * readable title, its severity as stored, the service's own description and the stored
 * evidence of the rule that produced it; the raw code stays visible but secondary. Below, every
 * rule the policy evaluated. Nothing here is inferred: an undescribed code says so.
 */
export function EvidencePanel({ reasons, rules, models }: { reasons: CaseT["reasons"]; rules: CaseT["rules"]; models?: CaseT["models"] }) {
  const [showAll, setShowAll] = useState(false);
  const matched = rules.filter((r) => r.matched);
  const other = rules.filter((r) => !r.matched);
  const primary = models?.entries.find((m) => m.role === "primary");
  return (
    <Panel
      title="Why this decision"
      id="evidence"
      flush
      meta={<span>{reasons.length} reason{reasons.length === 1 ? "" : "s"} · {matched.length}/{rules.length} rules matched</span>}
      note="Reasons and rule evidence exactly as stored on the assessment; descriptions come from the service's reason catalogue."
    >
      <ul className="reason-list" aria-label="Reasons for the decision">
        {reasons.length ? (
          reasons.map((r) => {
            const rule = rules.find((x) => x.reason_code === r.code && x.matched);
            const category = reasonCategory(r.code, Boolean(rule));
            const band = scoreBand(r.code);
            return (
              <li key={r.code} className="reason" data-category={category}>
                <div className="reason-head">
                  <Severity code={r.code} rule={rule} />
                  <span className="reason-title">{reasonTitle(r.code)}</span>
                  <span className="reason-code mono" title="Reason code as stored">
                    {r.code}
                  </span>
                </div>
                <p className={r.description ? "reason-desc" : "reason-desc faint"}>
                  {r.description ?? "No description in the service's reason catalogue."}
                </p>
                <div className="reason-meta">
                  <span className="label">{categoryLabel(category)}</span>
                  {band && primary?.calibrated_score !== undefined && primary.calibrated_score !== null ? (
                    <span className="mono faint">
                      calibrated primary score {primary.calibrated_score.toFixed(3)} · {primary.model ?? "primary model"}
                    </span>
                  ) : null}
                  {rule?.rule_id ? <span className="mono faint">rule {rule.rule_id}</span> : null}
                </div>
                {rule && Object.keys(rule.evidence).length ? (
                  <dl className="kv reason-evidence">
                    {Object.entries(rule.evidence).map(([k, v]) => (
                      <Pair key={k} k={k} v={formatValue(v)} />
                    ))}
                  </dl>
                ) : null}
              </li>
            );
          })
        ) : (
          <li className="reason faint">No reason codes on this assessment.</li>
        )}
      </ul>
      <div className="label" style={{ padding: "var(--space-3) var(--space-4) 0" }}>
        Rules evaluated · {matched.length} matched of {rules.length}
      </div>
      <ul className="evidence-list" aria-label="Rules">
        {[...matched, ...(showAll ? other : [])].map((r, i) => (
          <li key={`${r.rule_id}-${i}`} className="evidence-item">
            <div className="evidence-line">
              <span className="mono faint">{r.rule_id ?? "—"}</span>
              <span>{r.reason_code ? reasonTitle(r.reason_code) : r.description ?? "Unnamed rule"}</span>
              {r.matched ? (
                <Badge tone={SEVERITY[r.severity ?? ""]?.tone ?? "neutral"} glyph="●">
                  Matched · {r.severity ?? "—"}
                </Badge>
              ) : r.evaluated === false ? (
                <Badge tone="neutral" glyph="?">
                  Not evaluated
                </Badge>
              ) : (
                <Badge tone="neutral" glyph="○">
                  Not matched · {r.severity ?? "—"}
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
            {showAll ? "Hide" : "Show"} {other.length} rule{other.length === 1 ? "" : "s"} that did not match
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
