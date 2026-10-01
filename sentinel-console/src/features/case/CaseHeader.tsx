import Link from "next/link";

import { Badge } from "@/components/Badge";
import { CopyId } from "@/components/CopyId";
import { DecisionBadge } from "@/components/DecisionBadge";
import { RiskBadge } from "@/components/RiskBadge";
import { StatusBadge } from "@/components/StatusBadge";
import type { CaseT } from "@/lib/api/schemas";
import { priorityLabel } from "@/lib/domain";
import { score, shortId, utcDateTime } from "@/lib/format";
import { reasonTitle } from "@/lib/reasons";

const OUTCOME: Record<string, string> = {
  ALLOW: "Allowed",
  ALLOW_WITH_MONITORING: "Allowed with monitoring",
  STEP_UP_AUTHENTICATION: "Step-up authentication requested",
  MANUAL_REVIEW: "Sent to manual review",
  TEMPORARY_BLOCK: "Temporarily blocked",
};

/** One line an analyst can read first: what the policy did and the stored facts behind it. */
export function caseSummary(data: CaseT): string[] {
  const a = data.assessment;
  const parts = [OUTCOME[a.decision] ?? a.decision];
  const primary = data.models.entries.find((m) => m.role === "primary");
  const lead = data.reasons[0];
  if (lead) {
    const cal = primary?.calibrated_score;
    parts.push(`${reasonTitle(lead.code).toLowerCase()}${lead.code.startsWith("SCORE_BAND_") && cal !== undefined && cal !== null ? ` (calibrated ${score(cal)})` : ""}`);
  }
  if (data.reasons.length > 1) parts.push(`${data.reasons.length - 1} more reason${data.reasons.length > 2 ? "s" : ""}`);
  const matched = data.rules.filter((r) => r.matched).length;
  parts.push(matched ? `${matched} of ${data.rules.length} rules matched` : `no rule matched (${data.rules.length} evaluated)`);
  if (data.models.disagreement) parts.push("models disagree");
  else if (data.models.rated > 1) parts.push("models agree");
  if (a.fallback_used) parts.push("scoring fallback used");
  return parts;
}

export function CaseHeader({ data }: { data: CaseT }) {
  const a = data.assessment;
  const r = data.review;
  const superseded = a.latest_assessment_id !== a.assessment_id;
  return (
    <header className="case-head" data-testid="case-header">
      <div className="case-head-top">
        <span className="label">{r ? "Case" : "Assessment"}</span>
        <h2 title={r?.review_id ?? a.assessment_id}>{shortId(r?.review_id ?? a.assessment_id, 12)}</h2>
        <DecisionBadge decision={a.decision} />
        <RiskBadge level={a.risk_level} />
        {r ? <Badge tone={priorityLabel(r.priority).tone}>{priorityLabel(r.priority).label}</Badge> : null}
        {r ? <StatusBadge kind="review" status={r.status} /> : null}
        {a.fallback_used ? (
          <Badge tone="amber" glyph="!">
            Scoring fallback
          </Badge>
        ) : null}
        {a.mode === "step_up_followup" ? <Badge tone="blue">Step-up follow-up</Badge> : null}
      </div>
      <p className="case-summary" data-testid="case-summary">
        {caseSummary(data).map((part, i) => (
          <span key={i}>{part}</span>
        ))}
      </p>
      <div className="case-facts">
        <div className="case-fact">
          <span className="label">Assessed</span>
          <span className="mono">{utcDateTime(a.assessed_at)}</span>
        </div>
        <div className="case-fact">
          <span className="label">Assessment</span>
          <CopyId id={a.assessment_id} label="assessment" />
        </div>
        <div className="case-fact">
          <span className="label">Event</span>
          <CopyId id={a.event_id} label="event" />
        </div>
        <div className="case-fact">
          <span className="label">Version</span>
          <span className="mono">
            v{a.assessment_version}
            {superseded ? (
              <Link href={`/investigations/${a.latest_assessment_id}`} className="text-blue" style={{ marginLeft: 6 }}>
                newer v →
              </Link>
            ) : null}
          </span>
        </div>
        <div className="case-fact">
          <span className="label">Policy</span>
          <span className="mono">{a.policy_version}</span>
        </div>
        <div className="case-fact">
          <span className="label">Model</span>
          <span className="mono">{a.model_version ?? "—"}</span>
        </div>
        {data.latency_ms.total !== undefined ? (
          <div className="case-fact">
            <span className="label">Scoring</span>
            <span className="mono">{Math.round(data.latency_ms.total)} ms</span>
          </div>
        ) : null}
      </div>
    </header>
  );
}
