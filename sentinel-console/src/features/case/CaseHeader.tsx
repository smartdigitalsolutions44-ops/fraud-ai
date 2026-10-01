import Link from "next/link";

import { Badge } from "@/components/Badge";
import { CopyId } from "@/components/CopyId";
import { DecisionBadge } from "@/components/DecisionBadge";
import { RiskBadge } from "@/components/RiskBadge";
import { StatusBadge } from "@/components/StatusBadge";
import type { CaseT } from "@/lib/api/schemas";
import { priorityLabel } from "@/lib/domain";
import { shortId, utcDateTime } from "@/lib/format";

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
