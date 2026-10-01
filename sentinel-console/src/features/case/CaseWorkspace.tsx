"use client";

import { EvidencePanel, IndicatorPanel } from "@/components/EvidencePanel";
import { ModelComparison } from "@/components/ModelComparison";
import { Panel } from "@/components/Panel";
import { ErrorState, Skeleton, SkeletonRows } from "@/components/States";
import { DecisionBadge } from "@/components/DecisionBadge";
import { useCase } from "@/lib/api/queries";
import { utcDateTime } from "@/lib/format";

import { Actions } from "./Actions";
import { Activity } from "./Activity";
import { CaseHeader } from "./CaseHeader";
import { Investigation } from "./Investigation";
import { StepUp } from "./StepUp";
import { Timeline } from "./Timeline";

/**
 * The case workspace: timeline (left), investigation (centre), decision (right). Everything
 * shown is returned by GET /v1/analyst/cases/{id}; the console adds no evidence of its own.
 */
export function CaseWorkspace({ assessmentId }: { assessmentId: string }) {
  const q = useCase(assessmentId);
  if (q.isPending) {
    return (
      <div className="stack" role="status" aria-label="Loading case" style={{ gap: 16 }}>
        <div className="case-head">
          <Skeleton width={320} height={24} />
          <Skeleton width="70%" height={14} />
        </div>
        <div className="workspace">
          <div className="panel"><SkeletonRows rows={10} /></div>
          <div className="panel"><SkeletonRows rows={12} /></div>
          <div className="panel"><SkeletonRows rows={6} /></div>
        </div>
      </div>
    );
  }
  if (q.isError || !q.data) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const data = q.data;
  return (
    <div className="stack" style={{ gap: 16 }} data-testid="case-workspace">
      <CaseHeader data={data} />
      <div className="workspace">
        <div className="workspace-col workspace-timeline">
          <Timeline items={data.timeline} />
        </div>
        <div className="workspace-col">
          <EvidencePanel reasons={data.reasons} rules={data.rules} models={data.models} />
          <Panel title="Model assessment" id="models" flush note={data.models.note}>
            <ModelComparison models={data.models} />
          </Panel>
          <div className="grid grid-2">
            <IndicatorPanel group="device" indicators={data.indicators} />
            <IndicatorPanel group="network" indicators={data.indicators} />
          </div>
          <IndicatorPanel group="behaviour" indicators={data.indicators} />
          <Investigation assessmentId={data.assessment.assessment_id} investigation={data.investigation} />
        </div>
        <div className="workspace-col workspace-sticky">
          <Actions data={data} />
          <StepUp data={data} />
          {data.versions.length > 1 ? (
            <Panel title="Assessment versions" flush>
              <ul className="evidence-list">
                {data.versions.map((v) => (
                  <li key={v.assessment_id} className="evidence-item">
                    <div className="evidence-line">
                      <span className="mono">v{v.assessment_version}</span>
                      <DecisionBadge decision={v.decision} />
                      <span className="faint" style={{ fontSize: "var(--text-xs)" }}>
                        {v.mode === "step_up_followup" ? "follow-up" : "original"}
                      </span>
                    </div>
                    <span className="faint mono" style={{ fontSize: "var(--text-2xs)" }}>
                      {utcDateTime(v.assessed_at)}
                    </span>
                  </li>
                ))}
              </ul>
            </Panel>
          ) : null}
          <Activity items={data.activity} />
        </div>
      </div>
    </div>
  );
}
