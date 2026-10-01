"use client";

import { useEffect } from "react";

import { Badge } from "@/components/Badge";
import { formatValue } from "@/components/EvidencePanel";
import { Icon } from "@/components/Icon";
import { Panel } from "@/components/Panel";
import { ErrorState } from "@/components/States";
import { ApiError } from "@/lib/api/client";
import { useInvestigate, useSystem } from "@/lib/api/queries";
import type { CaseT } from "@/lib/api/schemas";
import { utcDateTime } from "@/lib/format";

type Inv = NonNullable<CaseT["investigation"]>;
type Finding = { statement: string; evidence_ids: string[] };

const SECTIONS: Array<{ key: keyof Inv["explanation"]; title: string }> = [
  { key: "risk_factors", title: "Risk factors" },
  { key: "protective_factors", title: "Protective factors" },
  { key: "model_disagreement", title: "Model agreement" },
  { key: "temporal_findings", title: "Temporal findings" },
  { key: "uncertainties", title: "Uncertainties" },
];

function EvidenceRefs({ ids, evidence }: { ids: string[]; evidence: Inv["evidence"] }) {
  if (!ids.length) return null;
  return (
    <span className="chips">
      {ids.map((id) => {
        const e = evidence.find((x) => x.id === id);
        const text = e ? `${e.name ?? id} = ${formatValue(e.value)}${e.source ? ` (${e.source})` : ""}` : `${id}: not in the cited evidence`;
        return (
          <span key={id} className="chip" title={text} aria-label={`Evidence ${text}`}>
            {id}
          </span>
        );
      })}
    </span>
  );
}

function FindingList({ items, evidence }: { items: Finding[]; evidence: Inv["evidence"] }) {
  return (
    <div>
      {items.map((f, i) => (
        <div key={i} className="finding">
          <span>{f.statement}</span>
          <EvidenceRefs ids={f.evidence_ids} evidence={evidence} />
        </div>
      ))}
    </div>
  );
}

/**
 * ANALYST ASSISTANCE: an explanation drafted from the case's stored evidence, only when the
 * analyst asks. It never scores, decides or changes anything. If no local model is available
 * the rest of the case is unaffected.
 */
export function Investigation({ assessmentId, investigation }: { assessmentId: string; investigation: CaseT["investigation"] }) {
  const run = useInvestigate(assessmentId);
  const llm = useSystem().data?.llm;
  const unavailable = run.error instanceof ApiError && run.error.kind === "llm_unavailable";
  const { mutate, isPending } = run;

  // R runs the investigation (analyst assistance only: it never changes the decision)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "r" && e.key !== "R") return;
      if (e.ctrlKey || e.metaKey || e.altKey || document.querySelector("[aria-modal='true']")) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName))) return;
      e.preventDefault();
      if (!isPending) mutate();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mutate, isPending]);
  return (
    <Panel
      title={
        <span className="flex">
          <span className="assist-banner">
            <Icon name="spark" /> ANALYST ASSISTANCE
          </span>
          <span>Investigation</span>
        </span>
      }
      id="investigation"
      meta={
        <button
          type="button"
          className="btn btn-sm btn-primary"
          onClick={() => run.mutate()}
          disabled={run.isPending}
          data-testid="run-investigation"
          aria-keyshortcuts="R"
        >
          <Icon name="spark" /> {run.isPending ? "Running…" : investigation ? "Run again" : "Run investigation"} <kbd>R</kbd>
        </button>
      }
      note={
        llm?.reference_template
          ? "Runtime: the deterministic reference template, not a language model. It restates the stored evidence; it is not an independent assessment."
          : "Drafted by the local analyst model from the stored evidence only. It can be wrong; check each cited item."
      }
    >
      {run.isPending ? (
        <div role="status" className="stack">
          <span className="muted">Drafting from the stored evidence…</span>
          <span className="skeleton" style={{ height: 12, width: "80%" }} />
          <span className="skeleton" style={{ height: 12, width: "64%" }} />
        </div>
      ) : null}
      {run.isError ? (
        unavailable ? (
          <div className="state" data-tone="amber" role="alert" data-testid="llm-unavailable">
            <Icon name="alert" className="state-icon text-amber" />
            <div>
              <div className="state-title">Local analyst model unavailable</div>
              <div className="muted">Scoring, decisions and the rest of this case are unaffected. {run.error instanceof ApiError ? `(${run.error.code})` : ""}</div>
            </div>
          </div>
        ) : (
          <ErrorState error={run.error} compact />
        )
      ) : null}
      {investigation ? (
        <div data-testid="investigation-result">
          <div className="flex flex-wrap faint" style={{ fontSize: "var(--text-xs)", marginBottom: 8 }}>
            <Badge tone="cyan">{investigation.runtime === "reference" ? "Reference template" : investigation.runtime}</Badge>
            <span className="mono">{investigation.model}</span>
            <span>· v{investigation.explanation_version}</span>
            <span>· {utcDateTime(investigation.created_at)}</span>
          </div>
          <div className="finding" style={{ fontSize: "var(--text-md)" }}>
            <span>{investigation.explanation.summary.statement}</span>
            <EvidenceRefs ids={investigation.explanation.summary.evidence_ids} evidence={investigation.evidence} />
          </div>
          {SECTIONS.map(({ key, title }) => {
            const items = investigation.explanation[key] as Finding[];
            if (!items?.length) return null;
            return (
              <div key={key} className="finding-section">
                <div className="label">{title}</div>
                <FindingList items={items} evidence={investigation.evidence} />
              </div>
            );
          })}
          {investigation.explanation.recommended_review_questions.length ? (
            <div className="finding-section">
              <div className="label">Questions for the reviewer</div>
              {investigation.explanation.recommended_review_questions.map((q, i) => (
                <div key={i} className="finding">
                  <span>{q.question}</span>
                  <EvidenceRefs ids={q.evidence_ids} evidence={investigation.evidence} />
                </div>
              ))}
            </div>
          ) : null}
          {investigation.limitations.length ? (
            <div className="finding-section">
              <div className="label">Stated limitations</div>
              <ul style={{ margin: "6px 0 0", paddingLeft: 18, color: "var(--text-1)", fontSize: "var(--text-sm)" }}>
                {investigation.limitations.map((l) => (
                  <li key={l.id}>{l.text}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : !run.isPending && !run.isError ? (
        <p className="muted" style={{ fontSize: "var(--text-sm)" }}>
          No investigation has been run for this case. Running one drafts an explanation from the evidence already stored; it does not change the decision.
        </p>
      ) : null}
    </Panel>
  );
}
