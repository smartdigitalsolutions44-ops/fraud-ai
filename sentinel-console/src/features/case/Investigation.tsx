"use client";

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

const INTERPRETATION: Array<{ key: keyof Inv["explanation"]; title: string }> = [
  { key: "risk_factors", title: "Points towards risk" },
  { key: "protective_factors", title: "Points against risk" },
  { key: "model_disagreement", title: "Model agreement" },
  { key: "temporal_findings", title: "Timing" },
];

function ObservedEvidence({ evidence }: { evidence: Inv["evidence"] }) {
  if (!evidence.length) return <p className="faint" style={{ fontSize: "var(--text-sm)" }}>No evidence items were cited.</p>;
  return (
    <table className="table assist-evidence">
      <caption className="sr-only">Evidence the draft was given</caption>
      <thead>
        <tr>
          <th scope="col">Ref</th>
          <th scope="col">Item</th>
          <th scope="col">Value</th>
          <th scope="col">Source</th>
        </tr>
      </thead>
      <tbody>
        {evidence.map((e) => (
          <tr key={e.id} id={`evidence-${e.id}`}>
            <td className="mono faint">{e.id}</td>
            <td>{e.name ?? e.section ?? "—"}</td>
            <td className="mono">{formatValue(e.value)}</td>
            <td className="faint">{e.source ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

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
  return (
    <Panel
      title={
        <span className="flex">
          <span className="assist-banner">
            <Icon name="spark" /> ANALYST ASSISTANCE
          </span>
          <span>Investigation</span>
          <span className="assist-nodecide" title="Scores and decisions come only from the policy and its models">
            Does not decide
          </span>
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
        >
          <Icon name="spark" /> {run.isPending ? "Running…" : investigation ? "Run again" : "Run investigation"}
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
          <section className="assist-section" aria-labelledby="assist-observed">
            <h4 id="assist-observed" className="assist-heading">
              <span className="assist-step">1</span> Observed evidence
              <span className="faint">stored facts the draft was given; nothing else</span>
            </h4>
            <ObservedEvidence evidence={investigation.evidence} />
          </section>
          <section className="assist-section" aria-labelledby="assist-interpretation">
            <h4 id="assist-interpretation" className="assist-heading">
              <span className="assist-step">2</span> Interpretation
              <span className="faint">a draft for the analyst to check, citing the refs above</span>
            </h4>
            <div className="finding" style={{ fontSize: "var(--text-md)" }}>
              <span>{investigation.explanation.summary.statement}</span>
              <EvidenceRefs ids={investigation.explanation.summary.evidence_ids} evidence={investigation.evidence} />
            </div>
            {INTERPRETATION.map(({ key, title }) => {
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
          </section>
          <section className="assist-section" aria-labelledby="assist-limits">
            <h4 id="assist-limits" className="assist-heading">
              <span className="assist-step">3</span> Limitations
              <span className="faint">what this draft cannot tell you</span>
            </h4>
            {(investigation.explanation.uncertainties as Finding[]).length ? (
              <FindingList items={investigation.explanation.uncertainties as Finding[]} evidence={investigation.evidence} />
            ) : null}
            <ul className="assist-limits">
              {investigation.limitations.map((l) => (
                <li key={l.id}>{l.text}</li>
              ))}
              <li>
                {investigation.runtime === "reference"
                  ? "Produced by the deterministic reference template, not a language model: it restates the stored evidence and adds no independent judgement."
                  : "Drafted by a local language model, which can be wrong: check each cited ref against the case."}
              </li>
              <li>It did not score, decide or change anything; the decision above is the policy&apos;s, and yours is recorded separately.</li>
            </ul>
          </section>
        </div>
      ) : !run.isPending && !run.isError ? (
        <p className="muted" style={{ fontSize: "var(--text-sm)" }}>
          No investigation has been run for this case. Running one drafts an explanation from the evidence already stored; it does not change the decision.
        </p>
      ) : null}
    </Panel>
  );
}
