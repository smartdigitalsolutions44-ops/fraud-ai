"use client";

import { useRef, useState } from "react";

import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Icon } from "@/components/Icon";
import { Panel } from "@/components/Panel";
import { ErrorState, Notice } from "@/components/States";
import { StatusBadge } from "@/components/StatusBadge";
import { type Resolution, useResolve, useSession } from "@/lib/api/queries";
import type { CaseT } from "@/lib/api/schemas";
import { RESOLUTIONS, priorityLabel } from "@/lib/domain";
import { shortId, utcDateTime } from "@/lib/format";

const ACTIONS: Array<{ resolution: Resolution; label: string; tone: "green" | "red" | "amber"; help: string }> = [
  { resolution: "legitimate", label: "Resolve as legitimate", tone: "green", help: "The activity is the customer's own." },
  { resolution: "fraud", label: "Resolve as fraud", tone: "red", help: "Your judgement that the activity is fraudulent." },
  { resolution: "needs_more_information", label: "Needs more information", tone: "amber", help: "Keeps the case open for follow-up." },
];

const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * The analyst's decision on a review item: only the outcomes the service supports. Every
 * outcome is recorded with the authenticated reviewer; a final outcome can never be edited.
 * The original assessment is never changed by it.
 */
export function Actions({ data }: { data: CaseT }) {
  const review = data.review;
  const session = useSession().data;
  const resolve = useResolve(review?.review_id ?? "", data.assessment.assessment_id);
  const [pending, setPending] = useState<Resolution | null>(null);
  const [note, setNote] = useState("");
  const [assertion, setAssertion] = useState("");
  const submitting = useRef(false);

  if (!review) {
    return (
      <Panel title="Analyst decision" id="actions">
        <Notice title="Not in the review queue">
          The policy did not send this assessment for manual review, so there is no analyst decision to record here.
        </Notice>
      </Panel>
    );
  }

  const final = review.status === "resolved";
  const demoKey = session?.operator.mode === "demo_key";
  const action = ACTIONS.find((a) => a.resolution === pending);
  const needsAssertion = !demoKey;
  const assertionOk = !needsAssertion || JWT.test(assertion.trim());

  const submit = () => {
    if (!pending || submitting.current || resolve.isPending) return; // no double submissions
    submitting.current = true;
    resolve.mutate(
      { resolution: pending, note: note.trim() || undefined, assertion: needsAssertion ? assertion.trim() : undefined },
      {
        onSuccess: () => {
          setPending(null);
          setNote("");
          setAssertion("");
        },
        onSettled: () => {
          submitting.current = false;
        },
      },
    );
  };

  const p = priorityLabel(review.priority);
  return (
    <Panel title="Analyst decision" id="actions" meta={<StatusBadge kind="review" status={review.status} />}>
      <div className="stack" style={{ gap: "var(--space-3)" }}>
        <dl className="kv" style={{ fontSize: "var(--text-xs)" }}>
          <dt>Case</dt>
          <dd className="mono" title={review.review_id}>
            {shortId(review.review_id, 12)}
          </dd>
          <dt>Priority</dt>
          <dd>{p.label}</dd>
          <dt>Queued</dt>
          <dd className="mono">{utcDateTime(review.created_at)}</dd>
        </dl>

        {review.outcomes.length ? (
          <div className="stack" data-testid="review-outcomes">
            {review.outcomes.map((o, i) => (
              <div key={i} className="resolution-card" data-testid={o.resolution === "needs_more_information" ? "outcome" : "resolution"}>
                <div className="spread">
                  <StatusBadge kind="resolution" resolution={o.resolution} />
                  {o.resolution !== "needs_more_information" ? (
                    <span className="flex faint" style={{ fontSize: "var(--text-xs)" }}>
                      <Icon name="lock" /> Final
                    </span>
                  ) : null}
                </div>
                <dl className="kv" style={{ fontSize: "var(--text-xs)" }}>
                  <dt>Reviewer</dt>
                  <dd className="mono" data-testid="resolution-reviewer">
                    {o.reviewer ?? "not recorded"}
                  </dd>
                  <dt>Recorded</dt>
                  <dd className="mono">{utcDateTime(o.created_at)}</dd>
                  {o.note ? (
                    <>
                      <dt>Note</dt>
                      <dd style={{ whiteSpace: "pre-wrap" }}>{o.note}</dd>
                    </>
                  ) : null}
                </dl>
              </div>
            ))}
          </div>
        ) : null}

        {final ? (
          <p className="faint" style={{ fontSize: "var(--text-xs)" }}>
            This review is resolved. Outcomes are immutable: the service refuses to rewrite them, and the original assessment is unchanged.
          </p>
        ) : (
          <>
            <div className="stack">
              {ACTIONS.map((a) => (
                <button
                  key={a.resolution}
                  type="button"
                  className={`btn btn-${a.tone}`}
                  style={{ justifyContent: "flex-start", height: "auto", padding: "8px 12px", flexDirection: "column", alignItems: "flex-start", gap: 2 }}
                  onClick={() => {
                    resolve.reset();
                    setPending(a.resolution);
                  }}
                  disabled={resolve.isPending}
                  data-testid={`resolve-${a.resolution}`}
                >
                  <span>{a.label}</span>
                  <span className="faint" style={{ fontSize: "var(--text-xs)", fontWeight: 400 }}>
                    {a.help}
                  </span>
                </button>
              ))}
            </div>
            <p className="faint" style={{ fontSize: "var(--text-xs)" }}>
              {demoKey
                ? `DEMO MODE: resolutions are signed as demo reviewer “${session?.operator.operator_id}” with the demo operator key held by the console server.`
                : "Each resolution needs your own single-use signed operator assertion; the console holds no operator key."}
            </p>
          </>
        )}
      </div>

      <ConfirmDialog
        open={pending !== null}
        title={action ? `${action.label}?` : ""}
        confirmLabel={action ? action.label : "Confirm"}
        tone={action?.tone ?? "primary"}
        busy={resolve.isPending}
        disabled={!assertionOk || note.length > 500}
        onCancel={() => {
          if (!resolve.isPending) setPending(null);
        }}
        onConfirm={submit}
      >
        <p>
          Case <span className="mono">{shortId(review.review_id, 12)}</span> will be recorded as{" "}
          <strong className={`text-${action?.tone ?? "blue"}`}>{pending ? RESOLUTIONS[pending]?.label : ""}</strong>
          {pending === "needs_more_information" ? ", and stay open." : ". This is final: resolved outcomes cannot be edited."}
        </p>
        <label className="field">
          <span className="label">Note (optional, max 500)</span>
          <textarea
            className="input"
            rows={3}
            maxLength={500}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="What you checked. No personal data, card numbers or secrets."
          />
          <span className="faint" style={{ fontSize: "var(--text-2xs)", textAlign: "right" }}>
            {note.length}/500
          </span>
        </label>
        {needsAssertion ? (
          <label className="field">
            <span className="label">Your operator assertion</span>
            <textarea className="input mono" rows={3} value={assertion} onChange={(e) => setAssertion(e.target.value)} spellCheck={false} placeholder="eyJ…" aria-invalid={assertion !== "" && !assertionOk} />
            <span className="faint mono" style={{ fontSize: "var(--text-2xs)", overflowWrap: "anywhere" }}>
              fraud-ai operators assert --key YOUR_KEY --id YOUR_ID --action review.resolve --target {review.review_id} --bind resolution={pending ?? "…"}
            </span>
          </label>
        ) : (
          <Notice tone="amber" icon="lock" title="DEMO MODE">
            Signed with the demo reviewer key (<span className="mono">{session?.operator.operator_id}</span>). Outside the demo, analysts sign their own assertions.
          </Notice>
        )}
        {resolve.isError ? <ErrorState error={resolve.error} compact /> : null}
      </ConfirmDialog>
    </Panel>
  );
}
