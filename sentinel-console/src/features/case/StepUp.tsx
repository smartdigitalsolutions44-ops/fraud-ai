import { Badge } from "@/components/Badge";
import { Panel } from "@/components/Panel";
import { StatusBadge } from "@/components/StatusBadge";
import type { CaseT } from "@/lib/api/schemas";
import { authLabel } from "@/lib/domain";
import { utcDateTime } from "@/lib/format";

/** Step-up authentication: attempts and provider-safe payment-authentication statuses only.
 * No payment credential, card data or provider token is ever part of this view. */
export function StepUp({ data }: { data: CaseT }) {
  const { attempts, payment_requests } = data.step_up;
  const auth = data.assessment.authentication;
  return (
    <Panel title="Step-up authentication" id="step-up" meta={<StatusBadge kind="auth" auth={auth} />} flush note="A passed step-up is evidence, not proof of legitimacy. Results create new follow-up assessments; the original never changes.">
      {attempts.length === 0 && payment_requests.length === 0 ? (
        <div className="empty">{data.assessment.step_up_required ? "Step-up was required; no attempt has been recorded yet." : "No step-up was requested for this assessment."}</div>
      ) : (
        <ul className="evidence-list">
          {attempts.map((a) => {
            const l = authLabel({ attempts: 1, latest_result: a.result, completed: true });
            return (
              <li key={`a-${a.attempt_number}`} className="evidence-item">
                <div className="evidence-line">
                  <span className="mono faint">#{a.attempt_number}</span>
                  <span>{a.method.toLowerCase().replace(/_/g, " ")}</span>
                  <Badge tone={l.tone} glyph={l.glyph}>
                    {l.label}
                  </Badge>
                  <span className="faint mono" style={{ marginLeft: "auto", fontSize: "var(--text-xs)" }}>
                    {utcDateTime(a.created_at)}
                  </span>
                </div>
                {a.failure_reason ? <span className="faint" style={{ fontSize: "var(--text-xs)" }}>reason: {a.failure_reason}</span> : null}
                {a.followup_assessment_id ? (
                  <a className="text-blue" style={{ fontSize: "var(--text-xs)" }} href={`/investigations/${a.followup_assessment_id}`}>
                    Follow-up assessment →
                  </a>
                ) : null}
              </li>
            );
          })}
          {payment_requests.map((p, i) => (
            <li key={`p-${i}`} className="evidence-item">
              <div className="evidence-line">
                <span className="mono faint">#{p.attempt_number}</span>
                <span>payment authentication · {p.provider}</span>
                <Badge tone={p.status === "authenticated" ? "green" : p.status === "pending" ? "orange" : "amber"}>{p.status}</Badge>
                <span className="faint mono" style={{ marginLeft: "auto", fontSize: "var(--text-xs)" }}>
                  {utcDateTime(p.created_at)}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
