"use client";

import { Badge } from "@/components/Badge";
import { DecisionBadge } from "@/components/DecisionBadge";
import { LiveIndicator } from "@/components/LiveIndicator";
import { Panel } from "@/components/Panel";
import { RiskBadge } from "@/components/RiskBadge";
import { ErrorState, Notice, SkeletonRows } from "@/components/States";
import { StatusBadge } from "@/components/StatusBadge";
import { SystemStatus } from "@/components/SystemStatus";
import { POLL } from "@/lib/api/queries";
import type { SystemT } from "@/lib/api/schemas";
import { shortId, utcDateTime } from "@/lib/format";
import { useLiveness } from "@/lib/hooks/useLiveness";

import type { HealthGroup } from "./groups";
import { useSystemStatus } from "./useSystemStatus";

/** The seven operational groups, each with its state and the reason for it. */
function GroupRail({ groups }: { groups: HealthGroup[] }) {
  return (
    <ul className="ops-rail" aria-label="System groups" data-testid="ops-rail">
      {groups.map((g) => (
        <li key={g.id} className="ops-tile" data-group={g.id} data-state={g.state}>
          <div className="ops-tile-head">
            <span className="ops-title">{g.title}</span>
            <StatusBadge kind="check" state={g.state} />
          </div>
          <p className="ops-cause">{g.cause}</p>
        </li>
      ))}
    </ul>
  );
}

function YesNo({ value, good = true }: { value: boolean | null | undefined; good?: boolean }) {
  if (value === null || value === undefined) return <Badge tone="neutral">Unknown</Badge>;
  const ok = value === good;
  return (
    <Badge tone={ok ? "green" : "amber"} glyph={value ? "✓" : "✕"}>
      {value ? "Yes" : "No"}
    </Badge>
  );
}

function Pair({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <>
      <dt>{k}</dt>
      <dd>{children}</dd>
    </>
  );
}

function Models({ models }: { models: SystemT["models"] }) {
  return (
    <div className="table-wrap">
      <table className="table" data-testid="models-table">
        <caption className="sr-only">Registered models</caption>
        <thead>
          <tr>
            <th scope="col">Model</th>
            <th scope="col">Role</th>
            <th scope="col">Algorithm</th>
            <th scope="col">Features</th>
            <th scope="col">Trained</th>
            <th scope="col">Artefact</th>
            <th scope="col">Signature</th>
            <th scope="col">Loaded</th>
          </tr>
        </thead>
        <tbody>
          {models.map((m) => (
            <tr key={`${m.role}-${m.ref}`}>
              <td className="mono">{m.ref}</td>
              <td>
                <Badge tone={m.role === "primary" ? "cyan" : "neutral"}>{m.role === "shadow" ? "Shadow" : m.role}</Badge>
              </td>
              <td className="mono faint">{m.algorithm ?? "—"}</td>
              <td className="mono faint">{m.feature_version ?? "—"}</td>
              <td className="mono faint">{m.trained_at ? utcDateTime(m.trained_at) : "—"}</td>
              <td className="mono faint" title={m.artifact_sha256 ?? ""}>
                {m.artifact_sha256 ? `sha256:${shortId(m.artifact_sha256, 12)}` : "—"}
              </td>
              <td>
                {!m.registered ? (
                  <Badge tone="red">Not registered</Badge>
                ) : m.signature?.present ? (
                  m.signature.matches_artifact ? (
                    <Badge tone="green" glyph="✓" title={`key ${m.signature.key_id ?? "?"}, signed ${m.signature.signed_at ?? "?"}`}>
                      Verified
                    </Badge>
                  ) : (
                    <Badge tone="red" glyph="✕">
                      Mismatch
                    </Badge>
                  )
                ) : (
                  <Badge tone="amber">Unsigned</Badge>
                )}
              </td>
              <td>
                {m.loaded ? (
                  <Badge tone="green" glyph="●">
                    Loaded{m.verified_at_readiness ? " · verified" : ""}
                  </Badge>
                ) : (
                  <Badge tone="neutral">Not loaded</Badge>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Read-only system view. The console cannot change policy, models or keys. */
export function SystemPage() {
  const status = useSystemStatus();
  const sys = status.system.data;
  const ready = status.ready.data;
  const session = status.session.data;
  const live = useLiveness(status.system, POLL.system);
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h2>System</h2>
          <p>Security operations view: every state below is what the fraud service reported. The console cannot change policy, models or keys.</p>
        </div>
        <LiveIndicator state={live.state} ageMs={live.ageMs} />
      </div>
      {status.system.isError && !sys ? <ErrorState error={status.system.error} onRetry={() => void status.system.refetch()} /> : null}
      {session?.problems.length ? (
        <Notice tone="amber" icon="alert" title="Console configuration">
          {session.problems.join("; ")}
        </Notice>
      ) : null}
      <GroupRail groups={status.groups} />
      <div className="grid grid-3">
        <Panel title="Readiness checks" flush meta={ready ? <Badge tone={ready.status === "ready" ? "green" : "red"}>{ready.status}</Badge> : null}>
          <SystemStatus checks={status.checks} />
        </Panel>
        <Panel title="Service and data">
          {sys && ready ? (
            <dl className="kv">
              <Pair k="API">
                <span className="mono">{sys.api_version}</span>
              </Pair>
              <Pair k="Environment">
                <span className="mono">{sys.environment}</span>
              </Pair>
              <Pair k="Console">
                <span className="mono">{session?.console_version ?? "—"}</span>
              </Pair>
              <Pair k="Readiness">
                <span className="chips">
                  {Object.entries(ready.checks).map(([k, v]) => (
                    <span key={k} className="chip" title={`${k}: ${v}`}>
                      {k}={v}
                    </span>
                  ))}
                </span>
              </Pair>
              <Pair k="Migrations">
                <span className="mono">
                  {sys.migrations.current ?? "—"} / head {sys.migrations.head ?? "—"}
                </span>{" "}
                <YesNo value={sys.migrations.up_to_date} />
              </Pair>
              <Pair k="Shared state">
                <span className="mono">{sys.security.state_backend}</span>
                {sys.security.state_backend === "memory" ? <span className="faint"> (single process; Redis not configured)</span> : null}
              </Pair>
              <Pair k="View computed in">
                <span className="mono">{Math.round(sys.checks_ms)} ms</span>
              </Pair>
            </dl>
          ) : (
            <SkeletonRows rows={6} />
          )}
        </Panel>
        <Panel title="Trust controls">
          {sys ? (
            <dl className="kv">
              <Pair k="Signed requests">
                <YesNo value={sys.security.request_signatures_required} /> <span className="mono faint">min {sys.security.signature_min_version}</span>
              </Pair>
              <Pair k="Signed models">
                <YesNo value={sys.security.model_signatures_required} />
              </Pair>
              <Pair k="Operator auth">
                <YesNo value={sys.security.operator_auth_required} />
              </Pair>
              <Pair k="Key provider">
                <span className="mono">{sys.security.key_provider}</span>
              </Pair>
              <Pair k="Console operator">
                {session?.operator.mode === "demo_key" ? (
                  <span className="text-amber">DEMO MODE · demo reviewer key on the console server</span>
                ) : (
                  <span>per-analyst signed assertions</span>
                )}
              </Pair>
            </dl>
          ) : (
            <SkeletonRows rows={5} />
          )}
        </Panel>
      </div>

      <Panel title="Models" flush note="Shadow models are scored and recorded for comparison; they never decide.">
        {sys ? <Models models={sys.models} /> : <SkeletonRows rows={3} />}
      </Panel>

      <div className="grid grid-2">
        <Panel title="Active risk policy" note="Policy changes need two-person approval through the service's own tooling. They cannot be made from this console.">
          {sys?.policy ? (
            <div className="stack" style={{ gap: 16 }}>
              <dl className="kv">
                <Pair k="Policy">
                  <span className="mono">{sys.policy.policy_version}</span>
                </Pair>
                <Pair k="Rules">
                  <span className="mono">{sys.policy.rules_version}</span>
                </Pair>
                <Pair k="Primary model">
                  <span className="mono">{sys.policy.primary_model}</span>
                </Pair>
                <Pair k="Deployment">
                  <span className="mono">#{sys.policy.deployment_sequence ?? "—"}</span>
                </Pair>
                <Pair k="Activated">
                  <span className="mono">
                    {utcDateTime(sys.policy.activated_at)} by {sys.policy.activated_by ?? "—"}
                  </span>
                </Pair>
                <Pair k="Approvals required">
                  <span className="mono">{sys.policy.approvals_required}</span>
                </Pair>
                <Pair k="Promotion required">
                  <YesNo value={sys.policy.promotion_required} good={sys.policy.promotion_required} />
                </Pair>
                <Pair k="Shadow models">
                  <span className="mono">{sys.policy.shadow_models.join(", ") || "—"}</span>
                </Pair>
                <Pair k="Shadow policies">
                  <span className="mono">{sys.policy.shadow_policies.join(", ") || "—"}</span>
                </Pair>
              </dl>
              <div>
                <div className="label" style={{ marginBottom: 8 }}>
                  Risk bands (calibrated primary score ≥ lower bound)
                </div>
                <table className="table">
                  <caption className="sr-only">Risk bands</caption>
                  <thead>
                    <tr>
                      <th scope="col">From</th>
                      <th scope="col">Risk band</th>
                      <th scope="col">Decision</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sys.policy.bands.map((b) => (
                      <tr key={b.lower}>
                        <td className="mono">{b.lower.toFixed(3)}</td>
                        <td>
                          <RiskBadge level={b.risk_level} />
                        </td>
                        <td>
                          <DecisionBadge decision={b.decision} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : sys ? (
            <Notice tone="red" icon="alert" title="No active policy">
              The service has no active risk policy deployment.
            </Notice>
          ) : (
            <SkeletonRows rows={8} />
          )}
        </Panel>
        <div className="grid" style={{ alignContent: "start" }}>
          <Panel title="Audit">
            {sys ? (
              <dl className="kv">
                <Pair k="Hash chain">
                  {sys.audit.chain.verified === true ? (
                    <Badge tone="green" glyph="✓">
                      Verified
                    </Badge>
                  ) : sys.audit.chain.verified === false ? (
                    <Badge tone="red" glyph="✕">
                      Broken
                    </Badge>
                  ) : (
                    <Badge tone="amber">Not verified here</Badge>
                  )}{" "}
                  <span className="mono faint">{sys.audit.chain.events} events</span>
                </Pair>
                {sys.audit.chain.reason ? <Pair k="Detail">{sys.audit.chain.reason}</Pair> : null}
                <Pair k="External anchor">
                  {sys.audit.anchor ? (
                    <span className="mono">
                      #{sys.audit.anchor.anchor_number} at seq {sys.audit.anchor.sequence} · {Math.round(sys.audit.anchor.age_minutes)} min ago · {sys.audit.anchor.events_since} events since
                    </span>
                  ) : (
                    <span className="text-amber">none yet</span>
                  )}
                </Pair>
                {sys.audit.anchor ? (
                  <Pair k="Anchor key">
                    <span className="mono">{sys.audit.anchor.key_id}</span>
                  </Pair>
                ) : null}
                <Pair k="Max anchor age">
                  <span className="mono">{sys.audit.anchor_max_age_minutes} min</span>
                </Pair>
              </dl>
            ) : (
              <SkeletonRows rows={4} />
            )}
          </Panel>
          <Panel title="Analyst layer: assistance" note={sys?.llm.note}>
            {sys ? (
              <dl className="kv">
                <Pair k="Runtime">
                  <span className="mono">{sys.llm.runtime ?? "none"}</span>
                </Pair>
                <Pair k="Model">
                  <span className="mono">{sys.llm.model ?? "—"}</span>
                </Pair>
                <Pair k="Available">
                  <YesNo value={sys.llm.available} />
                </Pair>
                <Pair k="Reference template">
                  {sys.llm.reference_template ? <span>yes — deterministic template, not a language model</span> : <span>no</span>}
                </Pair>
              </dl>
            ) : (
              <SkeletonRows rows={4} />
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
