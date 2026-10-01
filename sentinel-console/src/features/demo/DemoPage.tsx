"use client";

import Link from "next/link";
import { useState } from "react";

import { Badge } from "@/components/Badge";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DecisionBadge } from "@/components/DecisionBadge";
import { Icon } from "@/components/Icon";
import { Panel } from "@/components/Panel";
import { ErrorState, Notice, SkeletonRows } from "@/components/States";
import { useDemoReset, useDemoScenarios, useDemoStatus, usePlayScenario, useSession } from "@/lib/api/queries";
import type { DemoScenariosT } from "@/lib/api/schemas";

const PHRASE = "RESET DEMO";
type Scenario = DemoScenariosT["scenarios"][number];

function ScenarioCard({ s, index }: { s: Scenario; index: number }) {
  const play = usePlayScenario();
  const result = play.data?.label === s.label ? play.data : null;
  const assessmentId = result?.assessment_id ?? s.assessment_id;
  return (
    <section className="panel scenario" aria-labelledby={`sc-${s.label}`} data-testid={`scenario-${s.label}`}>
      <div className="panel-head">
        <span className="mono faint">{String(index + 1).padStart(2, "0")}</span>
        <h3 id={`sc-${s.label}`}>{s.title}</h3>
        <div className="panel-meta">{assessmentId ? <Badge tone="blue" glyph="●">Scored</Badge> : <Badge tone="neutral">Not scored yet</Badge>}</div>
      </div>
      <div className="panel-body stack" style={{ gap: 12 }}>
        <div className="flex flex-wrap" style={{ fontSize: "var(--text-sm)" }}>
          <span className="faint">Measured decision</span>
          <DecisionBadge decision={s.expected_decision} />
          {s.relaxed_match ? (
            <Badge tone="amber" title="No strict example existed in this seed; the nearest case was used">
              relaxed match
            </Badge>
          ) : null}
        </div>
        <div className="dev-note">
          <div className="label" style={{ color: "var(--amber)", marginBottom: 2 }}>
            Developer note · not model output
          </div>
          {s.purpose ? <p>{s.purpose}</p> : null}
          <p className="faint" style={{ marginTop: 4 }}>
            {s.story}
          </p>
          <p className="faint mono" style={{ marginTop: 4, fontSize: "var(--text-2xs)" }}>
            synthetic scenario: {s.scenario} · {s.prelude_events} prior events · {s.event_type?.toLowerCase() ?? "event"}
          </p>
        </div>
        {result ? (
          <div className="flex flex-wrap" style={{ fontSize: "var(--text-sm)" }} role="status">
            <span className="faint">Service decided</span>
            <DecisionBadge decision={result.decision} />
            {result.decision === s.expected_decision ? <span className="text-green">= measured</span> : <span className="text-amber">≠ measured ({s.expected_decision})</span>}
          </div>
        ) : null}
        {play.isError ? <ErrorState error={play.error} compact /> : null}
        <div className="flex">
          {assessmentId ? (
            <Link className="btn btn-sm btn-primary" href={`/investigations/${assessmentId}`} data-testid={`open-${s.label}`}>
              Open case <Icon name="chevronRight" />
            </Link>
          ) : (
            <button type="button" className="btn btn-sm btn-primary" onClick={() => play.mutate(s.label)} disabled={play.isPending} data-testid={`play-${s.label}`}>
              <Icon name="demo" /> {play.isPending ? "Scoring…" : "Score this scenario"}
            </button>
          )}
        </div>
      </div>
    </section>
  );
}

function ResetPanel({ available }: { available: boolean }) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const reset = useDemoReset();
  const running = (s?: string) => s === "stopping" || s === "resetting" || s === "starting";
  const status = useDemoStatus(available, running(reset.data?.state));
  const state = status.data?.state;
  const busy = running(state) || reset.isPending;
  return (
    <Panel
      title="Reset the demo world"
      meta={state ? <Badge tone={state === "failed" ? "red" : busy ? "orange" : "green"}>{state}</Badge> : null}
      note="Runs the existing guarded `fraud-ai demo reset`: it refuses anything but a marked *_demo.db database in the development profile with DEMO_MODE=true. All demo decisions, reviews and investigations are discarded."
    >
      {!available ? (
        <Notice tone="amber" icon="lock" title="Reset unavailable">
          Start the console with <span className="mono">npm run demo</span> to enable the demo supervisor. The console itself never touches a database.
        </Notice>
      ) : (
        <div className="stack" style={{ gap: 12 }}>
          <div className="flex">
            <button type="button" className="btn btn-red" disabled={busy} onClick={() => (setTyped(""), reset.reset(), setOpen(true))} data-testid="reset-demo">
              <Icon name="reset" /> RESET DEMO
            </button>
            {busy ? <span className="muted">Rebuilding the synthetic world; this takes a few minutes…</span> : null}
            {state === "ready" && status.data?.finished_at ? <span className="text-green">Demo world ready.</span> : null}
          </div>
          {status.data?.log.length ? (
            <pre className="progress-log" aria-live="polite" aria-label="Reset progress">
              {status.data.log.slice(-40).join("\n")}
            </pre>
          ) : null}
          {status.isError ? <ErrorState error={status.error} compact /> : null}
        </div>
      )}
      <ConfirmDialog
        open={open}
        title="Reset the demo world?"
        confirmLabel="Reset demo"
        tone="red"
        busy={reset.isPending}
        disabled={typed !== PHRASE}
        onCancel={() => setOpen(false)}
        onConfirm={() => reset.mutate(undefined, { onSuccess: () => setOpen(false) })}
      >
        <p>Every assessment, review outcome and investigation in the synthetic demo world will be discarded and the world rebuilt from its fixed seed.</p>
        <label className="field">
          <span className="label">Type {PHRASE} to confirm</span>
          <input className="input mono" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
        </label>
        {reset.isError ? <ErrorState error={reset.error} compact /> : null}
      </ConfirmDialog>
    </Panel>
  );
}

/** DEMO MODE only: the deterministic synthetic scenarios and the guarded reset. */
export function DemoPage() {
  const session = useSession();
  const demo = Boolean(session.data?.demo_mode);
  const scenarios = useDemoScenarios(demo);
  if (session.isPending) return <div className="page"><SkeletonRows rows={6} /></div>;
  if (!demo) {
    return (
      <div className="page">
        <Notice tone="amber" icon="lock" title="DEMO MODE only">
          Demo scenarios and the demo reset exist only when the console runs against the synthetic demo world (SENTINEL_DEMO_MODE=true). They are refused by the server otherwise.
        </Notice>
      </div>
    );
  }
  const d = scenarios.data;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h2 className="flex">
            Demo <span className="demo-ribbon">DEMO MODE · SYNTHETIC DATA</span>
          </h2>
          <p>Ten deterministic cases on the synthetic demo world. Every decision shown elsewhere is the live service&apos;s answer; the measured decision is what the same event produced when the world was built.</p>
        </div>
        {d ? (
          <span className="faint mono" style={{ fontSize: "var(--text-xs)" }}>
            seed {d.seed} · {d.users} synthetic users
          </span>
        ) : null}
      </div>
      {scenarios.isError ? <ErrorState error={scenarios.error} onRetry={() => void scenarios.refetch()} /> : null}
      {d?.missing.length ? (
        <Notice tone="amber" title="Not produced by this seed">
          {d.missing.join(", ")} — listed as missing, not faked.
        </Notice>
      ) : null}
      {d ? (
        <div className="scenario-grid">
          {d.scenarios.map((s, i) => (
            <ScenarioCard key={s.label} s={s} index={i} />
          ))}
        </div>
      ) : (
        <SkeletonRows rows={8} />
      )}
      <ResetPanel available={Boolean(session.data?.demo_reset_available)} />
    </div>
  );
}
