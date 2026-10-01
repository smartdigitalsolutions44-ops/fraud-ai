"use client";

import Link from "next/link";
import { useState } from "react";

import { Icon } from "@/components/Icon";
import { LiveIndicator } from "@/components/LiveIndicator";
import { MetricCard } from "@/components/MetricCard";
import { splitModel } from "@/components/ModelComparison";
import { Panel } from "@/components/Panel";
import { Empty, ErrorState, SkeletonRows } from "@/components/States";
import { SystemStatus } from "@/components/SystemStatus";
import { FeedTable } from "@/features/feed/FeedTable";
import { useSystemStatus } from "@/features/system/useSystemStatus";
import { POLL, useFeed, useSummary } from "@/lib/api/queries";
import { DECISION_ORDER, priorityLabel } from "@/lib/domain";
import { age, count, ms, pct } from "@/lib/format";
import { useLiveness } from "@/lib/hooks/useLiveness";
import { useNow } from "@/lib/hooks/useNow";

import { DecisionDistribution } from "./DecisionDistribution";

const WINDOWS = [
  { hours: 1, label: "1h" },
  { hours: 24, label: "24h" },
  { hours: 168, label: "7d" },
];

const FLAGGED = new Set(DECISION_ORDER.slice(2)); // step-up and stronger

export function Overview() {
  const [hours, setHours] = useState(24);
  const summary = useSummary(hours);
  const feed = useFeed(100);
  const status = useSystemStatus();
  const live = useLiveness(summary, POLL.summary);
  const now = useNow(5000);
  const s = summary.data;
  const system = status.system.data;
  const primary = system?.models.find((m) => m.role === "primary");
  const openReviews = s ? (s.reviews.by_status.open ?? 0) + (s.reviews.by_status.needs_more_information ?? 0) : null;
  const alerts = (feed.data?.items ?? []).filter((i) => FLAGGED.has(i.decision)).slice(0, 8);
  const loading = summary.isPending;
  const overallTone = { operational: "green", degraded: "amber", offline: "red", checking: "blue" } as const;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h2>Overview</h2>
          <p>Live assessments, the review backlog and system health, as reported by the fraud service.</p>
        </div>
        <div className="toolbar">
          <LiveIndicator state={live.state} ageMs={live.ageMs} />
          <div className="segmented" role="group" aria-label="Time window">
            {WINDOWS.map((w) => (
              <button key={w.hours} type="button" aria-pressed={hours === w.hours} onClick={() => setHours(w.hours)}>
                {w.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {live.state === "stale" ? (
        <div className="stale-banner" role="status">
          <Icon name="alert" /> Figures below are from the last successful update and may be out of date.
        </div>
      ) : null}
      {summary.isError && !s ? <ErrorState error={summary.error} onRetry={() => void summary.refetch()} /> : null}

      <div className="grid grid-metrics" data-testid="overview-metrics">
        <MetricCard
          label="System status"
          value={<span style={{ textTransform: "capitalize", fontSize: "var(--text-xl)" }}>{status.overall}</span>}
          tone={overallTone[status.overall]}
          sub={checkSummary(status.groups)}
        />
        <MetricCard label={`Assessments · ${hours}h`} value={s ? count(s.assessments.total) : null} loading={loading} tone="cyan" sub="live decisions (follow-ups excluded)" />
        <MetricCard
          label="Review queue"
          value={openReviews === null ? null : count(openReviews)}
          loading={loading}
          tone={openReviews ? "orange" : "neutral"}
          sub={s?.reviews.oldest_open_at ? `oldest open ${age(s.reviews.oldest_open_at, now)}` : "nothing waiting"}
        />
        <MetricCard label="Step-up requests" value={s ? count(s.step_up.requested) : null} loading={loading} tone="orange" sub={s ? `${count(s.assessments.step_up_followups)} follow-up assessments` : undefined} />
        <MetricCard label="Temporary blocks" value={s ? count(s.assessments.by_decision.TEMPORARY_BLOCK ?? 0) : null} loading={loading} tone="red" sub="policy decision; always reviewed" />
        <MetricCard label="Scoring fallbacks" value={s ? count(s.assessments.fallbacks) : null} loading={loading} tone={s?.assessments.fallbacks ? "amber" : "neutral"} sub={s ? `${pct(s.assessments.fallbacks, s.assessments.total)} of assessments` : undefined} />
        <MetricCard label="Scoring latency p95" value={s ? ms(s.latency_ms.p95) : null} unit="ms" loading={loading} tone="blue" sub={s ? `p50 ${ms(s.latency_ms.p50)} ms · ${count(s.latency_ms.samples)} samples` : undefined} />
        <MetricCard
          label="Primary model"
          value={
            primary ? (
              <span className="metric-model">
                <span className="mono">{splitModel(primary.ref)[0]}</span>
                {splitModel(primary.ref)[1] ? <span className="model-version mono">v{splitModel(primary.ref)[1]}</span> : null}
              </span>
            ) : (
              "—"
            )
          }
          loading={status.system.isPending}
          tone={primary?.loaded && primary.signature?.matches_artifact ? "green" : "amber"}
          sub={primary ? `${primary.loaded ? "loaded" : "not loaded"} · signature ${primary.signature?.matches_artifact ? "verified" : "not verified"}` : undefined}
        />
      </div>

      <div className="grid grid-overview">
        <div className="grid" style={{ alignContent: "start" }}>
          <Panel
            title="Recent flagged assessments"
            meta={
              <Link href="/feed" className="btn btn-sm btn-ghost">
                Live feed <Icon name="chevronRight" />
              </Link>
            }
            flush
            note="Step-up, manual review and temporary block decisions from the latest 100 assessments. A flag is a risk signal for review, not a finding of fraud."
          >
            {feed.isPending ? <SkeletonRows rows={5} /> : feed.isError && !feed.data ? <div className="panel-body"><ErrorState error={feed.error} compact /></div> : alerts.length ? <FeedTable items={alerts} keyboard={false} caption="Recent flagged assessments" compact /> : <Empty title="No flagged assessments">None of the latest 100 assessments was stepped up, reviewed or blocked. Monitoring remains active.</Empty>}
          </Panel>
          <Panel title="Decision distribution" meta={<span>{hours}h window</span>} note="Counts of the risk policy's decisions on live assessments.">
            {s ? <DecisionDistribution byDecision={s.assessments.by_decision} total={s.assessments.total} /> : <SkeletonRows rows={5} />}
          </Panel>
        </div>
        <div className="grid" style={{ alignContent: "start" }}>
          <Panel title="System health" flush meta={<Link href="/system" className="btn btn-sm btn-ghost">Details <Icon name="chevronRight" /></Link>}>
            <SystemStatus checks={status.groups.map((g) => ({ id: g.id, label: g.title, state: g.state, detail: g.cause }))} />
          </Panel>
          <Panel title="Review backlog" meta={<Link href="/queue" className="btn btn-sm btn-ghost">Queue <Icon name="chevronRight" /></Link>}>
            {s ? (
              <dl className="kv">
                <dt>Open</dt>
                <dd className="mono">{count(s.reviews.by_status.open ?? 0)}</dd>
                <dt>Needs information</dt>
                <dd className="mono">{count(s.reviews.by_status.needs_more_information ?? 0)}</dd>
                <dt>Resolved</dt>
                <dd className="mono">{count(s.reviews.by_status.resolved ?? 0)}</dd>
                {Object.entries(s.reviews.open_by_priority)
                  .sort(([a], [b]) => Number(a) - Number(b))
                  .map(([p, n]) => (
                    <FragmentRow key={p} term={`Open · ${priorityLabel(Number(p)).label}`} value={count(n)} />
                  ))}
                <dt>Oldest open</dt>
                <dd className="mono">{s.reviews.oldest_open_at ? `${age(s.reviews.oldest_open_at, now)} ago` : "—"}</dd>
              </dl>
            ) : (
              <SkeletonRows rows={4} />
            )}
          </Panel>
          <Panel title="Model disagreement" note="Shadow models are scored and recorded but never decide. Agreement is the shadow flag against the active decision (step-up or stronger).">
            {s ? (
              <dl className="kv">
                <dt>Shadow agrees</dt>
                <dd className="mono">{count(s.shadow.agree)}</dd>
                <dt>Shadow disagrees</dt>
                <dd className="mono">
                  {count(s.shadow.disagree)} <span className="faint">({pct(s.shadow.disagree, s.shadow.agree + s.shadow.disagree)})</span>
                </dd>
              </dl>
            ) : (
              <SkeletonRows rows={2} />
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function checkSummary(checks: { state: string }[]): string {
  const n = (s: string) => checks.filter((c) => c.state === s).length;
  const parts = [`${n("online")} online`];
  if (n("degraded")) parts.push(`${n("degraded")} degraded`);
  if (n("offline")) parts.push(`${n("offline")} offline`);
  if (n("not_used")) parts.push(`${n("not_used")} not used`);
  return parts.join(" · ");
}

function FragmentRow({ term, value }: { term: string; value: string }) {
  return (
    <>
      <dt>{term}</dt>
      <dd className="mono">{value}</dd>
    </>
  );
}
