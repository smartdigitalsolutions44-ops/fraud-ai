"use client";

import dynamic from "next/dynamic";
import { useState } from "react";

import { LiveIndicator } from "@/components/LiveIndicator";
import { MetricCard } from "@/components/MetricCard";
import { Panel } from "@/components/Panel";
import { Empty, ErrorState, SkeletonRows } from "@/components/States";
import { DecisionDistribution } from "@/features/overview/DecisionDistribution";
import { POLL, useSummary } from "@/lib/api/queries";
import { reviewStatusLabel } from "@/lib/domain";
import { count, ms, pct } from "@/lib/format";
import { useLiveness } from "@/lib/hooks/useLiveness";

// the chart is the heaviest part of the page: loaded on demand, with a skeleton meanwhile
const HourlyChart = dynamic(() => import("./HourlyChart").then((m) => m.HourlyChart), {
  ssr: false,
  loading: () => <SkeletonRows rows={5} label="Loading chart" />,
});

const WINDOWS = [
  { hours: 6, label: "6h" },
  { hours: 24, label: "24h" },
  { hours: 72, label: "3d" },
  { hours: 168, label: "7d" },
];

function Counts({ data, label }: { data: Record<string, number>; label: (k: string) => string }) {
  const entries = Object.entries(data);
  if (!entries.length) return <Empty>None recorded in this window.</Empty>;
  const total = entries.reduce((a, [, v]) => a + v, 0);
  return (
    <dl className="kv">
      {entries.map(([k, v]) => (
        <Row key={k} k={label(k)} v={`${count(v)} (${pct(v, total)})`} />
      ))}
    </dl>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <>
      <dt>{k}</dt>
      <dd className="mono">{v}</dd>
    </>
  );
}

/** Operational metrics computed by the service (GET /v1/analyst/summary). No business
 * outcome (money saved, fraud prevented) is estimated: the service does not measure one. */
export function Metrics() {
  const [hours, setHours] = useState(24);
  const summary = useSummary(hours);
  const live = useLiveness(summary, POLL.summary);
  const s = summary.data;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h2>Metrics</h2>
          <p>Operational measurements reported by the fraud service. Decision counts are policy outputs, not confirmed fraud.</p>
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
      {summary.isError && !s ? <ErrorState error={summary.error} onRetry={() => void summary.refetch()} /> : null}
      <div className="grid grid-metrics">
        <MetricCard label="Assessments" value={s ? count(s.assessments.total) : null} loading={!s} tone="cyan" sub={`live, last ${hours}h`} />
        <MetricCard label="Latency p50" value={s ? ms(s.latency_ms.p50) : null} unit="ms" loading={!s} tone="blue" />
        <MetricCard label="Latency p95" value={s ? ms(s.latency_ms.p95) : null} unit="ms" loading={!s} tone="blue" />
        <MetricCard label="Latency p99" value={s ? ms(s.latency_ms.p99) : null} unit="ms" loading={!s} tone="blue" sub={s ? `${count(s.latency_ms.samples)} samples` : undefined} />
        <MetricCard label="Fallbacks" value={s ? count(s.assessments.fallbacks) : null} loading={!s} tone={s?.assessments.fallbacks ? "amber" : "neutral"} sub={s ? pct(s.assessments.fallbacks, s.assessments.total) : undefined} />
        <MetricCard label="Step-up requested" value={s ? count(s.step_up.requested) : null} loading={!s} tone="orange" />
        <MetricCard label="Shadow disagreement" value={s ? pct(s.shadow.disagree, s.shadow.agree + s.shadow.disagree) : null} loading={!s} tone="cyan" sub={s ? `${count(s.shadow.disagree)} of ${count(s.shadow.agree + s.shadow.disagree)}` : undefined} />
        <MetricCard label="Open reviews" value={s ? count((s.reviews.by_status.open ?? 0) + (s.reviews.by_status.needs_more_information ?? 0)) : null} loading={!s} tone="orange" />
      </div>
      <Panel title="Assessments per hour" meta={<span>by policy decision</span>} note={s ? `Latency scope: ${s.latency_ms.scope}.` : undefined}>
        {s ? s.series.length ? <HourlyChart series={s.series} hours={Math.min(hours, 168)} end={s.generated_at} /> : <Empty>No assessments in this window.</Empty> : <SkeletonRows rows={5} />}
      </Panel>
      <div className="grid grid-3">
        <Panel title="Decision distribution">{s ? <DecisionDistribution byDecision={s.assessments.by_decision} total={s.assessments.total} /> : <SkeletonRows rows={5} />}</Panel>
        <Panel title="Review items by status">{s ? <Counts data={s.reviews.by_status} label={(k) => reviewStatusLabel(k).label} /> : <SkeletonRows rows={3} />}</Panel>
        <Panel title="Step-up attempts by result" note="A passed step-up is evidence, not proof of legitimacy.">
          {s ? <Counts data={s.step_up.attempts_by_result} label={(k) => k.toLowerCase()} /> : <SkeletonRows rows={3} />}
        </Panel>
      </div>
    </div>
  );
}
