"use client";

import { DECISION_ORDER, decisionLabel } from "@/lib/domain";
import type { SummaryT } from "@/lib/api/schemas";
import { utcDate, utcTime } from "@/lib/format";

const COLOR: Record<string, string> = {
  ALLOW: "var(--green)",
  ALLOW_WITH_MONITORING: "var(--amber)",
  STEP_UP_AUTHENTICATION: "var(--orange)",
  MANUAL_REVIEW: "#c06a3c",
  TEMPORARY_BLOCK: "var(--red)",
};

/**
 * Assessments per hour, stacked by decision. An SVG with a text summary for screen readers
 * and the exact numbers in a (visually hidden) table.
 */
export function HourlyChart({ series: reported, hours, end }: { series: SummaryT["series"]; hours: number; end: string }) {
  // One slot per hour of the window. The service reports only hours that had assessments,
  // so an hour it did not report had none.
  const endHour = Math.floor(new Date(end).getTime() / 3_600_000);
  const byHour = new Map(reported.map((s) => [Math.floor(new Date(s.hour).getTime() / 3_600_000), s]));
  const series = Array.from({ length: hours }, (_, i) => {
    const h = endHour - hours + 1 + i;
    return byHour.get(h) ?? { hour: new Date(h * 3_600_000).toISOString(), by_decision: {} };
  });
  const W = 960;
  const H = 220;
  const pad = { l: 36, r: 8, t: 8, b: 24 };
  const totals = series.map((s) => Object.values(s.by_decision).reduce((a, b) => a + b, 0));
  const max = Math.max(1, ...totals);
  const n = Math.max(1, series.length);
  const bw = (W - pad.l - pad.r) / n;
  const y = (v: number) => pad.t + (H - pad.t - pad.b) * (1 - v / max);
  const ticks = [0, Math.round(max / 2), max];
  const total = totals.reduce((a, b) => a + b, 0);
  const peak = series[totals.indexOf(Math.max(...totals))];
  const label = total
    ? `Assessments per hour over ${series.length} hours: ${total} in total, peak ${Math.max(...totals)} at ${peak ? utcTime(peak.hour, false) : ""} UTC.`
    : "No assessments in this window.";
  const decisions = [...DECISION_ORDER, ...new Set(series.flatMap((s) => Object.keys(s.by_decision)).filter((k) => !DECISION_ORDER.includes(k)))];
  return (
    <figure style={{ margin: 0 }}>
      <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label}>
        {ticks.map((t) => (
          <g key={t}>
            <line className="gridline" x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} />
            <text x={pad.l - 6} y={y(t) + 3} textAnchor="end">
              {t}
            </text>
          </g>
        ))}
        {series.map((s, i) => {
          if (!totals[i]) return i % Math.ceil(n / 8) === 0 ? <text key={s.hour} x={pad.l + i * bw + bw / 2} y={H - 6} textAnchor="middle">{utcTime(s.hour, false)}</text> : null;
          let acc = 0;
          return (
            <g key={s.hour}>
              <title>{`${utcDate(s.hour)} ${utcTime(s.hour, false)} UTC: ${totals[i]} assessments`}</title>
              {decisions.map((d) => {
                const v = s.by_decision[d] ?? 0;
                if (!v) return null;
                const y0 = y(acc + v);
                const h = y(acc) - y0;
                acc += v;
                return <rect key={d} x={pad.l + i * bw + 1} y={y0} width={Math.max(1, bw - 2)} height={Math.max(0.5, h)} fill={COLOR[d] ?? "var(--neutral)"} rx={1} />;
              })}
              {i % Math.ceil(n / 8) === 0 ? (
                <text x={pad.l + i * bw + bw / 2} y={H - 6} textAnchor="middle">
                  {utcTime(s.hour, false)}
                </text>
              ) : null}
            </g>
          );
        })}
      </svg>
      <figcaption className="legend" style={{ marginTop: 8 }}>
        {decisions.map((d) => (
          <span key={d}>
            <span className="legend-swatch" style={{ background: COLOR[d] ?? "var(--neutral)" }} aria-hidden="true" />
            {decisionLabel(d).label}
          </span>
        ))}
        <span className="faint">Hours in UTC</span>
      </figcaption>
      <table className="sr-only">
        <caption>Assessments per hour by decision</caption>
        <thead>
          <tr>
            <th scope="col">Hour (UTC)</th>
            {decisions.map((d) => (
              <th key={d} scope="col">
                {decisionLabel(d).label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {reported.map((s) => (
            <tr key={s.hour}>
              <th scope="row">{`${utcDate(s.hour)} ${utcTime(s.hour, false)}`}</th>
              {decisions.map((d) => (
                <td key={d}>{s.by_decision[d] ?? 0}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}
