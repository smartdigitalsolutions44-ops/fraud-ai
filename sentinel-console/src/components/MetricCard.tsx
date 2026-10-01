import type { ReactNode } from "react";

import type { Tone } from "@/lib/domain";

import { Skeleton } from "./States";

/** One headline number from the API. `value` null means "not reported", shown as a dash. */
export function MetricCard({
  label,
  value,
  unit,
  sub,
  tone,
  loading,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  sub?: ReactNode;
  tone?: Tone;
  loading?: boolean;
}) {
  return (
    <div className="metric" data-tone={tone && tone !== "neutral" ? tone : undefined} role="group" aria-label={label}>
      <span className="label">{label}</span>
      {loading ? (
        <Skeleton width="60%" height={26} />
      ) : (
        <span className="metric-value">
          {value ?? "—"}
          {unit && value !== null && value !== "—" ? <span className="unit">{unit}</span> : null}
        </span>
      )}
      {sub ? <span className="metric-sub">{sub}</span> : null}
    </div>
  );
}
