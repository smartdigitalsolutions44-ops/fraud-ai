import { riskLabel } from "@/lib/domain";

import { Badge } from "./Badge";

/**
 * The policy risk band (for example "elevated"). It is a band of the calibrated model score
 * set by the active policy, not a probability of fraud.
 */
export function RiskBadge({ level }: { level: string | null | undefined }) {
  const r = riskLabel(level);
  return (
    <Badge tone={r.tone} glyph={r.glyph} title={`Risk band (policy): ${level ?? "unknown"} — not a probability`}>
      {r.label}
    </Badge>
  );
}
