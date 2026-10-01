/**
 * Display vocabulary for values the fraud-ai service returns. This module only *labels*
 * backend values: it never derives a decision, a risk level or a score. Unknown values are
 * shown verbatim with a neutral tone rather than guessed at.
 */
export type Tone = "green" | "amber" | "orange" | "red" | "blue" | "cyan" | "neutral";

interface Label {
  label: string;
  tone: Tone;
  glyph: string; // a shape cue so that colour is never the only signal
}

export const DECISIONS: Record<string, Label> = {
  ALLOW: { label: "Allow", tone: "green", glyph: "✓" },
  ALLOW_WITH_MONITORING: { label: "Allow · monitor", tone: "amber", glyph: "◐" },
  STEP_UP_AUTHENTICATION: { label: "Step-up", tone: "orange", glyph: "▲" },
  MANUAL_REVIEW: { label: "Manual review", tone: "orange", glyph: "◆" },
  TEMPORARY_BLOCK: { label: "Temporary block", tone: "red", glyph: "■" },
};

/** Policy decision order, least to most restrictive (fraud_ai.core.enums.Decision). */
export const DECISION_ORDER = ["ALLOW", "ALLOW_WITH_MONITORING", "STEP_UP_AUTHENTICATION", "MANUAL_REVIEW", "TEMPORARY_BLOCK"];

export function decisionLabel(value: string | null | undefined): Label {
  if (!value) return { label: "—", tone: "neutral", glyph: "·" };
  return DECISIONS[value] ?? { label: value, tone: "neutral", glyph: "·" };
}

/** Risk levels are the policy's bands, not probabilities. */
export const RISK_LEVELS: Record<string, Label> = {
  very_low: { label: "Very low", tone: "green", glyph: "▁" },
  low: { label: "Low", tone: "green", glyph: "▂" },
  moderate: { label: "Moderate", tone: "amber", glyph: "▃" },
  elevated: { label: "Elevated", tone: "orange", glyph: "▅" },
  high: { label: "High", tone: "red", glyph: "▆" },
  extreme: { label: "Extreme", tone: "red", glyph: "█" },
  very_high: { label: "Very high", tone: "red", glyph: "▇" },
  unknown: { label: "Unknown", tone: "neutral", glyph: "?" },
};

export function riskLabel(value: string | null | undefined): Label {
  if (!value) return RISK_LEVELS.unknown!;
  return RISK_LEVELS[value] ?? { label: value.replace(/_/g, " "), tone: "neutral", glyph: "·" };
}

export const REVIEW_STATUS: Record<string, Label> = {
  open: { label: "Open", tone: "blue", glyph: "○" },
  needs_more_information: { label: "Needs info", tone: "amber", glyph: "?" },
  resolved: { label: "Resolved", tone: "neutral", glyph: "●" },
};

export function reviewStatusLabel(value: string | null | undefined): Label {
  if (!value) return { label: "No review", tone: "neutral", glyph: "·" };
  return REVIEW_STATUS[value] ?? { label: value, tone: "neutral", glyph: "·" };
}

export const RESOLUTIONS: Record<string, Label> = {
  legitimate: { label: "Legitimate", tone: "green", glyph: "✓" },
  fraud: { label: "Fraud", tone: "red", glyph: "✕" },
  needs_more_information: { label: "Needs more information", tone: "amber", glyph: "?" },
};

export function resolutionLabel(value: string | null | undefined): Label {
  if (!value) return { label: "—", tone: "neutral", glyph: "·" };
  return RESOLUTIONS[value] ?? { label: value, tone: "neutral", glyph: "·" };
}

/** Step-up results (fraud_ai.stepup): shown verbatim, toned by meaning. */
export function authLabel(a: { attempts: number; latest_result: string | null; completed: boolean }): Label {
  if (a.attempts === 0 && !a.latest_result) return { label: "Not requested", tone: "neutral", glyph: "·" };
  // AuthenticationResult (SUCCESS, FAILED, …) and provider statuses (authenticated, …).
  // A passed step-up is evidence, never proof of legitimacy.
  switch (a.latest_result?.toLowerCase() ?? null) {
    case "authenticated":
    case "success":
      return { label: "Passed", tone: "green", glyph: "✓" };
    case "failed":
      return { label: "Failed", tone: "red", glyph: "✕" };
    case "expired":
    case "timeout":
      return { label: "Expired", tone: "amber", glyph: "◷" };
    case "cancelled":
      return { label: "Cancelled", tone: "amber", glyph: "–" };
    case "unavailable":
      return { label: "Unavailable", tone: "amber", glyph: "!" };
    case "pending":
    case null:
      return { label: "Pending", tone: "orange", glyph: "…" };
    default:
      return { label: a.latest_result ?? "—", tone: "neutral", glyph: "·" };
  }
}

export type CheckState = "checking" | "online" | "degraded" | "offline" | "not_used";

export const CHECK_STATES: Record<CheckState, Label> = {
  checking: { label: "Checking", tone: "blue", glyph: "…" },
  online: { label: "Online", tone: "green", glyph: "●" },
  degraded: { label: "Degraded", tone: "amber", glyph: "◐" },
  offline: { label: "Offline", tone: "red", glyph: "○" },
  not_used: { label: "Not used", tone: "neutral", glyph: "–" },
};

/** Review priority, 1 (most urgent) to 5 (fraud_ai.risk.engine.review_priority):
 * 1 temporary block; 2 manual review with high/extreme risk or a scoring fallback; 3 other. */
export function priorityLabel(p: number): { label: string; tone: Tone } {
  if (p <= 1) return { label: `P${p} · urgent`, tone: "red" };
  if (p === 2) return { label: "P2 · high", tone: "orange" };
  if (p === 3) return { label: "P3 · normal", tone: "amber" };
  return { label: `P${p}`, tone: "neutral" };
}
