/**
 * Presentation of reason codes (Stage 14): a readable title and a category for each code the
 * service's catalogue defines. This is copy, not logic: the description still comes from the
 * service's catalogue, severity only from what the service stored (a rule's severity, or the
 * band named in a SCORE_BAND_* code), and an unknown code is shown with a title derived from
 * its own name, never an invented explanation.
 */
export type ReasonCategory = "score" | "rule" | "model" | "step_up" | "policy";

const TITLES: Record<string, string> = {
  SECONDARY_MODEL_ELEVATED: "Secondary model flagged the event",
  SEQUENCE_MODEL_ELEVATED: "Sequence model flagged the event",
  ANOMALY_SIGNAL: "Unusual behaviour (anomaly model)",
  LATE_EVENT: "Late-arriving event",
  BLOCK_NOT_CORROBORATED: "Block not corroborated",
  STEP_UP_SUCCESS: "Step-up passed",
  STEP_UP_FAILED: "Step-up failed",
  STEP_UP_EXPIRED: "Step-up expired",
  STEP_UP_CANCELLED: "Step-up cancelled",
  STEP_UP_UNAVAILABLE: "Step-up provider unavailable",
  ATTEMPTS_EXHAUSTED: "Step-up attempts exhausted",
  ATO_RESET_NEW_DEVICE_HIGH_VALUE: "Takeover pattern: reset, new device, high value",
  FAILED_LOGIN_BURST: "Burst of failed logins",
  RAPID_ACCOUNT_CHANGES: "Rapid account changes",
  MFA_REMOVED_NEW_DEVICE: "MFA removed, then a new device",
  ANONYMISED_NETWORK_NEW_DEVICE: "Anonymised network with a new device",
  NEW_PAYMENT_NEW_ADDRESS_HIGH_VALUE: "New payment method and address, high value",
};

const CATEGORY_LABEL: Record<ReasonCategory, string> = {
  score: "Model score",
  rule: "Rule",
  model: "Model signal",
  step_up: "Step-up",
  policy: "Policy",
};

/** "very_low" for SCORE_BAND_VERY_LOW; null for any other code. */
export function scoreBand(code: string): string | null {
  return code.startsWith("SCORE_BAND_") ? code.slice("SCORE_BAND_".length).toLowerCase() : null;
}

function humanise(code: string): string {
  const words = code.toLowerCase().replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function reasonTitle(code: string): string {
  const band = scoreBand(code);
  if (band) return `Score in the ${band.replace(/_/g, " ")} band`;
  return TITLES[code] ?? humanise(code);
}

export function reasonCategory(code: string, isRule: boolean): ReasonCategory {
  if (scoreBand(code)) return "score";
  if (isRule) return "rule";
  if (code.startsWith("STEP_UP_") || code === "ATTEMPTS_EXHAUSTED") return "step_up";
  if (code.endsWith("_ELEVATED") || code === "ANOMALY_SIGNAL") return "model";
  return "policy";
}

export function categoryLabel(c: ReasonCategory): string {
  return CATEGORY_LABEL[c];
}
