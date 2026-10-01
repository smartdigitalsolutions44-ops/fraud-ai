import { decisionLabel } from "@/lib/domain";

import { Badge } from "./Badge";

/** The risk policy's decision, exactly as the service returned it. */
export function DecisionBadge({ decision }: { decision: string | null | undefined }) {
  const d = decisionLabel(decision);
  return (
    <Badge tone={d.tone} glyph={d.glyph} title={decision ? `Policy decision: ${decision}` : undefined}>
      {d.label}
    </Badge>
  );
}
