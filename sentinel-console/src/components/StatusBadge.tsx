import { CHECK_STATES, authLabel, reviewStatusLabel, resolutionLabel, type CheckState } from "@/lib/domain";

import { Badge } from "./Badge";

type Props =
  | { kind: "check"; state: CheckState; label?: string }
  | { kind: "review"; status: string | null | undefined }
  | { kind: "resolution"; resolution: string | null | undefined }
  | { kind: "auth"; auth: { attempts: number; latest_result: string | null; completed: boolean } };

/** Status pills for system checks, review items, resolutions and step-up authentication. */
export function StatusBadge(props: Props) {
  let l;
  switch (props.kind) {
    case "check":
      l = CHECK_STATES[props.state];
      return (
        <Badge tone={l.tone} glyph={l.glyph}>
          {props.label ?? l.label}
        </Badge>
      );
    case "review":
      l = reviewStatusLabel(props.status);
      break;
    case "resolution":
      l = resolutionLabel(props.resolution);
      break;
    case "auth":
      l = authLabel(props.auth);
      break;
  }
  return (
    <Badge tone={l.tone} glyph={l.glyph}>
      {l.label}
    </Badge>
  );
}
