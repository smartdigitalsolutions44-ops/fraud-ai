import type { StartupCheck } from "@/features/system/checks";

import { StatusBadge } from "./StatusBadge";

/** One line of the start-up screen: a named check, what was found, and its state. */
export function LoadingCheck({ check, delayMs = 0 }: { check: StartupCheck; delayMs?: number }) {
  return (
    <li className="startup-check" style={{ animationDelay: `${delayMs}ms` }} data-check={check.id} data-state={check.state}>
      <span style={{ minWidth: 0 }}>
        {check.label}
        <span className="detail truncate">{check.detail}</span>
      </span>
      <StatusBadge kind="check" state={check.state} />
    </li>
  );
}
