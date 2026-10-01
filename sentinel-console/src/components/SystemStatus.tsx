import type { StartupCheck } from "@/features/system/checks";

import { StatusBadge } from "./StatusBadge";

/** The readiness checks as a list: name, what the service reported, and the state. */
export function SystemStatus({ checks }: { checks: StartupCheck[] }) {
  return (
    <ul className="status-list" aria-label="System checks">
      {checks.map((c) => (
        <li key={c.id} className="status-item" data-check={c.id}>
          <span className="status-name">
            {c.label}
            <span className="status-detail">{c.detail}</span>
          </span>
          <StatusBadge kind="check" state={c.state} />
        </li>
      ))}
    </ul>
  );
}
