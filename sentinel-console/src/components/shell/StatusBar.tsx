"use client";

import { LiveIndicator } from "@/components/LiveIndicator";
import { POLL, useHealth } from "@/lib/api/queries";
import type { SessionT, SystemT } from "@/lib/api/schemas";
import { useLiveness } from "@/lib/hooks/useLiveness";

export function StatusBar({ session, system }: { session?: SessionT; system?: SystemT }) {
  const health = useHealth();
  const live = useLiveness(health, POLL.health);
  return (
    <footer className="statusbar" aria-label="Status">
      <LiveIndicator state={live.state} ageMs={live.ageMs} />
      <span>console {session?.console_version ?? "—"}</span>
      <span>api {health.data?.api_version ?? system?.api_version ?? "—"}</span>
      <span>policy {system?.policy?.policy_version ?? "—"}</span>
      <span>model {system?.policy?.primary_model ?? "—"}</span>
      <span style={{ marginLeft: "auto" }}>
        <kbd>J</kbd>/<kbd>K</kbd> move · <kbd>Enter</kbd> open · <kbd>Esc</kbd> close · <kbd>R</kbd> refresh / investigate · <kbd>Ctrl K</kbd> commands
      </span>
    </footer>
  );
}
