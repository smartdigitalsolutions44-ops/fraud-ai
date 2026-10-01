"use client";

import { useReady, useSession, useSystem } from "@/lib/api/queries";

import { deriveChecks } from "./checks";
import { deriveGroups, overallOf } from "./groups";

/** One shared view of system health for the start-up screen, top bar, status bar and System
 * page: the detailed checks, and the same facts as seven operational groups. */
export function useSystemStatus() {
  const session = useSession();
  const ready = useReady();
  const system = useSystem();
  // Stage 14: a query whose latest poll failed keeps its previous data in React Query; for
  // system state that would show an unreachable service as healthy. Health is derived only
  // from the latest successful answer: a failed poll counts as no answer.
  const latest = <T,>(q: { status: string; data: T | undefined }) => (q.status === "error" ? undefined : q.data);
  const inputs = {
    session: latest(session),
    sessionError: session.status === "error" ? (session.error ?? undefined) : undefined,
    ready: latest(ready),
    readyError: ready.status === "error" ? (ready.error ?? undefined) : undefined,
    system: latest(system),
    systemError: system.status === "error" ? (system.error ?? undefined) : undefined,
  };
  const checks = deriveChecks(inputs);
  const groups = deriveGroups(inputs);
  return { checks, groups, overall: overallOf(groups), session, ready, system };
}
