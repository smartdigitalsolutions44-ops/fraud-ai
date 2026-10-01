"use client";

import { useReady, useSession, useSystem } from "@/lib/api/queries";

import { deriveChecks, overall } from "./checks";

/** One shared view of system health for the start-up screen, top bar and status bar. */
export function useSystemStatus() {
  const session = useSession();
  const ready = useReady();
  const system = useSystem();
  const checks = deriveChecks({
    session: session.data,
    sessionError: session.error ?? undefined,
    ready: ready.data,
    readyError: ready.error ?? undefined,
    system: system.data,
    systemError: system.error ?? undefined,
  });
  return { checks, overall: overall(checks), session, ready, system };
}
