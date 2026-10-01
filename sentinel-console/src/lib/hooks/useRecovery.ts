"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";

import { useHealth } from "@/lib/api/queries";

/**
 * When the service comes back after failing (the health poll succeeds again), re-run the
 * views whose last poll failed, once, instead of waiting out their backoff. Views that were
 * fine are left alone, so a recovery is never a burst of every query at once.
 */
export function useRecovery(): void {
  const qc = useQueryClient();
  const health = useHealth();
  const wasDown = useRef(false);
  useEffect(() => {
    if (health.status === "error") {
      wasDown.current = true;
      return;
    }
    if (health.status === "success" && wasDown.current) {
      wasDown.current = false;
      void qc.invalidateQueries({ predicate: (q) => q.state.status === "error" });
    }
  }, [health.status, health.dataUpdatedAt, qc]);
}
