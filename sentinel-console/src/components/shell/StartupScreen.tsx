"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";

import { useStored } from "@/lib/hooks/useStored";

import { BrandMark } from "@/components/Icon";
import { LoadingCheck } from "@/components/LoadingCheck";
import type { Overall, StartupCheck } from "@/features/system/checks";

const KEY = "sentinel.startup.done";
const MIN_VISIBLE_MS = 650; // long enough to read, short when everything is already up

/**
 * SENTINEL start-up: the real readiness checks, shown once per browser session. It leaves by
 * itself only when every check is ONLINE (or not used); otherwise it stays and says what is
 * wrong, and the analyst chooses to enter a degraded console.
 */
export function StartupScreen({ checks, overall, versions }: { checks: StartupCheck[]; overall: Overall; versions: string }) {
  const qc = useQueryClient();
  // undefined until hydrated: the server cannot know whether this session already saw it
  const [seen, markSeen] = useStored("session", KEY);
  const [leaving, setLeaving] = useState(false);
  const [gone, setGone] = useState(false);
  const phase = seen === undefined ? "pending" : gone || (seen && !leaving) ? "hidden" : leaving ? "leaving" : "visible";
  const shownAt = useRef(0);
  const [slow, setSlow] = useState(false);
  const enterButton = useRef<HTMLButtonElement>(null);

  const leave = useCallback(() => {
    setLeaving(true);
    markSeen("1"); // not persisted in private mode: the checks simply show again next time
    setTimeout(() => setGone(true), 320);
  }, [markSeen]);

  useEffect(() => {
    if (phase === "visible" && !shownAt.current) shownAt.current = Date.now();
  }, [phase]);

  useEffect(() => {
    if (phase !== "visible") return;
    const t = setTimeout(() => setSlow(true), 10_000);
    return () => clearTimeout(t);
  }, [phase]);

  useEffect(() => {
    if (phase !== "visible" || overall !== "operational") return;
    const wait = Math.max(0, MIN_VISIBLE_MS - (Date.now() - shownAt.current));
    const t = setTimeout(leave, wait);
    return () => clearTimeout(t);
  }, [phase, overall, leave]);

  useEffect(() => {
    if (phase === "visible" && (overall === "degraded" || overall === "offline")) enterButton.current?.focus();
  }, [phase, overall]);

  if (phase === "hidden") return null;
  if (phase === "pending") return <div className="startup" aria-hidden="true" />;
  const attention = checks.filter((c) => c.state === "offline" || c.state === "degraded").length;
  const status =
    overall === "checking"
      ? "Running readiness checks"
      : overall === "operational"
        ? "All systems online"
        : overall === "degraded"
          ? `${attention} check${attention === 1 ? "" : "s"} degraded — console will run with reduced assurance`
          : "Core services offline — live data unavailable";

  return (
    <div className="startup" data-leaving={phase === "leaving" ? "" : undefined} role="dialog" aria-modal="true" aria-labelledby="startup-title" data-testid="startup">
      <div className="startup-inner">
        <div className="startup-brand">
          <div className="flex" style={{ gap: 12 }}>
            <BrandMark />
            <span id="startup-title" className="startup-word">
              SENTINEL
            </span>
          </div>
          <span className="startup-sub">INITIALIZING FRAUD INTELLIGENCE ENVIRONMENT</span>
        </div>
        <div className="startup-trace" aria-hidden="true" />
        <ul className="startup-checks" aria-live="polite" aria-label="Start-up checks">
          {checks.map((c, i) => (
            <LoadingCheck key={c.id} check={c} delayMs={i * 45} />
          ))}
        </ul>
        <div className="startup-foot">
          <span className={overall === "offline" ? "text-red" : overall === "degraded" ? "text-amber" : undefined} role="status">
            {status}
          </span>
          <span className="mono">{versions}</span>
        </div>
        {overall === "degraded" || overall === "offline" || slow ? (
          <div className="flex" style={{ justifyContent: "flex-end" }}>
            <button type="button" className="btn btn-ghost" onClick={() => void qc.invalidateQueries()}>
              Retry checks
            </button>
            <button type="button" ref={enterButton} className="btn" onClick={leave}>
              Enter console{overall === "operational" ? "" : " (degraded)"}
            </button>
          </div>
        ) : null}
      </div>
    </div>
  );
}
