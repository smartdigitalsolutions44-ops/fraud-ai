"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";

import { useStored } from "@/lib/hooks/useStored";
import { CHECK_STATES } from "@/lib/domain";

import { BrandMark } from "@/components/Icon";
import type { HealthGroup, Overall } from "@/features/system/groups";

const KEY = "sentinel.startup.done";
const MIN_VISIBLE_MS = 480; // long enough to register, never a reason to wait
const HOLD_MS = 260; // "all systems online" stays readable for a moment before leaving

/**
 * SENTINEL start-up (Stage 14): one line per operational group, each resolved by the real
 * readiness data (see features/system/groups.ts). Nothing here is animated into a state it
 * has not reached: a line says CHECKING until the service has answered for it.
 *
 * Shown once per browser session. It leaves by itself only when every group is ONLINE (or not
 * used), as soon as that is true; otherwise it stays, says what is wrong and what to do, and
 * the analyst chooses to enter a degraded console.
 */
export function StartupScreen({ groups, overall, versions, demoMode }: { groups: HealthGroup[]; overall: Overall; versions: string; demoMode: boolean }) {
  const qc = useQueryClient();
  // undefined until hydrated: the server cannot know whether this session already saw it
  const [seen, markSeen] = useStored("session", KEY);
  const [leaving, setLeaving] = useState(false);
  const [gone, setGone] = useState(false);
  const phase = seen === undefined ? "pending" : gone || (seen && !leaving) ? "hidden" : leaving ? "leaving" : "visible";
  const shownAt = useRef(0);
  const [resolvedMs, setResolvedMs] = useState<number | null>(null);
  const [slow, setSlow] = useState(false);
  const enterButton = useRef<HTMLButtonElement>(null);

  const leave = useCallback(() => {
    setLeaving(true);
    markSeen("1"); // not persisted in private mode: the checks simply show again next time
    setTimeout(() => setGone(true), 320);
  }, [markSeen]);

  useEffect(() => {
    if (phase === "visible" && !shownAt.current) shownAt.current = performance.now();
  }, [phase]);

  useEffect(() => {
    if (phase !== "visible" || overall === "checking" || resolvedMs !== null) return;
    setResolvedMs(Math.round(performance.now() - shownAt.current));
  }, [phase, overall, resolvedMs]);

  useEffect(() => {
    if (phase !== "visible") return;
    const t = setTimeout(() => setSlow(true), 10_000);
    return () => clearTimeout(t);
  }, [phase]);

  useEffect(() => {
    if (phase !== "visible" || overall !== "operational") return;
    const wait = Math.max(HOLD_MS, MIN_VISIBLE_MS - (performance.now() - shownAt.current));
    const t = setTimeout(leave, wait);
    return () => clearTimeout(t);
  }, [phase, overall, leave]);

  useEffect(() => {
    if (phase === "visible" && (overall === "degraded" || overall === "offline")) enterButton.current?.focus();
  }, [phase, overall]);

  if (phase === "hidden") return null;
  if (phase === "pending") return <div className="startup" aria-hidden="true" />;
  const resolved = groups.filter((g) => g.state !== "checking").length;
  const attention = groups.filter((g) => g.state === "offline" || g.state === "degraded");
  const status =
    overall === "checking"
      ? slow
        ? "Still waiting for the service: its checks are shown as they answer"
        : "Running readiness checks"
      : overall === "operational"
        ? "All systems online"
        : overall === "degraded"
          ? `${attention.length} group${attention.length === 1 ? "" : "s"} degraded: the console runs with reduced assurance`
          : "Core services offline: live data is unavailable";
  const serviceDown = groups.find((g) => g.id === "service")?.state === "offline";

  return (
    <div className="startup" data-leaving={phase === "leaving" ? "" : undefined} data-overall={overall} role="dialog" aria-modal="true" aria-labelledby="startup-title" aria-describedby="startup-status" data-testid="startup">
      <div className="startup-inner">
        <div className="startup-brand">
          <div className="startup-mark">
            <BrandMark />
            <span id="startup-title" className="startup-word">
              SENTINEL
            </span>
          </div>
          <div className="startup-sub">
            <span>SECURE ANALYST ENVIRONMENT</span>
            {demoMode ? <span className="startup-demo">DEMO MODE · SYNTHETIC DATA</span> : null}
          </div>
        </div>
        <div
          className="startup-progress"
          role="progressbar"
          aria-label="Readiness checks answered"
          aria-valuemin={0}
          aria-valuemax={groups.length}
          aria-valuenow={resolved}
        >
          <span style={{ width: `${(resolved / groups.length) * 100}%` }} />
        </div>
        <ol className="startup-seq" aria-label="Start-up checks">
          {groups.map((g, i) => (
            <li key={g.id} className="startup-line" data-check={g.id} data-state={g.state} style={{ animationDelay: `${i * 40}ms` }}>
              <span className="startup-index" aria-hidden="true">
                {String(i + 1).padStart(2, "0")}
              </span>
              <span className="startup-action">{g.action}</span>
              <span className="startup-leader" aria-hidden="true" />
              <span className="startup-state">
                <span className="sr-only">: </span>
                {g.state === "checking" ? "CHECKING" : CHECK_STATES[g.state].label.toUpperCase()}
              </span>
              <span className="startup-cause">{g.cause}</span>
            </li>
          ))}
        </ol>
        <div className="startup-foot">
          <span id="startup-status" className="startup-status" role="status">
            {status}
            {resolvedMs !== null ? <span className="startup-time"> · answered in {resolvedMs} ms</span> : null}
          </span>
          <span className="mono startup-versions">{versions}</span>
        </div>
        {overall === "offline" || (slow && overall === "checking") ? (
          <p className="startup-help">
            {serviceDown ? "The fraud service is not answering. " : ""}
            Check it with <span className="mono">sentinel-status</span>; its logs are in <span className="mono">.runtime/logs</span>.
          </p>
        ) : null}
        {overall === "degraded" || overall === "offline" || slow ? (
          <div className="startup-actions">
            <button type="button" className="btn btn-ghost" onClick={() => void qc.invalidateQueries()}>
              Retry checks
            </button>
            <button type="button" ref={enterButton} className="btn" onClick={leave} data-testid="enter-console">
              Enter console{overall === "operational" ? "" : overall === "offline" ? " (offline)" : " (degraded)"}
            </button>
          </div>
        ) : null}
      </div>
    </div>
  );
}
