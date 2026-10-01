"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useState, type ReactNode } from "react";

import { useRecovery } from "@/lib/hooks/useRecovery";
import { useStored } from "@/lib/hooks/useStored";

import { CommandPalette } from "@/components/CommandPalette";
import { useSystemStatus } from "@/features/system/useSystemStatus";

import { Nav } from "./Nav";
import { StartupScreen } from "./StartupScreen";
import { StatusBar } from "./StatusBar";
import { TopBar } from "./TopBar";

const DENSITY_KEY = "sentinel.density";
const PRESENTATION_KEY = "sentinel.presentation";

function typingTarget(el: EventTarget | null): boolean {
  const node = el as HTMLElement | null;
  if (!node) return false;
  return node.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(node.tagName);
}

export function Shell({ children }: { children: ReactNode }) {
  const status = useSystemStatus();
  const qc = useQueryClient();
  useRecovery();
  const [palette, setPalette] = useState(false);
  const [density, setDensity] = useStored("local", DENSITY_KEY);
  const compact = density === "compact";
  const toggleDensity = useCallback(() => setDensity(compact ? "comfortable" : "compact"), [compact, setDensity]);
  const [presentationFlag, setPresentation] = useStored("local", PRESENTATION_KEY);
  const presentation = presentationFlag === "on";
  const togglePresentation = useCallback(() => setPresentation(presentation ? "off" : "on"), [presentation, setPresentation]);
  const closePalette = useCallback(() => setPalette(false), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
        return;
      }
      if (e.ctrlKey || e.metaKey || e.altKey || typingTarget(e.target)) return;
      if (e.key === "r" || e.key === "R") {
        if (document.querySelector("[aria-modal='true']")) return;
        if (document.querySelector("[data-testid='case-workspace']")) return; // there R opens the resolve panel (never submits)
        e.preventDefault();
        void qc.invalidateQueries(); // refresh only: re-reads data, changes nothing
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [qc]);

  const session = status.session.data;
  const system = status.system.data;
  const versions = `console ${session?.console_version ?? "—"} · ${status.ready.data?.api_version ?? "api —"} · ${system?.policy?.policy_version ?? "policy —"}`;
  return (
    <div className="shell" data-density={compact ? "compact" : undefined} data-presentation={presentation ? "" : undefined}>
      <Nav session={session} apiVersion={status.ready.data?.api_version} />
      <TopBar session={session} overall={status.overall} onPalette={() => setPalette(true)} presentation={presentation} onExitPresentation={togglePresentation} />
      <main className="main" id="main" tabIndex={0} aria-label="Main content">
        {children}
      </main>
      <StatusBar session={session} system={system} />
      {palette ? <CommandPalette onClose={closePalette} demoMode={Boolean(session?.demo_mode)} onToggleDensity={toggleDensity} onTogglePresentation={togglePresentation} /> : null}
      <StartupScreen groups={status.groups} overall={status.overall} versions={versions} demoMode={Boolean(session?.demo_mode)} />
    </div>
  );
}
