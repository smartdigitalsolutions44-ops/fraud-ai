"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useEffect, useId, useMemo, useRef, useState } from "react";

import { NAV } from "@/components/shell/nav";
import { SEARCH_PATTERN, useDemoScenarios, useSearch } from "@/lib/api/queries";
import { shortId } from "@/lib/format";

import { Icon, type IconName } from "./Icon";

interface Command {
  id: string;
  group: string;
  label: string;
  hint?: string;
  icon: IconName;
  run: () => void;
}

/**
 * Ctrl/Cmd+K. Navigation, lookup by case / assessment / event id, the demo scenarios (they
 * open the Demo page; nothing is played from here), system status, and view preferences.
 * Deliberately contains no consequential action: no resolutions, no demo reset, no scoring.
 */
export function CommandPalette({
  onClose,
  demoMode,
  onToggleDensity,
  onTogglePresentation,
}: {
  onClose: () => void;
  demoMode: boolean;
  onToggleDensity: () => void;
  onTogglePresentation?: () => void;
}) {
  const router = useRouter();
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [index, setIndex] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const listId = useId();
  const search = useSearch(q);
  const scenarios = useDemoScenarios(demoMode);

  // mounted only while open: focus the input, and give focus back when closed
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    input.current?.focus();
    return () => previous?.focus?.();
  }, []);

  const commands = useMemo<Command[]>(() => {
    const go = (href: string) => () => {
      router.push(href);
      onClose();
    };
    const nav: Command[] = NAV.filter((n) => !n.demoOnly || demoMode).map((n) => ({
      id: `nav:${n.href}`,
      group: "Go to",
      label: n.label,
      icon: n.icon,
      run: go(n.href),
    }));
    const view: Command[] = [
      {
        id: "refresh",
        group: "View",
        label: "Refresh all data",
        hint: "R",
        icon: "refresh",
        run: () => {
          void qc.invalidateQueries();
          onClose();
        },
      },
      { id: "status", group: "View", label: "System status (all groups)", icon: "system", run: go("/system") },
      { id: "density", group: "View", label: "Toggle compact density", icon: "queue", run: () => (onToggleDensity(), onClose()) },
      ...(onTogglePresentation
        ? [{ id: "presentation", group: "View", label: "Toggle presentation mode", icon: "overview" as IconName, run: () => (onTogglePresentation(), onClose()) }]
        : []),
    ];
    const demo: Command[] = demoMode
      ? (scenarios.data?.scenarios ?? []).map((sc) => ({
          id: `scenario:${sc.label}`,
          group: "Demo scenarios",
          label: `Scenario: ${sc.title}`,
          hint: "opens the Demo page",
          icon: "demo" as IconName,
          run: go(`/demo#scenario-${sc.label}`),
        }))
      : [];
    const found: Command[] = (search.data?.matches ?? []).map((m) => ({
      id: `match:${m.kind}:${m.id}`,
      group: "Matches",
      label: `${m.kind === "review" ? "Case" : m.kind === "assessment" ? "Assessment" : "Event"} ${shortId(m.id, 12)}`,
      hint: m.decision ?? undefined,
      icon: "investigations",
      run: go(`/investigations/${m.assessment_id}`),
    }));
    const needle = q.trim().toLowerCase();
    const all = [...nav, ...view, ...demo];
    const filtered = needle && !SEARCH_PATTERN.test(needle) ? all.filter((c) => c.label.toLowerCase().includes(needle)) : all;
    return [...found, ...filtered];
  }, [router, onClose, demoMode, qc, onToggleDensity, onTogglePresentation, scenarios.data, search.data, q]);

  const active = commands[Math.min(index, commands.length - 1)];
  const idLike = SEARCH_PATTERN.test(q.trim()) && q.replace(/-/g, "").trim().length >= 8;

  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dialog palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <input
          ref={input}
          className="palette-input"
          placeholder="Go to a page, or paste a case / assessment / event ID…"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setIndex(0);
          }}
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-activedescendant={active ? `${listId}-${active.id}` : undefined}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setIndex((i) => Math.min(i + 1, commands.length - 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setIndex((i) => Math.max(i - 1, 0));
            } else if (e.key === "Enter") {
              e.preventDefault();
              active?.run();
            } else if (e.key === "Escape") {
              e.preventDefault();
              onClose();
            } else if (e.key === "Tab") {
              e.preventDefault(); // keep focus inside the dialog
            }
          }}
          spellCheck={false}
          autoComplete="off"
        />
        <ul className="palette-list" id={listId} role="listbox" aria-label="Commands">
          {idLike && search.isFetching ? <li className="palette-group label">Searching…</li> : null}
          {idLike && search.data && search.data.matches.length === 0 ? (
            <li className="palette-group faint" style={{ fontSize: "var(--text-sm)" }}>
              No case, assessment or event with this ID.
            </li>
          ) : null}
          {commands.map((c, i) => (
            <li
              key={c.id}
              id={`${listId}-${c.id}`}
              role="option"
              aria-selected={c === active}
              className="palette-item"
              onMouseEnter={() => setIndex(i)}
              onClick={() => c.run()}
            >
              <Icon name={c.icon} />
              <span className="truncate">{c.label}</span>
              <span className="hint">{c.hint ?? c.group}</span>
            </li>
          ))}
        </ul>
        <div className="dialog-foot" style={{ justifyContent: "space-between" }}>
          <span className="faint" style={{ fontSize: "var(--text-xs)" }}>
            Search by ID only (8+ hex characters). No personal data is searchable.
          </span>
          <span className="faint" style={{ fontSize: "var(--text-xs)" }}>
            <kbd>↑</kbd> <kbd>↓</kbd> <kbd>Enter</kbd> <kbd>Esc</kbd>
          </span>
        </div>
      </div>
    </div>
  );
}
