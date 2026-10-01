"use client";

import { useEffect, useLayoutEffect, useRef, useState } from "react";

function typing(el: EventTarget | null): boolean {
  const n = el as HTMLElement | null;
  return Boolean(n && (n.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(n.tagName)));
}

/**
 * J/K move the selection, Enter opens it, Esc clears it. Navigation only: no key here ever
 * changes data (resolutions always need a button and a confirmation).
 */
export function useListNavigation<T>(items: T[], keyOf: (item: T) => string, onOpen: (item: T) => void, enabled = true) {
  const [selected, setSelected] = useState<string | null>(null);
  const latest = useRef({ items, keyOf, onOpen, selected });
  useLayoutEffect(() => {
    latest.current = { items, keyOf, onOpen, selected };
  });

  useEffect(() => {
    if (!enabled) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || typing(e.target)) return;
      if (document.querySelector("[aria-modal='true']")) return;
      const { items: list, keyOf: k, onOpen: open, selected: sel } = latest.current;
      if (!list.length) return;
      const index = sel ? list.findIndex((i) => k(i) === sel) : -1;
      if (e.key === "j" || e.key === "J") {
        e.preventDefault();
        const next = list[Math.min(index + 1, list.length - 1)];
        if (next) setSelected(k(next));
      } else if (e.key === "k" || e.key === "K") {
        e.preventDefault();
        const prev = list[Math.max(index - 1, 0)];
        if (prev) setSelected(k(prev));
      } else if (e.key === "Enter" && index >= 0) {
        const item = list[index];
        if (item && document.activeElement?.tagName !== "BUTTON" && document.activeElement?.tagName !== "A") {
          e.preventDefault();
          open(item);
        }
      } else if (e.key === "Escape") {
        setSelected(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [enabled]);

  useEffect(() => {
    if (selected) document.querySelector(`[data-row-key="${selected}"]`)?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  return { selected, setSelected };
}
