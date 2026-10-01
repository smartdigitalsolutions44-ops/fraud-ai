"use client";

import { useCallback, useSyncExternalStore } from "react";

const EVENT = "sentinel:storage";

function read(store: "local" | "session", key: string): string | null {
  try {
    return (store === "local" ? localStorage : sessionStorage).getItem(key);
  } catch {
    return null; // private mode or blocked storage: behave as unset
  }
}

/**
 * A per-browser preference in local/session storage (never application data). Returns
 * `undefined` during server rendering and hydration, then the stored value.
 */
export function useStored(store: "local" | "session", key: string): [string | null | undefined, (v: string) => void] {
  const subscribe = useCallback((cb: () => void) => {
    const on = () => cb();
    window.addEventListener(EVENT, on);
    window.addEventListener("storage", on);
    return () => {
      window.removeEventListener(EVENT, on);
      window.removeEventListener("storage", on);
    };
  }, []);
  const value = useSyncExternalStore<string | null | undefined>(subscribe, () => read(store, key), () => undefined);
  const set = useCallback(
    (v: string) => {
      try {
        (store === "local" ? localStorage : sessionStorage).setItem(key, v);
      } catch {
        /* not persisted */
      }
      window.dispatchEvent(new Event(EVENT));
    },
    [store, key],
  );
  return [value, set];
}
