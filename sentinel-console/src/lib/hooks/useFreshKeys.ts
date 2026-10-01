"use client";

import { useState } from "react";

const EMPTY = new Set<string>();

/** Keys that appeared since the previous poll (for a brief highlight; not on first load).
 * Uses React's "state from the previous render" pattern, keyed on the list's content. */
export function useFreshKeys(keys: string[] | undefined): Set<string> {
  const signature = keys?.join("|") ?? null;
  const [state, setState] = useState<{ signature: string | null; seen: Set<string> | null; fresh: Set<string> }>({
    signature,
    seen: keys ? new Set(keys) : null,
    fresh: EMPTY,
  });
  if (signature !== state.signature) {
    const fresh = new Set<string>();
    if (keys && state.seen) for (const k of keys) if (!state.seen.has(k)) fresh.add(k);
    setState({ signature, seen: keys ? new Set(keys) : state.seen, fresh });
    return fresh;
  }
  return state.fresh;
}
