import type { ReactNode } from "react";

import type { Tone } from "@/lib/domain";

/** The base pill: tone colour plus a glyph and text, so meaning never rests on colour. */
export function Badge({ tone, glyph, children, title }: { tone: Tone; glyph?: string; children: ReactNode; title?: string }) {
  return (
    <span className={`badge tone-${tone}`} title={title}>
      {glyph ? (
        <span className="badge-glyph" aria-hidden="true">
          {glyph}
        </span>
      ) : null}
      {children}
    </span>
  );
}
