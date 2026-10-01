"use client";

import { useSystem } from "@/lib/api/queries";
import { reasonTitle } from "@/lib/reasons";

/**
 * Reason codes as readable titles (Stage 14); the exact code and the service's own catalogue
 * description are in the tooltip. An unknown code gets a title from its own name, never an
 * explanation.
 */
export function ReasonChips({ codes, max = 2 }: { codes: string[]; max?: number }) {
  const catalogue = useSystem().data?.reason_catalogue;
  if (!codes.length) return <span className="faint">—</span>;
  const shown = codes.slice(0, max);
  const rest = codes.length - shown.length;
  return (
    <span className="chips">
      {shown.map((c) => (
        <span key={c} className="chip chip-title" title={`${c}${catalogue?.[c] ? `: ${catalogue[c]}` : ""}`} data-code={c}>
          {reasonTitle(c)}
        </span>
      ))}
      {rest > 0 ? (
        <span className="chip" title={codes.slice(max).map(reasonTitle).join(", ")} aria-label={`${rest} more reason codes`}>
          +{rest}
        </span>
      ) : null}
    </span>
  );
}
