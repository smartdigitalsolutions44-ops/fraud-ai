"use client";

import { useSystem } from "@/lib/api/queries";

/**
 * Reason codes exactly as the service returned them. The description (tooltip) comes from the
 * service's own reason catalogue; an unknown code is shown without one, never explained here.
 */
export function ReasonChips({ codes, max = 2 }: { codes: string[]; max?: number }) {
  const catalogue = useSystem().data?.reason_catalogue;
  if (!codes.length) return <span className="faint">—</span>;
  const shown = codes.slice(0, max);
  const rest = codes.length - shown.length;
  return (
    <span className="chips">
      {shown.map((c) => (
        <span key={c} className="chip" title={catalogue?.[c] ?? c}>
          {c}
        </span>
      ))}
      {rest > 0 ? (
        <span className="chip" title={codes.slice(max).join(", ")} aria-label={`${rest} more reason codes`}>
          +{rest}
        </span>
      ) : null}
    </span>
  );
}
