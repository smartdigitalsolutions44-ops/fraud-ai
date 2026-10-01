import { DECISION_ORDER, decisionLabel } from "@/lib/domain";
import { count, pct } from "@/lib/format";

const FILL: Record<string, string> = {
  green: "var(--green)",
  amber: "var(--amber)",
  orange: "var(--orange)",
  red: "var(--red)",
  neutral: "var(--neutral)",
};

/** Counts per policy decision, as a labelled bar list (readable without the bars). */
export function DecisionDistribution({ byDecision, total }: { byDecision: Record<string, number>; total: number }) {
  const keys = [...DECISION_ORDER, ...Object.keys(byDecision).filter((k) => !DECISION_ORDER.includes(k))];
  const max = Math.max(1, ...Object.values(byDecision));
  return (
    <ul className="dist" aria-label="Decision distribution" style={{ listStyle: "none", margin: 0, padding: 0 }}>
      {keys.map((k) => {
        const n = byDecision[k] ?? 0;
        const d = decisionLabel(k);
        return (
          <li key={k} className="dist-row">
            <span className="flex">
              <span className={`badge-glyph text-${d.tone === "neutral" ? "blue" : d.tone}`} aria-hidden="true">
                {d.glyph}
              </span>
              <span className="truncate">{d.label}</span>
            </span>
            <span className="dist-bar" aria-hidden="true">
              <span style={{ width: `${(n / max) * 100}%`, background: FILL[d.tone] }} />
            </span>
            <span className="mono" style={{ textAlign: "right" }}>
              {count(n)} <span className="faint">{pct(n, total)}</span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}
