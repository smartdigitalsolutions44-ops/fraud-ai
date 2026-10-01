import type { CaseT } from "@/lib/api/schemas";
import { score } from "@/lib/format";

import { Badge } from "./Badge";
import { DecisionBadge } from "./DecisionBadge";
import { RiskBadge } from "./RiskBadge";

/**
 * Stored model scores side by side, each against its own threshold. No consensus or averaged
 * score is computed: models are listed separately and disagreement is stated, not resolved.
 */
export function ModelComparison({ models }: { models: CaseT["models"] }) {
  return (
    <div data-testid="model-comparison">
      <div className="spread" style={{ padding: "var(--space-3) var(--space-4)", borderBottom: "1px solid var(--border-subtle)" }}>
        <span className="muted" style={{ fontSize: "var(--text-sm)" }}>
          {models.rated
            ? `${models.flagged} of ${models.rated} models at or above their threshold`
            : "No model produced a comparable score"}
        </span>
        {models.disagreement ? (
          <Badge tone="amber" glyph="≠">
            Models disagree
          </Badge>
        ) : models.rated > 1 ? (
          <Badge tone="neutral" glyph="=">
            Models agree
          </Badge>
        ) : null}
      </div>
      {models.entries.map((m, i) => {
        const raw = m.raw_score ?? null;
        const t = m.threshold ?? null;
        return (
          <div key={`${m.role}-${m.model ?? i}`} className="model-row">
            <div style={{ minWidth: 0 }}>
              <div className="mono" style={{ overflowWrap: "anywhere" }} title={m.model ?? ""}>
                {m.model ?? "unknown model"}
              </div>
              <div className="flex" style={{ marginTop: 4 }}>
                <Badge tone={m.role === "shadow" ? "neutral" : "cyan"}>{m.role === "shadow" ? "Shadow · never decides" : m.role === "primary" ? "Primary" : m.role}</Badge>
              </div>
            </div>
            <div style={{ minWidth: 0 }}>
              <div
                className="score-track"
                role="img"
                aria-label={`Raw model score ${score(raw)}${t !== null ? `, threshold ${score(t)}` : ""}`}
              >
                {raw !== null ? <span className="score-fill" style={{ width: `${Math.min(100, Math.max(0, raw * 100))}%`, background: m.flagged ? "var(--orange)" : "var(--cyan)" }} /> : null}
                {t !== null ? <span className="score-threshold" style={{ left: `calc(${Math.min(100, t * 100)}% - 1px)` }} title={`threshold ${score(t)}`} /> : null}
              </div>
              <div className="flex faint" style={{ marginTop: 6, fontSize: "var(--text-xs)", gap: 12, flexWrap: "wrap" }}>
                <span>
                  model score <span className="mono muted">{score(raw)}</span>
                </span>
                <span>
                  threshold <span className="mono muted">{score(t)}</span>
                </span>
                {m.calibrated_score !== undefined && m.calibrated_score !== null ? (
                  <span title="The policy's calibrated score, which its risk bands are drawn on">
                    calibrated <span className="mono muted">{score(m.calibrated_score)}</span>
                  </span>
                ) : null}
                {m.role === "shadow" && m.agrees_with_active !== undefined && m.agrees_with_active !== null ? (
                  <span title="Shadow flag compared with the active decision being step-up or stronger">
                    {m.agrees_with_active ? "agrees with active decision" : "differs from active decision"}
                  </span>
                ) : null}
              </div>
            </div>
            <div>
              {m.flagged === null ? (
                <Badge tone="neutral">Not rated</Badge>
              ) : m.flagged ? (
                <Badge tone="orange" glyph="▲">
                  At/above threshold
                </Badge>
              ) : (
                <Badge tone="neutral" glyph="▽">
                  Below threshold
                </Badge>
              )}
            </div>
          </div>
        );
      })}
      {models.shadow_policies.length ? (
        <div style={{ padding: "var(--space-3) var(--space-4)", borderTop: "1px solid var(--border-subtle)" }}>
          <div className="label" style={{ marginBottom: 8 }}>
            Shadow policies (recorded, never decide)
          </div>
          {models.shadow_policies.map((p, i) => (
            <div key={`${p.policy_version}-${i}`} className="flex flex-wrap" style={{ fontSize: "var(--text-sm)", marginBottom: 4 }}>
              <span className="mono">{p.policy_version ?? "—"}</span>
              <span className="faint">would decide</span>
              <DecisionBadge decision={p.decision} />
              <RiskBadge level={p.risk_level} />
              {p.agrees === false ? (
                <Badge tone="amber" glyph="≠">
                  Differs from active
                </Badge>
              ) : p.agrees ? (
                <Badge tone="neutral" glyph="=">
                  Same as active
                </Badge>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
