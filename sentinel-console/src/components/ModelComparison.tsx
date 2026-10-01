import type { CaseT } from "@/lib/api/schemas";
import { score } from "@/lib/format";

import { Badge } from "./Badge";
import { DecisionBadge } from "./DecisionBadge";
import { RiskBadge } from "./RiskBadge";

type Entry = CaseT["models"]["entries"][number];

/** "gradient-boosting-1.0.0" -> ["gradient-boosting", "1.0.0"]; anything else unchanged. */
export function splitModel(ref: string | null | undefined): [string, string | null] {
  if (!ref) return ["unknown model", null];
  const m = /^(.*)-(\d+\.\d+\.\d+(?:[-+.][\w.]+)?)$/.exec(ref);
  return m ? [m[1]!, m[2]!] : [ref, null];
}

function ModelRow({ m }: { m: Entry }) {
  const raw = m.raw_score ?? null;
  const t = m.threshold ?? null;
  const [name, version] = splitModel(m.model);
  const shadow = m.role === "shadow";
  return (
    <div className="model-row" data-role={m.role}>
      <div style={{ minWidth: 0 }}>
        <div className="model-name" title={m.model ?? ""}>
          <span className="mono">{name}</span>
          {version ? <span className="model-version mono">v{version}</span> : null}
        </div>
        <div className="flex" style={{ marginTop: 4 }}>
          <Badge tone={shadow ? "neutral" : "cyan"}>{shadow ? "Shadow · never decides" : m.role === "primary" ? "Primary" : m.role}</Badge>
        </div>
      </div>
      <div style={{ minWidth: 0 }}>
        <div className="score-track" role="img" aria-label={`${name} raw score ${score(raw)}${t !== null ? `, its own threshold ${score(t)}` : ""}`}>
          {raw !== null ? <span className="score-fill" style={{ width: `${Math.min(100, Math.max(0, raw * 100))}%`, background: m.flagged ? "var(--orange)" : "var(--cyan)" }} /> : null}
          {t !== null ? <span className="score-threshold" style={{ left: `calc(${Math.min(100, t * 100)}% - 1px)` }} title={`threshold ${score(t)}`} /> : null}
        </div>
        <div className="flex faint" style={{ marginTop: 6, fontSize: "var(--text-xs)", gap: 12, flexWrap: "wrap" }}>
          <span>
            score <span className="mono muted">{score(raw)}</span>
          </span>
          <span>
            threshold <span className="mono muted">{score(t)}</span>
          </span>
          {m.calibrated_score !== undefined && m.calibrated_score !== null ? (
            <span title="The policy's calibrated score, which its risk bands are drawn on">
              calibrated <span className="mono muted">{score(m.calibrated_score)}</span>
            </span>
          ) : null}
          {shadow && m.agrees_with_active !== undefined && m.agrees_with_active !== null ? (
            <span className={m.agrees_with_active ? undefined : "text-amber"} title="Shadow flag compared with the active decision being step-up or stronger">
              {m.agrees_with_active ? "agrees with the active decision" : "differs from the active decision"}
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
}

/**
 * Stored model scores, each against its own threshold. The primary model is shown apart from
 * the shadow models because only it drives the policy decision (through its calibrated score
 * and the risk bands); shadow models are recorded for comparison and never decide. No
 * consensus or averaged score is computed, and disagreement is stated, never resolved: this
 * is not a vote.
 */
export function ModelComparison({ models }: { models: CaseT["models"] }) {
  const primary = models.entries.filter((m) => m.role !== "shadow");
  const shadows = models.entries.filter((m) => m.role === "shadow");
  return (
    <div data-testid="model-comparison">
      <div className="model-verdict" data-disagree={models.disagreement ? "" : undefined}>
        <span>
          {models.rated
            ? models.disagreement
              ? `Models disagree: ${models.flagged} of ${models.rated} at or above their own threshold. The decision is the active policy's, as recorded; shadow results never change it.`
              : models.rated > 1
                ? `Models agree: ${models.flagged} of ${models.rated} at or above their own threshold.`
                : `${models.flagged} of ${models.rated} model at or above its threshold.`
            : "No model produced a comparable score."}
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
      {primary.length ? (
        <section aria-label="Primary model">
          <div className="model-group label">Decides · through the active policy</div>
          {primary.map((m, i) => (
            <ModelRow key={`${m.role}-${m.model ?? i}`} m={m} />
          ))}
        </section>
      ) : null}
      {shadows.length ? (
        <section aria-label="Shadow models">
          <div className="model-group label">Recorded for comparison · never decides</div>
          {shadows.map((m, i) => (
            <ModelRow key={`${m.role}-${m.model ?? i}`} m={m} />
          ))}
        </section>
      ) : null}
      {models.shadow_policies.length ? (
        <div style={{ padding: "var(--space-3) var(--space-4)", borderTop: "1px solid var(--border-subtle)" }}>
          <div className="label" style={{ marginBottom: 8 }}>
            Shadow policies (recorded, never decide)
          </div>
          {models.shadow_policies.map((p, i) => (
            <div key={`${p.policy_version}-${i}`} className="flex flex-wrap" style={{ fontSize: "var(--text-sm)", marginBottom: 4 }}>
              <span className="mono">{p.policy_version ?? "—"}</span>
              <span className="faint">would have decided</span>
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
