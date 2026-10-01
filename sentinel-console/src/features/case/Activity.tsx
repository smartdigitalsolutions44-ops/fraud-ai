import { Panel } from "@/components/Panel";
import type { CaseT } from "@/lib/api/schemas";
import { utcDateTime } from "@/lib/format";

/** What happened to this case, from the service's records and hash-chained audit log.
 * Summaries only: no tokens, keys, signatures or raw rows. */
export function Activity({ items }: { items: CaseT["activity"] }) {
  return (
    <Panel title="Audit trail" id="activity" flush meta={<span>{items.length} entries</span>}>
      {items.length ? (
        <ol className="evidence-list" aria-label="Case activity">
          {items.map((a, i) => (
            <li key={`${a.kind}-${i}`} className="evidence-item" style={{ gridTemplateColumns: "150px 1fr", display: "grid", alignItems: "baseline" }}>
              <span className="mono faint" style={{ fontSize: "var(--text-2xs)" }}>
                {utcDateTime(a.at).replace(" UTC", "")}
              </span>
              <span style={{ minWidth: 0 }}>
                <span style={{ fontSize: "var(--text-sm)" }}>{a.summary}</span>
                <span className="faint mono" style={{ display: "block", fontSize: "var(--text-2xs)" }}>
                  {a.kind} · {a.source === "audit_log" ? `audit log${a.sequence !== undefined ? ` #${a.sequence}` : ""}` : a.source}
                </span>
              </span>
            </li>
          ))}
        </ol>
      ) : (
        <div className="empty">No recorded activity.</div>
      )}
    </Panel>
  );
}
