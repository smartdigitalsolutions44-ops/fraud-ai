"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";

import { CaseRow } from "@/components/CaseRow";
import { DecisionBadge } from "@/components/DecisionBadge";
import { Panel } from "@/components/Panel";
import { Empty, ErrorState, SkeletonRows } from "@/components/States";
import { SEARCH_PATTERN, useQueue, useSearch } from "@/lib/api/queries";
import { shortId, utcDateTime } from "@/lib/format";
import { useListNavigation } from "@/lib/hooks/useListNavigation";
import { useNow } from "@/lib/hooks/useNow";

const KIND: Record<string, string> = { review: "Case", assessment: "Assessment", event: "Event" };

export function Investigations() {
  const router = useRouter();
  const [q, setQ] = useState("");
  const search = useSearch(q);
  const all = useQueue("all");
  const now = useNow(10_000);
  const recent = useMemo(
    () => [...(all.data?.items ?? [])].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()).slice(0, 25),
    [all.data],
  );
  const open = (assessmentId: string) => router.push(`/investigations/${assessmentId}`);
  const nav = useListNavigation(recent, (i) => i.review_id, (i) => open(i.assessment_id));
  const trimmed = q.trim();
  const valid = SEARCH_PATTERN.test(trimmed) && trimmed.replace(/-/g, "").length >= 8;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h2>Investigations</h2>
          <p>Open any case, assessment or event by its identifier. Search is by ID only; no personal data is searchable.</p>
        </div>
      </div>
      <Panel title="Find by ID">
        <form
          className="toolbar"
          onSubmit={(e) => {
            e.preventDefault();
            const first = search.data?.matches[0];
            if (first) open(first.assessment_id);
          }}
          role="search"
        >
          <input
            className="input mono"
            style={{ flex: 1, minWidth: 260 }}
            placeholder="case, assessment or event ID (8+ hex characters or a full UUID)"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            aria-label="Case, assessment or event ID"
            aria-invalid={trimmed !== "" && !valid}
            spellCheck={false}
            autoComplete="off"
          />
          <button type="submit" className="btn btn-primary" disabled={!search.data?.matches.length}>
            Open
          </button>
        </form>
        {trimmed && !valid ? (
          <p className="faint" style={{ marginTop: 8, fontSize: "var(--text-xs)" }}>
            Enter at least 8 hexadecimal characters of an ID.
          </p>
        ) : null}
        {valid ? (
          <div style={{ marginTop: 12 }}>
            {search.isFetching && !search.data ? <SkeletonRows rows={2} label="Searching" /> : null}
            {search.isError ? <ErrorState error={search.error} compact /> : null}
            {search.data && search.data.matches.length === 0 ? <p className="muted">No case, assessment or event matches this ID.</p> : null}
            {search.data?.matches.length ? (
              <ul className="evidence-list" aria-label="Matches">
                {search.data.matches.map((m) => (
                  <li key={`${m.kind}-${m.id}`} className="evidence-item">
                    <button type="button" className="btn btn-ghost" style={{ justifyContent: "flex-start" }} onClick={() => open(m.assessment_id)}>
                      <span className="label" style={{ minWidth: 80 }}>
                        {KIND[m.kind]}
                      </span>
                      <span className="mono">{shortId(m.id, 16)}</span>
                      {m.decision ? <DecisionBadge decision={m.decision} /> : null}
                      {m.assessed_at ? <span className="faint mono">{utcDateTime(m.assessed_at)}</span> : null}
                    </button>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : null}
      </Panel>
      <Panel title="Recent cases" flush note="The 25 most recent review items of any status.">
        {all.isPending ? (
          <SkeletonRows rows={6} />
        ) : all.isError && !all.data ? (
          <div className="panel-body">
            <ErrorState error={all.error} onRetry={() => void all.refetch()} />
          </div>
        ) : recent.length ? (
          <div className="table-wrap">
            <table className="table">
              <caption className="sr-only">Recent cases</caption>
              <thead>
                <tr>
                  <th scope="col">Priority</th>
                  <th scope="col">Created</th>
                  <th scope="col">Case / event</th>
                  <th scope="col">Decision</th>
                  <th scope="col">Reasons</th>
                  <th scope="col">Step-up</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((i) => (
                  <CaseRow key={i.review_id} item={i} now={now} selected={nav.selected === i.review_id} fresh={false} onOpen={(x) => open(x.assessment_id)} />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No review items yet">Cases the policy sends for review are listed here.</Empty>
        )}
      </Panel>
    </div>
  );
}
