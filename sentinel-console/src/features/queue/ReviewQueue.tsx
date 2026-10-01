"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";

import { CaseRow } from "@/components/CaseRow";
import { Icon } from "@/components/Icon";
import { LiveIndicator } from "@/components/LiveIndicator";
import { Panel } from "@/components/Panel";
import { Empty, ErrorState, SkeletonRows } from "@/components/States";
import { CaseWorkspace } from "@/features/case/CaseWorkspace";
import { POLL, useQueue } from "@/lib/api/queries";
import type { QueueItemT } from "@/lib/api/schemas";
import { DECISION_ORDER, decisionLabel } from "@/lib/domain";
import { useFreshKeys } from "@/lib/hooks/useFreshKeys";
import { useListNavigation } from "@/lib/hooks/useListNavigation";
import { useLiveness } from "@/lib/hooks/useLiveness";
import { useNow } from "@/lib/hooks/useNow";

import { DEFAULT_FILTERS, ID_FILTER, applyFilters, reasonOptions, type QueueFilters } from "./filters";

type StatusFilter = "open" | "needs_more_information" | "resolved" | "all";
const STATUSES: Array<{ value: StatusFilter; label: string }> = [
  { value: "open", label: "Open" },
  { value: "needs_more_information", label: "Needs info" },
  { value: "resolved", label: "Resolved" },
  { value: "all", label: "All" },
];

function typing(el: EventTarget | null): boolean {
  const n = el as HTMLElement | null;
  return Boolean(n && (n.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(n.tagName)));
}

export function ReviewQueue() {
  const router = useRouter();
  const params = useSearchParams();
  const caseId = params.get("case");
  const [status, setStatus] = useState<StatusFilter>("open");
  const [filters, setFilters] = useState<QueueFilters>(DEFAULT_FILTERS);
  const queue = useQueue(status);
  const live = useLiveness(queue, POLL.queue);
  const now = useNow(5000);
  const all = queue.data?.items;
  const items = useMemo(() => applyFilters(all ?? [], filters, now), [all, filters, now]);
  const reasons = useMemo(() => reasonOptions(all ?? []), [all]);
  const fresh = useFreshKeys(all?.map((i) => i.review_id));

  const open = useCallback((item: QueueItemT) => router.push(`/queue?case=${item.assessment_id}`), [router]);
  const nav = useListNavigation(items, (i) => i.review_id, open, !caseId);
  const set = <K extends keyof QueueFilters>(k: K, v: QueueFilters[K]) => setFilters((f) => ({ ...f, [k]: v }));
  const filtered = JSON.stringify({ ...filters, sort: "" }) !== JSON.stringify({ ...DEFAULT_FILTERS, sort: "" });

  // inside a case: J/K step through the filtered queue, Esc returns to it
  const index = caseId ? items.findIndex((i) => i.assessment_id === caseId) : -1;
  useEffect(() => {
    if (!caseId) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey || e.altKey || typing(e.target) || document.querySelector("[aria-modal='true']")) return;
      if (e.key === "Escape") {
        e.preventDefault();
        router.push("/queue");
      } else if ((e.key === "j" || e.key === "J") && index >= 0 && items[index + 1]) {
        router.push(`/queue?case=${items[index + 1]!.assessment_id}`);
      } else if ((e.key === "k" || e.key === "K") && index > 0 && items[index - 1]) {
        router.push(`/queue?case=${items[index - 1]!.assessment_id}`);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [caseId, index, items, router]);

  if (caseId) {
    return (
      <div className="page">
        <div className="toolbar">
          <button type="button" className="btn btn-sm" onClick={() => router.push("/queue")}>
            <Icon name="chevronRight" style={{ transform: "rotate(180deg)" }} /> Back to queue <kbd>Esc</kbd>
          </button>
          {index >= 0 ? (
            <span className="faint" style={{ fontSize: "var(--text-xs)" }}>
              Case {index + 1} of {items.length} in this view · <kbd>J</kbd> next · <kbd>K</kbd> previous
            </span>
          ) : null}
        </div>
        <CaseWorkspace assessmentId={caseId} />
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h2>Review queue</h2>
          <p>Assessments the risk policy sent to an analyst. Priority 1 is most urgent; ties are oldest first.</p>
        </div>
        <div className="toolbar">
          <LiveIndicator state={live.state} ageMs={live.ageMs} />
          <div className="segmented" role="group" aria-label="Review status">
            {STATUSES.map((s) => (
              <button key={s.value} type="button" aria-pressed={status === s.value} onClick={() => setStatus(s.value)}>
                {s.label}
              </button>
            ))}
          </div>
        </div>
      </div>
      {live.state === "stale" ? (
        <div className="stale-banner" role="status">
          <Icon name="alert" /> The queue could not be refreshed. It may have changed since the last update.
        </div>
      ) : null}
      <Panel
        title={
          <span>
            {STATUSES.find((s) => s.value === status)?.label} items{" "}
            {all ? (
              <span className="faint mono" style={{ fontWeight: 400 }}>
                {items.length}
                {filtered ? ` of ${all.length}` : ""}
              </span>
            ) : null}
          </span>
        }
        flush
        meta={
          <div className="toolbar" role="group" aria-label="Filters">
            <input
              className="input"
              style={{ width: 170 }}
              placeholder="Filter by ID…"
              aria-label="Filter by case, assessment or event ID"
              value={filters.id}
              onChange={(e) => set("id", e.target.value)}
              aria-invalid={filters.id !== "" && !ID_FILTER.test(filters.id.trim())}
              spellCheck={false}
            />
            <select className="select" aria-label="Decision" value={filters.decision} onChange={(e) => set("decision", e.target.value)}>
              <option value="">Any decision</option>
              {DECISION_ORDER.map((d) => (
                <option key={d} value={d}>
                  {decisionLabel(d).label}
                </option>
              ))}
            </select>
            <select className="select" aria-label="Reason" value={filters.reason} onChange={(e) => set("reason", e.target.value)} style={{ maxWidth: 220 }}>
              <option value="">Any reason</option>
              {reasons.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <select className="select" aria-label="Age" value={filters.age} onChange={(e) => set("age", e.target.value as QueueFilters["age"])}>
              <option value="any">Any age</option>
              <option value="lt1h">Under 1 hour</option>
              <option value="lt24h">Under 24 hours</option>
              <option value="gt24h">Over 24 hours</option>
            </select>
            <select className="select" aria-label="Step-up authentication" value={filters.auth} onChange={(e) => set("auth", e.target.value as QueueFilters["auth"])}>
              <option value="any">Any step-up</option>
              <option value="none">Not requested</option>
              <option value="pending">Pending</option>
              <option value="passed">Passed</option>
              <option value="failed">Failed / expired</option>
            </select>
            <select className="select" aria-label="Sort" value={filters.sort} onChange={(e) => set("sort", e.target.value as QueueFilters["sort"])}>
              <option value="priority">Sort: priority</option>
              <option value="newest">Sort: newest</option>
              <option value="oldest">Sort: oldest</option>
            </select>
            {filtered ? (
              <button type="button" className="btn btn-sm btn-ghost" onClick={() => setFilters((f) => ({ ...DEFAULT_FILTERS, sort: f.sort }))}>
                Clear
              </button>
            ) : null}
          </div>
        }
        note="The service does not assign cases to analysts; status is the review item's own. Filters apply to the items loaded (up to 500)."
      >
        {queue.isPending ? (
          <SkeletonRows rows={8} label="Loading review queue" />
        ) : queue.isError && !queue.data ? (
          <div className="panel-body">
            <ErrorState error={queue.error} onRetry={() => void queue.refetch()} />
          </div>
        ) : items.length ? (
          <div className="table-wrap">
            <table className="table" data-testid="queue-table">
              <caption className="sr-only">Review queue</caption>
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
                {items.map((item) => (
                  <CaseRow key={item.review_id} item={item} now={now} selected={nav.selected === item.review_id} fresh={fresh.has(item.review_id)} onOpen={open} />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          filtered ? (
            <Empty title="No items match these filters">Clear a filter to see the rest of the queue.</Empty>
          ) : status === "open" ? (
            <Empty title="No cases require review">Monitoring remains active. New review items appear here within seconds.</Empty>
          ) : (
            <Empty title="No items">Nothing with this status.</Empty>
          )
        )}
      </Panel>
    </div>
  );
}
