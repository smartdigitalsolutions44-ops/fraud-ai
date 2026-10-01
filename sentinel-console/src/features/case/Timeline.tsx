"use client";

import { useState } from "react";

import { Panel } from "@/components/Panel";
import { TimelineEvent, changes } from "@/components/TimelineEvent";
import type { TimelineItemT } from "@/lib/api/schemas";
import { utcDate } from "@/lib/format";

/** Events with a day heading whenever the UTC date changes. */
function withDays(items: TimelineItemT[], caseAt: string | undefined, previousDay: string | null) {
  const out: React.ReactNode[] = [];
  let day = previousDay;
  for (const i of items) {
    const d = utcDate(i.occurred_at);
    if (d !== day) {
      out.push(
        <li key={`day-${d}-${i.event_id}`} className="timeline-day" aria-hidden="true">
          {d}
        </li>,
      );
      day = d;
    }
    out.push(<TimelineEvent key={i.event_id} item={i} caseAt={caseAt} />);
  }
  return { nodes: out, day };
}

const RECENT = 8;

/** The account's events around the case (up to 40 before and 10 after, within 24 hours of
 * the decision for "after"). Older history is collapsed until asked for. */
export function Timeline({ items }: { items: TimelineItemT[] }) {
  const [expanded, setExpanded] = useState(false);
  const caseIndex = items.findIndex((i) => i.is_case_event);
  const before = items.filter((i) => !i.is_case_event && !i.after_decision);
  const theCase = caseIndex >= 0 ? items[caseIndex] : undefined;
  const after = items.filter((i) => i.after_decision && !i.is_case_event);
  const hidden = expanded ? 0 : Math.max(0, before.length - RECENT);
  const shownBefore = before.slice(hidden);
  const caseAt = theCase?.occurred_at;
  const notable = items.filter((i) => changes(i).length).length;
  const first = withDays(theCase ? [...shownBefore, theCase] : shownBefore, caseAt, null);
  const second = withDays(after, caseAt, first.day);
  return (
    <Panel
      title="Timeline"
      id="timeline"
      flush
      meta={
        <span>
          {items.length} events{notable ? ` · ${notable} notable` : ""}
        </span>
      }
      note="Same pseudonymous account, oldest first. Times in UTC; offsets are from the case event. Marked events carry a stored signal (new device, network type, account change, failed login), not proof of fraud."
    >
      {items.length === 0 ? (
        <div className="empty">No events recorded for this account.</div>
      ) : (
        <ol className="timeline" aria-label="Account timeline">
          {hidden > 0 ? (
            <li style={{ padding: "0 var(--space-4) var(--space-2)" }}>
              <button type="button" className="btn btn-sm btn-ghost" onClick={() => setExpanded(true)} aria-expanded={false}>
                Show {hidden} earlier event{hidden === 1 ? "" : "s"}
              </button>
            </li>
          ) : before.length > RECENT ? (
            <li style={{ padding: "0 var(--space-4) var(--space-2)" }}>
              <button type="button" className="btn btn-sm btn-ghost" onClick={() => setExpanded(false)} aria-expanded={true}>
                Collapse earlier events
              </button>
            </li>
          ) : null}
          {first.nodes}
          {after.length ? (
            <li className="timeline-divider" aria-hidden="true">
              After the decision
            </li>
          ) : null}
          {second.nodes}
        </ol>
      )}
    </Panel>
  );
}
