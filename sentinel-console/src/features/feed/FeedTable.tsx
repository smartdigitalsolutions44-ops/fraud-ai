"use client";

import { useRouter } from "next/navigation";
import { memo } from "react";

import { DecisionBadge } from "@/components/DecisionBadge";
import { ReasonChips } from "@/components/ReasonChips";
import { RiskBadge } from "@/components/RiskBadge";
import { StatusBadge } from "@/components/StatusBadge";
import type { FeedItemT } from "@/lib/api/schemas";
import { shortId, utcDate, utcTime } from "@/lib/format";
import { useFreshKeys } from "@/lib/hooks/useFreshKeys";
import { useListNavigation } from "@/lib/hooks/useListNavigation";

function eventKind(type: string | null): string {
  if (!type) return "";
  return type.toLowerCase().replace(/_/g, " ");
}

const Row = memo(function Row({
  item,
  selected,
  fresh,
  onOpen,
}: {
  item: FeedItemT;
  selected: boolean;
  fresh: boolean;
  onOpen: (item: FeedItemT) => void;
}) {
  return (
    <tr
      data-interactive=""
      data-row-key={item.assessment_id}
      data-fresh={fresh ? "" : undefined}
      aria-selected={selected}
      tabIndex={0}
      onClick={() => onOpen(item)}
      onKeyDown={(e) => {
        if (e.key === "Enter" && e.currentTarget === e.target) onOpen(item);
      }}
    >
      <td className="mono" title={`${utcDate(item.assessed_at)} ${utcTime(item.assessed_at)} UTC`}>
        {utcTime(item.assessed_at)}
      </td>
      <td style={{ whiteSpace: "nowrap" }}>
        <span className="mono" title={`event ${item.event_id}`}>
          {shortId(item.event_id, 10)}
        </span>
        <span className="faint" style={{ marginLeft: 8, fontSize: "var(--text-xs)" }}>
          {eventKind(item.event_type)}
          {item.mode === "step_up_followup" ? " · follow-up" : ""}
        </span>
      </td>
      <td>
        <RiskBadge level={item.risk_level} />
      </td>
      <td>
        <DecisionBadge decision={item.decision} />
      </td>
      <td>
        <ReasonChips codes={item.reason_codes} />
      </td>
      <td>{item.review ? <StatusBadge kind="review" status={item.review.status} /> : <span className="faint">—</span>}</td>
      <td>
        <StatusBadge kind="auth" auth={item.authentication} />
      </td>
      <td className="num mono faint">{item.latency_ms === null ? "—" : `${Math.round(item.latency_ms)}`}</td>
    </tr>
  );
});

/** Assessments, newest first. References are pseudonymous ids; no personal data is shown. */
export function FeedTable({ items, keyboard = true, caption }: { items: FeedItemT[]; keyboard?: boolean; caption: string }) {
  const router = useRouter();
  const open = (item: FeedItemT) => router.push(`/investigations/${item.assessment_id}`);
  const nav = useListNavigation(items, (i) => i.assessment_id, open, keyboard);
  const fresh = useFreshKeys(items.map((i) => i.assessment_id));
  return (
    <div className="table-wrap">
      <table className="table" data-testid="feed-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Time (UTC)</th>
            <th scope="col">Event</th>
            <th scope="col">Risk band</th>
            <th scope="col">Decision</th>
            <th scope="col">Reasons</th>
            <th scope="col">Review</th>
            <th scope="col">Step-up</th>
            <th scope="col" className="num">
              ms
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <Row key={item.assessment_id} item={item} selected={nav.selected === item.assessment_id} fresh={fresh.has(item.assessment_id)} onOpen={open} />
          ))}
        </tbody>
      </table>
    </div>
  );
}
