"use client";

import { memo } from "react";

import { priorityLabel } from "@/lib/domain";
import type { QueueItemT } from "@/lib/api/schemas";
import { age, shortId, utcDateTime } from "@/lib/format";

import { Badge } from "./Badge";
import { DecisionBadge } from "./DecisionBadge";
import { ReasonChips } from "./ReasonChips";
import { StatusBadge } from "./StatusBadge";

/** One review-queue item. The whole row opens the case; it carries no action of its own. */
export const CaseRow = memo(function CaseRow({
  item,
  selected,
  fresh,
  now,
  onOpen,
}: {
  item: QueueItemT;
  selected: boolean;
  fresh: boolean;
  now: number;
  onOpen: (item: QueueItemT) => void;
}) {
  const p = priorityLabel(item.priority);
  return (
    <tr
      data-interactive=""
      data-row-key={item.review_id}
      data-fresh={fresh ? "" : undefined}
      aria-selected={selected}
      tabIndex={0}
      onClick={() => onOpen(item)}
      onKeyDown={(e) => {
        if (e.key === "Enter" && e.currentTarget === e.target) onOpen(item);
      }}
      data-testid="case-row"
    >
      <td>
        <Badge tone={p.tone} title={`Queue priority ${item.priority} (1 is most urgent)`}>
          {p.label}
        </Badge>
      </td>
      <td title={utcDateTime(item.created_at)}>
        <span className="mono">{age(item.created_at, now)}</span> <span className="faint">ago</span>
      </td>
      <td style={{ whiteSpace: "nowrap" }}>
        <span className="mono" title={`review ${item.review_id}\nassessment ${item.assessment_id}\nevent ${item.event_id}`}>
          {shortId(item.review_id, 10)}
        </span>
        <span className="faint" style={{ marginLeft: 8, fontSize: "var(--text-xs)" }}>
          {item.event_type?.toLowerCase().replace(/_/g, " ") ?? ""}
        </span>
      </td>
      <td>
        <DecisionBadge decision={item.decision} />
      </td>
      <td>
        <ReasonChips codes={item.reason_codes} />
      </td>
      <td>
        <StatusBadge kind="auth" auth={item.authentication} />
      </td>
      <td>
        {item.status === "resolved" ? <StatusBadge kind="resolution" resolution={item.outcome} /> : <StatusBadge kind="review" status={item.status} />}
      </td>
    </tr>
  );
});
