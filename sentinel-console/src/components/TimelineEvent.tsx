import type { TimelineItemT } from "@/lib/api/schemas";
import { money, utcDate, utcTime } from "@/lib/format";

import { Badge } from "./Badge";

function title(t: TimelineItemT): string {
  return t.event_type.toLowerCase().replace(/_/g, " ");
}

/**
 * One event in the account's history around the case. Network flags are shown as signals
 * (a VPN, proxy or Tor exit is not proof of fraud); values come from the stored events.
 */
export function TimelineEvent({ item }: { item: TimelineItemT }) {
  const net = item.network;
  const flags = net ? (["vpn", "proxy", "tor", "datacenter"] as const).filter((f) => net[f]) : [];
  return (
    <li className="timeline-item" data-case={item.is_case_event ? "" : undefined} data-after={item.after_decision ? "" : undefined} data-testid="timeline-event">
      <span className="timeline-node" aria-hidden="true" />
      <div style={{ minWidth: 0 }}>
        <div className="timeline-row">
          <span className="timeline-time" title={`${utcDate(item.occurred_at)} ${utcTime(item.occurred_at)} UTC`}>
            {utcDate(item.occurred_at).slice(5)} {utcTime(item.occurred_at, false)}
          </span>
          <span className="truncate" style={{ fontWeight: item.is_case_event ? 600 : 400 }}>
            {title(item)}
          </span>
          {item.is_case_event ? (
            <Badge tone="blue" glyph="◉">
              This case
            </Badge>
          ) : null}
        </div>
        <div className="timeline-detail">
          {item.transaction ? (
            <span className="mono">
              {money(item.transaction.amount_minor, item.transaction.currency)}
              {item.transaction.merchant_category ? ` · ${item.transaction.merchant_category}` : ""}
              {item.transaction.channel ? ` · ${item.transaction.channel}` : ""}
            </span>
          ) : null}
          {item.login ? (
            <span>
              {item.event_type.startsWith("LOGIN") ? "" : `login ${item.login.outcome.toLowerCase()} · `}
              {item.login.auth_method?.toLowerCase() ?? "method not recorded"}
              {item.login.mfa_used ? " · MFA" : ""}
            </span>
          ) : null}
          {item.new_device ? <span className="text-amber">◇ new device</span> : null}
          {net?.country ? <span>{net.country}</span> : null}
          {net?.network_type ? <span>{net.network_type}</span> : null}
          {flags.map((f) => (
            <span key={f} className="text-amber" title="A network signal, not proof of fraud">
              ⚑ {f === "datacenter" ? "datacentre" : f.toUpperCase()}
            </span>
          ))}
          {item.security_event && item.security_event !== item.event_type ? <span>{item.security_event.toLowerCase()}</span> : null}
        </div>
      </div>
    </li>
  );
}
