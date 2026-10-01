"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { BrandMark, Icon } from "@/components/Icon";
import { LiveIndicator } from "@/components/LiveIndicator";
import { POLL, useQueue } from "@/lib/api/queries";
import type { SessionT } from "@/lib/api/schemas";
import { useLiveness } from "@/lib/hooks/useLiveness";

import { NAV, isActive } from "./routes";

export function Nav({ session, apiVersion }: { session?: SessionT; apiVersion?: string }) {
  const pathname = usePathname();
  const queue = useQueue("open");
  const live = useLiveness(queue, POLL.queue);
  const open = queue.data?.items.length;
  return (
    <nav className="nav" aria-label="Primary">
      <div className="nav-brand">
        <BrandMark />
        <span className="brand-word">SENTINEL</span>
      </div>
      <ul className="nav-list">
        {NAV.filter((n) => !n.demoOnly || session?.demo_mode).map((n) => (
          <li key={n.href}>
            <Link
              href={n.href}
              className="nav-link"
              aria-current={isActive(pathname, n.href) ? "page" : undefined}
              title={n.label}
              aria-label={n.href === "/queue" && open !== undefined ? `${n.label}, ${open} open` : n.label}
            >
              <Icon name={n.icon} />
              <span>{n.label}</span>
              {n.href === "/queue" && open !== undefined ? (
                <span className="nav-count" aria-label={`${open} open review items`}>
                  {open}
                </span>
              ) : null}
            </Link>
          </li>
        ))}
      </ul>
      <div className="nav-foot">
        <div className="nav-foot-row">
          <span>Console</span>
          <span>v{session?.console_version ?? "—"}</span>
        </div>
        <div className="nav-foot-row">
          <span>API</span>
          <span>{apiVersion ?? "—"}</span>
        </div>
        <div className="nav-foot-row">
          <span>Environment</span>
          <span>{session?.environment ?? "—"}</span>
        </div>
        <div className="nav-foot-row">
          <span>Connection</span>
          <LiveIndicator state={live.state} ageMs={null} />
        </div>
      </div>
    </nav>
  );
}
