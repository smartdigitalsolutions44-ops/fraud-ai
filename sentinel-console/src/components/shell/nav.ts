import type { IconName } from "@/components/Icon";

export interface NavItem {
  href: string;
  label: string;
  icon: IconName;
  demoOnly?: boolean;
}

export const NAV: NavItem[] = [
  { href: "/", label: "Overview", icon: "overview" },
  { href: "/feed", label: "Live Feed", icon: "feed" },
  { href: "/queue", label: "Review Queue", icon: "queue" },
  { href: "/investigations", label: "Investigations", icon: "investigations" },
  { href: "/metrics", label: "Metrics", icon: "metrics" },
  { href: "/system", label: "System", icon: "system" },
  { href: "/demo", label: "Demo", icon: "demo", demoOnly: true },
];

export function isActive(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}

export function titleFor(pathname: string): string {
  const item = [...NAV].reverse().find((n) => isActive(pathname, n.href));
  return item?.label ?? "SENTINEL";
}
