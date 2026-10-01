import type { SVGProps } from "react";

/** A small inline icon set (1.5px strokes, 16px grid); decorative unless given a title. */
const PATHS: Record<string, string> = {
  overview: "M2.5 2.5h4.5v6h-4.5zM9 2.5h4.5v3.5H9zM9 8h4.5v5.5H9zM2.5 10.5h4.5v3H2.5z",
  feed: "M2 8h2.5l1.5-4 3 8 1.5-4H14",
  queue: "M3 4h10M3 8h10M3 12h6",
  investigations: "M7 12.5a5.5 5.5 0 1 1 0-11 5.5 5.5 0 0 1 0 11zM11 11l3.5 3.5",
  metrics: "M2.5 13.5h11M4 11V8M7 11V4.5M10 11V6.5M13 11V9",
  system: "M3 3.5h10v4H3zM3 9.5h10v4H3zM5 5.5h.01M5 11.5h.01",
  demo: "M5 3.5v9l7-4.5z",
  search: "M7 12a5 5 0 1 1 0-10 5 5 0 0 1 0 10zM10.8 10.8L14 14",
  check: "M3 8.5l3 3 7-7",
  x: "M4 4l8 8M12 4l-8 8",
  alert: "M8 2l6.5 11.5h-13zM8 6.5v3M8 11.5h.01",
  info: "M8 14.5a6.5 6.5 0 1 1 0-13 6.5 6.5 0 0 1 0 13zM8 7.5v4M8 5h.01",
  lock: "M4 7.5h8v6H4zM5.5 7.5V5a2.5 2.5 0 0 1 5 0v2.5",
  chevronDown: "M4 6l4 4 4-4",
  chevronRight: "M6 4l4 4-4 4",
  refresh: "M13 3.5v3.5H9.5M13 7A5 5 0 1 0 12 11",
  spark: "M8 2v3M8 11v3M2 8h3M11 8h3M4 4l2 2M10 10l2 2M12 4l-2 2M6 10l-2 2",
  external: "M9 3h4v4M13 3L7.5 8.5M11 9.5V13H3V5h3.5",
  copy: "M5.5 5.5h7v8h-7zM3.5 10.5v-8h7",
  shield: "M8 1.8l5 2v4c0 3.2-2.2 5.5-5 6.5-2.8-1-5-3.3-5-6.5v-4z",
  cpu: "M4.5 4.5h7v7h-7zM6.5 1.5v3M9.5 1.5v3M6.5 11.5v3M9.5 11.5v3M1.5 6.5h3M1.5 9.5h3M11.5 6.5h3M11.5 9.5h3",
  clock: "M8 14.5a6.5 6.5 0 1 1 0-13 6.5 6.5 0 0 1 0 13zM8 4.5V8l2.5 1.5",
  user: "M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM2.5 14.5c.8-2.6 3-4 5.5-4s4.7 1.4 5.5 4",
  reset: "M3 3.5v3.5h3.5M3 7a5 5 0 1 1 1 4.5",
  command: "M5.5 5.5h5v5h-5zM5.5 5.5V4a1.5 1.5 0 1 0-1.5 1.5zM10.5 5.5V4A1.5 1.5 0 1 1 12 5.5zM5.5 10.5V12A1.5 1.5 0 1 1 4 10.5zM10.5 10.5V12a1.5 1.5 0 1 0 1.5-1.5z",
};

export type IconName = keyof typeof PATHS;

export function Icon({ name, title, ...props }: { name: IconName; title?: string } & SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 16 16"
      width={16}
      height={16}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden={title ? undefined : true}
      role={title ? "img" : undefined}
      {...props}
    >
      {title ? <title>{title}</title> : null}
      <path d={PATHS[name]} />
    </svg>
  );
}

export function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 18 18" aria-hidden="true">
      <path d="M9 1.2l6.8 3v4.6c0 3.9-2.8 6.8-6.8 8-4-1.2-6.8-4.1-6.8-8V4.2z" fill="none" stroke="var(--cyan)" strokeWidth="1.3" />
      <path d="M5.2 9h2l1-2.6 1.6 5.2 1-2.6h2" fill="none" stroke="var(--text-0)" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
