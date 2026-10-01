import type { ReactNode } from "react";

export function Panel({
  title,
  meta,
  children,
  flush,
  note,
  id,
  className,
  headingLevel = 3,
}: {
  title: ReactNode;
  meta?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  note?: ReactNode;
  id?: string;
  className?: string;
  headingLevel?: 2 | 3;
}) {
  const H = headingLevel === 2 ? "h2" : "h3";
  const headingId = id ? `${id}-title` : undefined;
  return (
    <section className={`panel ${className ?? ""}`} aria-labelledby={headingId} id={id}>
      <div className="panel-head">
        <H id={headingId}>{title}</H>
        {meta ? <div className="panel-meta">{meta}</div> : null}
      </div>
      <div className={`panel-body ${flush ? "flush" : ""}`}>{children}</div>
      {note ? <div className="panel-note">{note}</div> : null}
    </section>
  );
}
