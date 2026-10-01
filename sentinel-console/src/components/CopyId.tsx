"use client";

import { useState } from "react";

import { shortId } from "@/lib/format";

import { Icon } from "./Icon";

/** A pseudonymous identifier: short form shown, full value on hover and copy. */
export function CopyId({ id, label, n = 12 }: { id: string; label: string; n?: number }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="flex" style={{ gap: 4 }}>
      <span className="mono" title={`${label} ${id}`}>
        {shortId(id, n)}
      </span>
      <button
        type="button"
        className="btn btn-sm btn-ghost"
        style={{ padding: "0 4px", height: 20 }}
        aria-label={`Copy ${label} ${id}`}
        onClick={() => {
          void navigator.clipboard?.writeText(id).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          });
        }}
      >
        <Icon name={copied ? "check" : "copy"} />
      </button>
    </span>
  );
}
