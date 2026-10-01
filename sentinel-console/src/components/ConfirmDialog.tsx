"use client";

import { useEffect, useRef, type ReactNode } from "react";

/**
 * A modal confirmation for consequential actions. Esc or Cancel backs out; the confirm button
 * is never the default focus, so a stray Enter cannot confirm.
 */
export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  tone = "primary",
  busy,
  disabled,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  tone?: "primary" | "red" | "green" | "amber";
  busy?: boolean;
  disabled?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const cancel = useRef<HTMLButtonElement>(null);
  const dialog = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    cancel.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) {
        e.preventDefault();
        onCancel();
      }
      if (e.key === "Tab" && dialog.current) {
        const nodes = [...dialog.current.querySelectorAll<HTMLElement>("button:not(:disabled), textarea, input, select")];
        if (!nodes.length) return;
        const first = nodes[0]!;
        const last = nodes[nodes.length - 1]!;
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      previous?.focus?.();
    };
  }, [open, busy, onCancel]);
  if (!open) return null;
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && !busy && onCancel()}>
      <div className="dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" ref={dialog}>
        <div className="dialog-head">
          <h2 id="confirm-title">{title}</h2>
        </div>
        <div className="dialog-body">{children}</div>
        <div className="dialog-foot">
          <button ref={cancel} type="button" className="btn btn-ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button type="button" className={`btn btn-${tone}`} onClick={onConfirm} disabled={busy || disabled} data-testid="confirm-action">
            {busy ? "Submitting…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
