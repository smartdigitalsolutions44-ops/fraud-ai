/** Formatting helpers. Times are shown in UTC with an explicit marker, never local-guessed. */

export function shortId(id: string | null | undefined, n = 8): string {
  if (!id) return "—";
  return id.replace(/-/g, "").slice(0, n);
}

const pad = (v: number) => String(v).padStart(2, "0");

export function utcTime(iso: string | null | undefined, withSeconds = true): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const t = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}${withSeconds ? `:${pad(d.getUTCSeconds())}` : ""}`;
  return t;
}

export function utcDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

export function utcDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return `${utcDate(iso)} ${utcTime(iso)} UTC`;
}

export function age(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d`;
}

export function ageSeconds(iso: string | null | undefined, now: number = Date.now()): number {
  if (!iso) return 0;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? 0 : Math.max(0, (now - t) / 1000);
}

export function count(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  return new Intl.NumberFormat("en-GB").format(n);
}

export function ms(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n < 10) return n.toFixed(1);
  return String(Math.round(n));
}

export function pct(part: number, whole: number): string {
  if (!whole) return "—";
  const v = (part / whole) * 100;
  return `${v < 10 && v > 0 ? v.toFixed(1) : Math.round(v)}%`;
}

/** Model scores are shown to 3 decimals and always named as model scores. */
export function score(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  return n.toFixed(3);
}

export function humanise(code: string): string {
  return code.replace(/_/g, " ").toLowerCase();
}

export function money(minor: number, currency: string): string {
  try {
    return new Intl.NumberFormat("en-GB", { style: "currency", currency }).format(minor / 100);
  } catch {
    return `${(minor / 100).toFixed(2)} ${currency}`;
  }
}
