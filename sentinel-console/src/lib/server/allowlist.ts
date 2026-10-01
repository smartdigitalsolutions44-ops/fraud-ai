import "server-only";

/**
 * The only fraud-ai routes the browser may reach through /api/fraud/*. Anything else (for
 * example POST /v1/score, step-up writes, key management) is refused before it leaves the
 * console. Query parameters are allow-listed per route and validated.
 */
const UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

export interface RouteRule {
  method: "GET" | "POST";
  pattern: RegExp;
  params: Record<string, RegExp>;
  signed: boolean;
  timeoutMs?: number;
}

const INT = /^\d{1,4}$/;
export const ROUTES: RouteRule[] = [
  { method: "GET", pattern: /^health$/, params: {}, signed: false },
  { method: "GET", pattern: /^ready$/, params: {}, signed: false },
  { method: "GET", pattern: /^policy$/, params: {}, signed: true },
  { method: "GET", pattern: /^metrics$/, params: {}, signed: true },
  { method: "GET", pattern: new RegExp(`^assessments/${UUID}$`), params: {}, signed: true },
  { method: "GET", pattern: new RegExp(`^reviews/${UUID}$`), params: {}, signed: true },
  {
    method: "GET",
    pattern: /^analyst\/feed$/,
    params: { limit: INT, since: /^[0-9T:.+\-Z]{10,40}$/, decision: /^[A-Z_]{3,40}$/ },
    signed: true,
  },
  {
    method: "GET",
    pattern: /^analyst\/reviews$/,
    params: { status: /^(open|resolved|needs_more_information|all)$/, limit: INT },
    signed: true,
  },
  { method: "GET", pattern: new RegExp(`^analyst/cases/${UUID}$`), params: {}, signed: true },
  { method: "GET", pattern: /^analyst\/summary$/, params: { hours: INT }, signed: true },
  { method: "GET", pattern: /^analyst\/system$/, params: {}, signed: true },
  { method: "GET", pattern: /^analyst\/search$/, params: { q: /^[0-9a-fA-F-]{8,36}$/ }, signed: true },
  {
    method: "POST",
    pattern: new RegExp(`^assessments/${UUID}/investigate$`),
    params: {},
    signed: true,
    timeoutMs: 180_000,
  },
];

export type Match = { rule: RouteRule; query: URLSearchParams } | { error: string };

export function matchRoute(method: string, path: string, search: URLSearchParams): Match {
  const rule = ROUTES.find((r) => r.method === method && r.pattern.test(path));
  if (!rule) return { error: "route not available to the analyst console" };
  const query = new URLSearchParams();
  for (const [name, value] of search) {
    const check = rule.params[name];
    if (!check) return { error: `query parameter '${name}' is not allowed` };
    if (!check.test(value)) return { error: `query parameter '${name}' is invalid` };
    query.append(name, value);
  }
  return { rule, query };
}
