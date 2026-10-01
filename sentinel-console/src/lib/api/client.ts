import type { z } from "zod";

/**
 * The single place the browser talks to the console's own server routes (/api/*). Components
 * never call fetch() directly (enforced by eslint). Every response is parsed against a schema;
 * a shape the console does not understand is an error, never rendered on a guess.
 *
 * The browser holds no fraud-ai credential: /api/fraud/* is a server-side, allow-listed proxy
 * that signs each request (see src/lib/server).
 */

export type ApiErrorKind =
  | "unavailable" // the fraud service or the console server cannot be reached
  | "timeout"
  | "unauthorised"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "invalid"
  | "llm_unavailable"
  | "server"
  | "schema";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly kind: ApiErrorKind,
    readonly retryAfterSeconds: number | null = null,
  ) {
    super(message);
    this.name = "ApiError";
  }

  /** Worth retrying automatically: transient, and the request is safe to repeat. */
  get transient(): boolean {
    return this.kind === "unavailable" || this.kind === "timeout" || (this.kind === "server" && this.status >= 502);
  }
}

export function kindFor(status: number, code: string): ApiErrorKind {
  if (code === "LLM_UNAVAILABLE" || code === "LLM_TIMEOUT" || code === "INVESTIGATION_FAILED") return "llm_unavailable";
  if (code === "SCHEMA_MISMATCH") return "schema";
  if (code === "BACKEND_TIMEOUT" || code === "CLIENT_TIMEOUT" || status === 504) return "timeout";
  if (code === "BACKEND_UNREACHABLE" || code === "NETWORK_ERROR" || status === 503) return "unavailable";
  if (status === 401) return "unauthorised";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 429) return "rate_limited";
  if (status === 400 || status === 413 || status === 422) return "invalid";
  return "server";
}

export interface RequestOptions {
  method?: "GET" | "POST";
  query?: Record<string, string | number | undefined | null>;
  body?: unknown;
  timeoutMs?: number;
  /** GETs retry transient failures by default; POSTs never do (they are not idempotent). */
  retries?: number;
  signal?: AbortSignal;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const RETRY_DELAYS_MS = [400, 1200];

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null && v !== "") params.set(k, String(v));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

async function once(url: string, opts: RequestOptions): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("timeout"), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const onAbort = () => controller.abort("cancelled");
  opts.signal?.addEventListener("abort", onAbort);
  let res: Response;
  try {
    res = await fetch(url, {
      method: opts.method ?? "GET",
      headers: opts.body === undefined ? { Accept: "application/json" } : { Accept: "application/json", "Content-Type": "application/json" },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
    });
  } catch {
    if (controller.signal.aborted && controller.signal.reason === "timeout") {
      throw new ApiError(0, "CLIENT_TIMEOUT", "the console did not answer in time", "timeout");
    }
    if (opts.signal?.aborted) throw new ApiError(0, "CANCELLED", "request cancelled", "unavailable");
    throw new ApiError(0, "NETWORK_ERROR", "the console server is unreachable", "unavailable");
  } finally {
    clearTimeout(timeout);
    opts.signal?.removeEventListener("abort", onAbort);
  }
  let payload: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      throw new ApiError(res.status || 502, "BAD_RESPONSE", "the response was not JSON", "server");
    }
  }
  if (!res.ok) {
    const e = (payload as { error?: { code?: unknown; message?: unknown } } | null)?.error;
    const code = typeof e?.code === "string" ? e.code : `HTTP_${res.status}`;
    const message = typeof e?.message === "string" ? e.message : `request failed (${res.status})`;
    const retryAfter = Number(res.headers.get("retry-after"));
    throw new ApiError(res.status, code, message, kindFor(res.status, code), Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null);
  }
  return payload;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** One request to a console route, parsed against `schema`. */
export async function request<S extends z.ZodType>(path: string, schema: S, opts: RequestOptions = {}): Promise<z.infer<S>> {
  const url = buildUrl(path, opts.query);
  const method = opts.method ?? "GET";
  const retries = opts.retries ?? (method === "GET" ? RETRY_DELAYS_MS.length : 0);
  let attempt = 0;
  for (;;) {
    try {
      const payload = await once(url, opts);
      const parsed = schema.safeParse(payload);
      if (!parsed.success) {
        const where = parsed.error.issues[0]?.path.join(".") || "(root)";
        throw new ApiError(200, "SCHEMA_MISMATCH", `unexpected response shape at ${where}`, "schema");
      }
      return parsed.data;
    } catch (err) {
      if (err instanceof ApiError && err.transient && attempt < retries && !opts.signal?.aborted) {
        await sleep(RETRY_DELAYS_MS[attempt] ?? 1500);
        attempt += 1;
        continue;
      }
      throw err;
    }
  }
}

export const apiGet = <S extends z.ZodType>(path: string, schema: S, opts: Omit<RequestOptions, "method" | "body"> = {}) =>
  request(path, schema, { ...opts, method: "GET" });

export const apiPost = <S extends z.ZodType>(path: string, schema: S, body: unknown, opts: Omit<RequestOptions, "method" | "body"> = {}) =>
  request(path, schema, { ...opts, method: "POST", body });

/** A readable one-line description for error panels. */
export function describeError(err: unknown): { title: string; detail: string; kind: ApiErrorKind } {
  if (!(err instanceof ApiError)) return { title: "Unexpected error", detail: "the console hit an unexpected error", kind: "server" };
  const titles: Record<ApiErrorKind, string> = {
    unavailable: "Service unavailable",
    timeout: "Request timed out",
    unauthorised: "Not authenticated",
    forbidden: "Permission denied",
    not_found: "Not found",
    conflict: "Conflict",
    rate_limited: "Rate limited",
    invalid: "Request rejected",
    llm_unavailable: "Local analyst model unavailable",
    server: "Service error",
    schema: "Unexpected response",
  };
  let detail = `${err.message} (${err.code})`;
  if (err.kind === "rate_limited" && err.retryAfterSeconds) detail += ` — retry in ${err.retryAfterSeconds}s`;
  return { title: titles[err.kind], detail, kind: err.kind };
}
