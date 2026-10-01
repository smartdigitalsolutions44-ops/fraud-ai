import "server-only";

import { serverConfig } from "./config";
import { TimestampAllocator, signV2 } from "./signing";

const timestamps = new TimestampAllocator();

export interface BackendResponse {
  status: number;
  contentType: string;
  body: string;
}

export class BackendUnavailable extends Error {
  constructor(
    readonly code: "BACKEND_NOT_CONFIGURED" | "BACKEND_UNREACHABLE" | "BACKEND_TIMEOUT",
    message: string,
  ) {
    super(message);
  }
}

export interface BackendRequest {
  method: "GET" | "POST";
  path: string; // e.g. /v1/analyst/feed
  query?: URLSearchParams;
  body?: unknown;
  headers?: Record<string, string>;
  timeoutMs?: number;
  signed?: boolean; // health/ready are unauthenticated
}

/** One signed call to the fraud-ai service. The credential and secret stay in this process. */
export async function callBackend(req: BackendRequest): Promise<BackendResponse> {
  const cfg = serverConfig();
  const query = req.query?.toString() ?? "";
  const raw = req.body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(req.body));
  const headers: Record<string, string> = { Accept: "application/json", ...(req.headers ?? {}) };
  if (req.body !== undefined) headers["Content-Type"] = "application/json";
  if (req.signed !== false) {
    if (!cfg.credential || !cfg.signingSecret) {
      throw new BackendUnavailable("BACKEND_NOT_CONFIGURED", "the console has no API credential configured");
    }
    const ts = timestamps.next(`${req.method} ${req.path}?${query} ${raw.toString("base64")}`);
    headers.Authorization = `Bearer ${cfg.credential}`;
    headers["X-Fraud-Timestamp"] = String(ts);
    headers["X-Fraud-Signature"] = signV2(cfg.signingSecret, req.method, req.path, ts, raw, query);
  }
  const url = `${cfg.baseUrl}${req.path}${query ? `?${query}` : ""}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), req.timeoutMs ?? cfg.timeoutMs);
  try {
    const res = await fetch(url, {
      method: req.method,
      headers,
      body: raw.length ? raw : undefined,
      signal: controller.signal,
      cache: "no-store",
    });
    return {
      status: res.status,
      contentType: res.headers.get("content-type") ?? "application/json",
      body: await res.text(),
    };
  } catch (err) {
    if (controller.signal.aborted) {
      throw new BackendUnavailable("BACKEND_TIMEOUT", "the fraud service did not answer in time");
    }
    void err;
    throw new BackendUnavailable("BACKEND_UNREACHABLE", "the fraud service is unreachable");
  } finally {
    clearTimeout(timer);
  }
}

/** A uniform JSON error body for the browser: { error: { code, message, status } }. */
export function errorResponse(status: number, code: string, message: string): Response {
  return Response.json({ error: { code, message, status } }, { status, headers: { "Cache-Control": "no-store" } });
}

export function relay(res: BackendResponse, options: { keepErrorBody?: boolean } = {}): Response {
  if (res.contentType.includes("application/json")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(res.body);
    } catch {
      return errorResponse(502, "BAD_BACKEND_RESPONSE", "the fraud service returned malformed JSON");
    }
    if (res.status >= 400 && !options.keepErrorBody) {
      const e = (parsed as { error?: { code?: string; message?: string } })?.error;
      return errorResponse(res.status, e?.code ?? "BACKEND_ERROR", e?.message ?? "request failed");
    }
    return Response.json(parsed, { status: res.status, headers: { "Cache-Control": "no-store" } });
  }
  return new Response(res.body, {
    status: res.status,
    headers: { "Content-Type": res.contentType, "Cache-Control": "no-store" },
  });
}

export function unavailable(err: unknown): Response {
  if (err instanceof BackendUnavailable) {
    return errorResponse(err.code === "BACKEND_NOT_CONFIGURED" ? 500 : 503, err.code, err.message);
  }
  return errorResponse(500, "CONSOLE_ERROR", "unexpected console error");
}
