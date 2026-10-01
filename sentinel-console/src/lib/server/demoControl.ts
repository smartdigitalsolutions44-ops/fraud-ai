import "server-only";

import { serverConfig } from "./config";

/** The local demo supervisor started by `npm run demo` (scripts/demo.mjs). It runs the
 * existing guarded `fraud-ai demo reset`; the console never touches a database itself. */
export async function demoControl(method: "GET" | "POST", path: "/status" | "/reset"): Promise<Response> {
  const cfg = serverConfig();
  if (!cfg.demoMode) {
    return Response.json({ error: { code: "DEMO_MODE_REQUIRED", message: "DEMO MODE only", status: 403 } }, { status: 403 });
  }
  if (!cfg.demoControlUrl || !cfg.demoControlToken) {
    return Response.json(
      { error: { code: "DEMO_CONTROL_UNAVAILABLE", message: "start the console with `npm run demo` to enable reset", status: 503 } },
      { status: 503 },
    );
  }
  try {
    const res = await fetch(`${cfg.demoControlUrl}${path}`, {
      method,
      headers: { Authorization: `Bearer ${cfg.demoControlToken}` },
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    return new Response(await res.text(), { status: res.status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: { code: "DEMO_CONTROL_UNAVAILABLE", message: "the demo supervisor is not answering", status: 503 } }, { status: 503 });
  }
}
