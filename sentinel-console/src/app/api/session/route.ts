import { serverConfig } from "@/lib/server/config";

import pkg from "../../../../package.json";

export const dynamic = "force-dynamic";

/** What the browser may know about this console session: never credentials or keys. */
export function GET(): Response {
  const cfg = serverConfig();
  return Response.json(
    {
      console_version: pkg.version,
      environment: cfg.environment,
      demo_mode: cfg.demoMode,
      backend_configured: Boolean(cfg.credential && cfg.signingSecret),
      demo_reset_available: Boolean(cfg.demoMode && cfg.demoControlUrl),
      operator: cfg.operatorKeyFile
        ? {
            mode: "demo_key",
            operator_id: cfg.operatorId,
            note: "DEMO MODE: the console signs reviewer assertions with the demo operator key.",
          }
        : {
            mode: "assertion",
            operator_id: null,
            note: "Each resolution needs the analyst's own signed operator assertion.",
          },
      audience: cfg.operatorAudience,
      problems: cfg.problems,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
