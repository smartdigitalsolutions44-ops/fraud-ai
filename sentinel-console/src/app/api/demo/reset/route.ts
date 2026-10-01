import { demoControl } from "@/lib/server/demoControl";
import { errorResponse } from "@/lib/server/backend";
import { readJson, sameOrigin } from "@/lib/server/request";

export const dynamic = "force-dynamic";

/** DEMO MODE only (enforced in demoControl): asks the local supervisor to run the existing
 * guarded `fraud-ai demo reset`. The body must carry the typed confirmation phrase. */
export async function POST(request: Request): Promise<Response> {
  if (!sameOrigin(request)) return errorResponse(403, "CROSS_ORIGIN", "cross-origin request refused");
  let body: unknown;
  try {
    body = await readJson(request);
  } catch {
    body = null;
  }
  if ((body as { confirm?: unknown } | null)?.confirm !== "RESET DEMO") {
    return errorResponse(422, "CONFIRMATION_REQUIRED", "type RESET DEMO to confirm");
  }
  return demoControl("POST", "/reset");
}
