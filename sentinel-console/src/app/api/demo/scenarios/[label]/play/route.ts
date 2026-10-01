import { callBackend, errorResponse, unavailable } from "@/lib/server/backend";
import { readCatalogue } from "@/lib/server/demo";
import { sameOrigin } from "@/lib/server/request";

export const dynamic = "force-dynamic";

/**
 * DEMO MODE only: score one catalogue case through the real service (its earlier events for
 * the same customer first, then the case event). Replaying is idempotent: the service
 * returns the stored assessment for an event it has already decided.
 */
export async function POST(request: Request, { params }: { params: Promise<{ label: string }> }): Promise<Response> {
  if (!sameOrigin(request)) return errorResponse(403, "CROSS_ORIGIN", "cross-origin request refused");
  const { label } = await params;
  let catalogue;
  try {
    catalogue = readCatalogue();
  } catch {
    return errorResponse(403, "DEMO_MODE_REQUIRED", "the demo is available in DEMO MODE only");
  }
  const scenario = catalogue.cases.find((c) => c.label === label);
  if (!scenario) return errorResponse(404, "NOT_FOUND", "unknown demo scenario");
  try {
    for (const event of scenario.prelude) {
      const r = await callBackend({ method: "POST", path: "/v1/score", body: event, timeoutMs: 60_000 });
      if (r.status >= 500) return errorResponse(r.status, "SCORING_UNAVAILABLE", "scoring the scenario failed");
    }
    const res = await callBackend({ method: "POST", path: "/v1/score", body: scenario.event, timeoutMs: 60_000 });
    const body = JSON.parse(res.body) as Record<string, unknown>;
    if (res.status >= 400) {
      const e = (body.error ?? {}) as { code?: string; message?: string };
      return errorResponse(res.status, e.code ?? "SCORING_FAILED", e.message ?? "scoring failed");
    }
    return Response.json({
      label,
      assessment_id: body.assessment_id,
      decision: body.decision,
      status: body.status,
      expected_decision: scenario.expected_decision,
    });
  } catch (err) {
    return unavailable(err);
  }
}
