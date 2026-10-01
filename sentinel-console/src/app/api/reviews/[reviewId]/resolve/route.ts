import { z } from "zod";

import { createAssertion } from "@/lib/server/assertion";
import { callBackend, errorResponse, relay, unavailable } from "@/lib/server/backend";
import { serverConfig } from "@/lib/server/config";
import { readJson, sameOrigin } from "@/lib/server/request";

export const dynamic = "force-dynamic";

const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const Body = z
  .object({
    resolution: z.enum(["legitimate", "fraud", "needs_more_information"]),
    note: z.string().trim().max(500).optional(),
    assertion: z
      .string()
      .max(4096)
      .regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
      .optional(),
  })
  .strict();

/**
 * Resolve a review. The backend decides everything (roles, bindings, immutability); the
 * console only supplies the reviewer's signed assertion:
 * - DEMO MODE with a demo operator key: signed here, bound to this review and resolution;
 * - otherwise: the analyst's own assertion from `fraud-ai operators assert`, passed through.
 */
export async function POST(request: Request, { params }: { params: Promise<{ reviewId: string }> }): Promise<Response> {
  if (!sameOrigin(request)) return errorResponse(403, "CROSS_ORIGIN", "cross-origin request refused");
  const { reviewId } = await params;
  if (!UUID.test(reviewId)) return errorResponse(404, "NOT_FOUND", "unknown review item");
  let parsed: z.infer<typeof Body>;
  try {
    parsed = Body.parse(await readJson(request));
  } catch {
    return errorResponse(422, "VALIDATION_ERROR", "resolution must be legitimate, fraud or needs_more_information");
  }
  const cfg = serverConfig();
  let assertion = parsed.assertion ?? null;
  if (!assertion && cfg.operatorKeyFile && cfg.operatorId) {
    try {
      assertion = createAssertion({
        keyFile: cfg.operatorKeyFile,
        operatorId: cfg.operatorId,
        action: "review.resolve",
        target: reviewId,
        binding: { resolution: parsed.resolution },
        audience: cfg.operatorAudience,
      });
    } catch {
      return errorResponse(500, "OPERATOR_KEY_UNAVAILABLE", "the demo operator key could not be used");
    }
  }
  const headers: Record<string, string> = {};
  if (assertion) headers["X-Fraud-Operator-Assertion"] = assertion;
  const body: Record<string, string> = { resolution: parsed.resolution };
  if (parsed.note) body.note = parsed.note;
  try {
    const res = await callBackend({ method: "POST", path: `/v1/reviews/${reviewId}/resolve`, body, headers });
    return relay(res);
  } catch (err) {
    return unavailable(err);
  }
}
