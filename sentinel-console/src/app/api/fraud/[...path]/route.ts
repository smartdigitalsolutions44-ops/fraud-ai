import { matchRoute } from "@/lib/server/allowlist";
import { callBackend, errorResponse, relay, unavailable } from "@/lib/server/backend";
import { sameOrigin } from "@/lib/server/request";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ path: string[] }> };

async function handle(method: "GET" | "POST", request: Request, { params }: Params): Promise<Response> {
  const { path } = await params;
  const joined = path.join("/");
  const match = matchRoute(method, joined, new URL(request.url).searchParams);
  if ("error" in match) return errorResponse(403, "ROUTE_NOT_ALLOWED", match.error);
  let body: unknown;
  if (method === "POST") {
    if (!sameOrigin(request)) return errorResponse(403, "CROSS_ORIGIN", "cross-origin request refused");
    const text = await request.text();
    if (text.length > 16_384) return errorResponse(413, "REQUEST_TOO_LARGE", "request body too large");
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      return errorResponse(400, "INVALID_JSON", "request body is not valid JSON");
    }
  }
  try {
    const res = await callBackend({
      method,
      path: `/v1/${joined}`,
      query: match.query,
      body,
      signed: match.rule.signed,
      timeoutMs: match.rule.timeoutMs,
    });
    // /v1/ready answers 503 *with* its checks when not ready: keep that body.
    return relay(res, { keepErrorBody: joined === "ready" && res.status === 503 });
  } catch (err) {
    return unavailable(err);
  }
}

export function GET(request: Request, ctx: Params): Promise<Response> {
  return handle("GET", request, ctx);
}

export function POST(request: Request, ctx: Params): Promise<Response> {
  return handle("POST", request, ctx);
}
