import "server-only";

/**
 * State-changing console routes accept only same-origin browser requests (a cross-site page
 * cannot make the console's server act on its behalf). JSON bodies also force a CORS
 * preflight, which this server never answers.
 */
export function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return request.headers.get("sec-fetch-site") === "same-origin";
  try {
    const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

export async function readJson(request: Request, limit = 16_384): Promise<unknown> {
  const text = await request.text();
  if (text.length > limit) throw new Error("request body too large");
  return text ? JSON.parse(text) : {};
}
