import { DEMO_SCENARIOS } from "@/features/demo/scenarios";
import { callBackend, errorResponse } from "@/lib/server/backend";
import { readCatalogue } from "@/lib/server/demo";

export const dynamic = "force-dynamic";

/** DEMO MODE only: the deterministic cases, their measured decision, and whether each has
 * already been scored in this demo world (looked up by its event id, read-only). */
export async function GET(): Promise<Response> {
  let catalogue;
  try {
    catalogue = readCatalogue();
  } catch (err) {
    const message = err instanceof Error ? err.message : "unavailable";
    return message === "DEMO_MODE_REQUIRED"
      ? errorResponse(403, "DEMO_MODE_REQUIRED", "the demo is available in DEMO MODE only")
      : errorResponse(503, "DEMO_UNAVAILABLE", "the demo catalogue is not available");
  }
  const scenarios = await Promise.all(
    catalogue.cases.map(async (c) => {
      let assessmentId: string | null = null;
      const eventId = typeof c.event.event_id === "string" ? c.event.event_id : null;
      if (eventId) {
        try {
          const res = await callBackend({
            method: "GET",
            path: "/v1/analyst/search",
            query: new URLSearchParams({ q: eventId }),
          });
          if (res.status === 200) {
            const found = JSON.parse(res.body) as { matches: Array<{ kind: string; assessment_id: string }> };
            assessmentId = found.matches.find((m) => m.kind === "event")?.assessment_id ?? null;
          }
        } catch {
          assessmentId = null;
        }
      }
      return {
        label: c.label,
        title: DEMO_SCENARIOS[c.label]?.title ?? c.title,
        purpose: DEMO_SCENARIOS[c.label]?.purpose ?? null,
        story: c.story,
        scenario: c.scenario,
        expected_decision: c.expected_decision,
        expected_reasons: c.expected_reasons,
        relaxed_match: c.relaxed_match,
        prelude_events: c.prelude.length,
        event_type: (c.event.event_type as string | undefined) ?? null,
        assessment_id: assessmentId,
      };
    }),
  );
  return Response.json(
    { synthetic: true, seed: catalogue.seed, users: catalogue.users, missing: catalogue.missing_cases, note: catalogue.note, scenarios },
    { headers: { "Cache-Control": "no-store" } },
  );
}
