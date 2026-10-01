import { describe, expect, it } from "vitest";

import { matchRoute } from "@/lib/server/allowlist";

const q = (s = "") => new URLSearchParams(s);
const UUID = "49044c7e-adcc-448b-8633-c0c91edb1c4c";

describe("console proxy allow-list", () => {
  it.each([
    ["GET", "health", ""],
    ["GET", "ready", ""],
    ["GET", "analyst/feed", "limit=100&decision=MANUAL_REVIEW"],
    ["GET", "analyst/reviews", "status=open&limit=500"],
    ["GET", `analyst/cases/${UUID}`, ""],
    ["GET", "analyst/summary", "hours=24"],
    ["GET", "analyst/system", ""],
    ["GET", "analyst/search", "q=49044c7e"],
    ["POST", `assessments/${UUID}/investigate`, ""],
  ])("allows %s %s", (method, path, search) => {
    expect("rule" in matchRoute(method, path, q(search))).toBe(true);
  });

  it.each([
    ["POST", "score"], // scoring is never reachable from the browser
    ["POST", `reviews/${UUID}/resolve`], // only through the dedicated, same-origin resolve route
    ["POST", "stepup/callback"],
    ["GET", "keys"],
    ["POST", "policy/activate"],
    ["GET", "analyst/cases/not-a-uuid"],
    ["GET", "../v1/keys"],
    ["DELETE", "analyst/feed"],
  ])("refuses %s %s", (method, path) => {
    expect("error" in matchRoute(method, path, q())).toBe(true);
  });

  it("refuses unknown or malformed query parameters", () => {
    expect("error" in matchRoute("GET", "analyst/feed", q("limit=100&user_id=1"))).toBe(true);
    expect("error" in matchRoute("GET", "analyst/feed", q("decision=allow;drop"))).toBe(true);
    expect("error" in matchRoute("GET", "analyst/search", q("q=alice@example.com"))).toBe(true); // no PII search
    expect("error" in matchRoute("GET", "analyst/reviews", q("status=deleted"))).toBe(true);
  });

  it("marks health and readiness as unsigned, everything else as signed", () => {
    const m = matchRoute("GET", "ready", q());
    expect("rule" in m && m.rule.signed).toBe(false);
    const f = matchRoute("GET", "analyst/feed", q());
    expect("rule" in f && f.rule.signed).toBe(true);
  });
});
