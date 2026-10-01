import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EvidencePanel } from "@/components/EvidencePanel";
import { ModelComparison, splitModel } from "@/components/ModelComparison";
import { Actions } from "@/features/case/Actions";
import { caseSummary } from "@/features/case/CaseHeader";
import { Investigation } from "@/features/case/Investigation";
import { deriveGroups, overallOf } from "@/features/system/groups";
import { ApiError } from "@/lib/api/client";
import { backoff } from "@/lib/api/queries";
import * as S from "@/lib/api/schemas";
import { offset } from "@/lib/format";
import { reasonCategory, reasonTitle } from "@/lib/reasons";

import { fixture, mockFetch, renderWithClient } from "./utils";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }), usePathname: () => "/", useSearchParams: () => new URLSearchParams() }));
afterEach(() => vi.unstubAllGlobals());

const ready = S.Ready.parse(fixture("ready"));
const system = S.System.parse(fixture("system"));
const session = S.Session.parse(fixture("session"));
const theCase = S.Case.parse(fixture("case"));
const byId = (gs: ReturnType<typeof deriveGroups>, id: string) => gs.find((g) => g.id === id)!;

describe("health groups (start-up sequence and System page)", () => {
  it("are all CHECKING before any answer, never assumed fine", () => {
    const gs = deriveGroups({});
    expect(gs.map((g) => g.state)).toEqual(Array(7).fill("checking"));
    expect(overallOf(gs)).toBe("checking");
  });

  it("describe the demo service from what it reported", () => {
    const gs = deriveGroups({ ready, system, session });
    expect(byId(gs, "service").state).toBe("online");
    expect(byId(gs, "data").state).toBe("online");
    expect(byId(gs, "data").cause).toContain("Redis not used");
    expect(byId(gs, "models").cause).toContain("signed and verified");
    expect(byId(gs, "policy").cause).toContain("risk-policy-1.0.0");
    expect(byId(gs, "trust").state).toBe("online");
    expect(byId(gs, "audit").state).toBe("degraded"); // no external anchor in this world
    expect(byId(gs, "analyst").cause).toContain("reference template");
    expect(overallOf(gs)).toBe("degraded");
  });

  it("name the failing component and stay honest about the rest", () => {
    const down = new ApiError(0, "NETWORK_ERROR", "down", "unavailable");
    const gs = deriveGroups({ readyError: down, systemError: down, session });
    expect(gs.every((g) => g.state === "offline")).toBe(true);
    expect(overallOf(gs)).toBe("offline");
    const denied = new ApiError(403, "INSUFFICIENT_SCOPE", "no", "forbidden");
    expect(byId(deriveGroups({ ready, systemError: denied, session }), "models").cause).toContain("analyst:read");
  });

  it("never keep an unreachable service looking healthy from an older answer", () => {
    // the latest readiness poll failed while the system view is still the last good one
    const down = new ApiError(0, "BACKEND_UNREACHABLE", "down", "unavailable");
    const gs = deriveGroups({ readyError: down, system, session });
    expect(gs.every((g) => g.state === "offline")).toBe(true);
    expect(byId(gs, "trust").cause).toContain("unreachable");
    expect(overallOf(gs)).toBe("offline");
  });

  it("mark Redis failures and relaxed trust settings as DEGRADED, with the cause", () => {
    const redisDown = { ...ready, status: "not_ready" as const, checks: { ...ready.checks, shared_state: "failed" } };
    expect(byId(deriveGroups({ ready: redisDown, system, session }), "data")).toMatchObject({ state: "degraded" });
    expect(byId(deriveGroups({ ready: redisDown, system, session }), "service").cause).toContain("shared_state failed");
    const relaxed = { ...system, environment: "development", security: { ...system.security, operator_auth_required: false } };
    const trust = byId(deriveGroups({ ready, system: relaxed, session }), "trust");
    expect(trust.state).toBe("degraded");
    expect(trust.cause).toContain("operator authentication off");
  });

  it("refuse to call a model group online when a signature does not match", () => {
    const bad = { ...system, models: system.models.map((m) => (m.role === "shadow" ? { ...m, signature: { ...m.signature!, matches_artifact: false } } : m)) };
    expect(byId(deriveGroups({ ready, system: bad, session }), "models").state).toBe("offline");
  });
});

describe("reasons are readable, with severity only as stored", () => {
  it("titles and categories", () => {
    expect(reasonTitle("SCORE_BAND_HIGH")).toBe("Score in the high band");
    expect(reasonTitle("FAILED_LOGIN_BURST")).toBe("Burst of failed logins");
    expect(reasonTitle("SOMETHING_NEW")).toBe("Something new"); // unknown: from its own name only
    expect(reasonCategory("SCORE_BAND_LOW", false)).toBe("score");
    expect(reasonCategory("FAILED_LOGIN_BURST", true)).toBe("rule");
    expect(reasonCategory("STEP_UP_FAILED", false)).toBe("step_up");
  });

  it("shows the title first, the band as severity, the rule's own severity and evidence", () => {
    const rule = { rule_id: "R002", reason_code: "FAILED_LOGIN_BURST", description: "burst", severity: "medium", matched: true, evaluated: true, evidence: { failed_logins_15m: 9 }, missing: [] };
    render(<EvidencePanel reasons={[{ code: "SCORE_BAND_HIGH", description: "From the service." }, { code: "FAILED_LOGIN_BURST", description: "Burst." }, { code: "LATE_EVENT", description: null }]} rules={[rule]} />);
    expect(screen.getByText("Score in the high band")).toBeInTheDocument();
    expect(screen.getAllByText("SCORE_BAND_HIGH")[0]).toHaveClass("reason-code"); // the raw code is secondary
    expect(screen.getByText("Medium severity")).toBeInTheDocument();
    expect(screen.getAllByText("failed_logins_15m").length).toBeGreaterThan(0);
    expect(screen.getByText("Not graded")).toBeInTheDocument(); // LATE_EVENT: the policy grades nothing here
  });
});

describe("model panel", () => {
  it("separates the deciding model from shadow models, with versions, and is not a vote", () => {
    const { container } = render(<ModelComparison models={theCase.models} />);
    expect(screen.getByLabelText("Primary model")).toBeInTheDocument();
    expect(screen.getByLabelText("Shadow models")).toBeInTheDocument();
    expect(screen.getByText("Recorded for comparison · never decides")).toBeInTheDocument();
    expect(container.textContent?.toLowerCase()).not.toMatch(/consensus|average|majority|vote|combined score/);
    expect(splitModel("gradient-boosting-1.0.0")).toEqual(["gradient-boosting", "1.0.0"]);
    expect(splitModel("custom")).toEqual(["custom", null]);
  });
});

describe("case header and timeline", () => {
  it("summarises the case from stored facts", () => {
    const parts = caseSummary(theCase);
    expect(parts[0]).toBe("Sent to manual review");
    expect(parts.join(" ")).toMatch(/score in the high band \(calibrated 0\.\d+\)/);
    expect(parts.join(" ")).toContain(theCase.models.disagreement ? "models disagree" : "models agree");
  });

  it("formats offsets from the case event", () => {
    const ref = "2026-06-29T19:04:00Z";
    expect(offset("2026-06-23T17:04:00Z", ref)).toBe("−6d 2h");
    expect(offset("2026-06-29T18:51:00Z", ref)).toBe("−13m");
    expect(offset("2026-06-29T19:04:40Z", ref)).toBe("+40s");
    expect(offset(ref, ref)).toBe("same time");
  });
});

describe("polling backoff", () => {
  it("keeps the interval while healthy and backs off, capped and jittered, while failing", () => {
    expect(backoff(5_000, 0)).toBe(5_000);
    expect(backoff(5_000, 1, () => 0)).toBe(10_000);
    expect(backoff(5_000, 3, () => 0)).toBe(30_000); // capped
    expect(backoff(5_000, 9, () => 0)).toBe(30_000);
    expect(backoff(5_000, 2, () => 1)).toBe(24_000); // +20 % jitter at most
  });
});

describe("keyboard: R opens the resolve panel and never submits", () => {
  it("focuses the first outcome; nothing is sent, no dialog opens", async () => {
    const fetch = mockFetch({ "/api/session": session });
    renderWithClient(<Actions data={{ ...theCase, review: { ...theCase.review!, status: "open", outcomes: [] } }} />);
    await screen.findByText(/DEMO MODE: resolutions are signed/);
    fireEvent.keyDown(window, { key: "r" });
    fireEvent.keyDown(window, { key: "R" });
    await waitFor(() => expect(screen.getByTestId("resolve-legitimate")).toHaveFocus());
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(fetch.mock.calls.every(([u]) => !String(u).includes("/resolve"))).toBe(true);
  });

  it("the confirmation says what will happen before anything is sent", async () => {
    mockFetch({ "/api/session": session });
    renderWithClient(<Actions data={{ ...theCase, review: { ...theCase.review!, status: "open", outcomes: [] } }} />);
    await screen.findByText(/DEMO MODE: resolutions are signed/);
    fireEvent.click(screen.getByTestId("resolve-fraud"));
    expect(screen.getByText("What will happen")).toBeInTheDocument();
    expect(screen.getByText(/original assessment and its decision are not changed/)).toBeInTheDocument();
    expect(screen.getByText("operator:rita")).toBeInTheDocument();
  });
});

describe("analyst assistance", () => {
  it("separates observed evidence, interpretation and limitations, and never decides", () => {
    const inv = {
      investigation_id: "11111111-1111-4111-8111-111111111111",
      explanation_version: 1,
      created_at: "2026-09-30T22:00:00Z",
      runtime: "reference",
      model: "reference-template",
      explanation: {
        summary: { statement: "The score is in the high band.", evidence_ids: ["E1"] },
        risk_factors: [],
        protective_factors: [],
        model_disagreement: [],
        temporal_findings: [],
        uncertainties: [{ statement: "No step-up result yet.", evidence_ids: [] }],
        recommended_review_questions: [],
      },
      evidence: [{ id: "E1", name: "calibrated score", value: 0.43, source: "assessment" }],
      limitations: [{ id: "L1", text: "Synthetic data." }],
      note: "",
    };
    mockFetch({ "/api/fraud/analyst/system": system });
    renderWithClient(<Investigation assessmentId={theCase.assessment.assessment_id} investigation={inv} />);
    expect(screen.getByText("Observed evidence")).toBeInTheDocument();
    expect(screen.getByText("Interpretation")).toBeInTheDocument();
    expect(screen.getByText("Limitations")).toBeInTheDocument();
    expect(screen.getByText("Does not decide")).toBeInTheDocument();
    expect(screen.getByText(/did not score, decide or change anything/)).toBeInTheDocument();
  });
});
