import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DecisionBadge } from "@/components/DecisionBadge";
import { EvidencePanel } from "@/components/EvidencePanel";
import { ModelComparison } from "@/components/ModelComparison";
import { RiskBadge } from "@/components/RiskBadge";
import { ErrorState } from "@/components/States";
import { StatusBadge } from "@/components/StatusBadge";
import { Actions } from "@/features/case/Actions";
import { Investigation } from "@/features/case/Investigation";
import { Timeline } from "@/features/case/Timeline";
import { ApiError, type ApiErrorKind } from "@/lib/api/client";
import { Case, type CaseT } from "@/lib/api/schemas";

import { fixture, mockFetch, renderWithClient } from "./utils";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }), usePathname: () => "/", useSearchParams: () => new URLSearchParams() }));

const theCase = Case.parse(fixture("case"));
const session = fixture("session");
const system = fixture("system");

afterEach(() => vi.unstubAllGlobals());

describe("badges never rely on colour alone", () => {
  it("decision: label and glyph", () => {
    render(<DecisionBadge decision="TEMPORARY_BLOCK" />);
    expect(screen.getByText("Temporary block")).toBeInTheDocument();
    expect(screen.getByText("■")).toBeInTheDocument();
  });
  it("unknown values are shown verbatim, not guessed", () => {
    render(<DecisionBadge decision="SOMETHING_NEW" />);
    expect(screen.getByText("SOMETHING_NEW")).toBeInTheDocument();
  });
  it("risk band is labelled as a band, not a probability", () => {
    render(<RiskBadge level="elevated" />);
    expect(screen.getByTitle(/not a probability/)).toHaveTextContent("Elevated");
  });
  it("step-up states", () => {
    render(<StatusBadge kind="auth" auth={{ attempts: 1, latest_result: "SUCCESS", completed: true }} />);
    expect(screen.getByText("Passed")).toBeInTheDocument();
  });
});

describe("error states", () => {
  it.each<[ApiErrorKind, string, number, string]>([
    ["unavailable", "BACKEND_UNREACHABLE", 503, "Service unavailable"],
    ["forbidden", "INSUFFICIENT_SCOPE", 403, "Permission denied"],
    ["rate_limited", "RATE_LIMITED", 429, "Rate limited"],
    ["not_found", "NOT_FOUND", 404, "Not found"],
    ["llm_unavailable", "LLM_UNAVAILABLE", 503, "Local analyst model unavailable"],
    ["timeout", "BACKEND_TIMEOUT", 504, "Request timed out"],
    ["schema", "SCHEMA_MISMATCH", 200, "Unexpected response"],
  ])("%s → %s", (kind, code, status, title) => {
    render(<ErrorState error={new ApiError(status, code, "msg", kind)} />);
    const alert = screen.getByRole("alert");
    expect(within(alert).getByText(title)).toBeInTheDocument();
    expect(within(alert).getByText(new RegExp(code))).toBeInTheDocument();
  });
});

describe("case evidence", () => {
  it("shows only the service's reason descriptions and says when there is none", () => {
    render(<EvidencePanel reasons={[{ code: "SCORE_BAND_HIGH", description: "From the service." }, { code: "NEW_CODE", description: null }]} rules={[]} />);
    expect(screen.getByText("From the service.")).toBeInTheDocument();
    expect(screen.getByText(/No description in the service's reason catalogue/)).toBeInTheDocument();
  });

  it("lists models separately against their own thresholds, with no consensus score", () => {
    const { container } = render(<ModelComparison models={theCase.models} />);
    expect(screen.getByText(/Shadow · never decides/)).toBeInTheDocument();
    expect(screen.getAllByText(/threshold/).length).toBeGreaterThan(0);
    expect(container.textContent?.toLowerCase()).not.toMatch(/consensus|average|combined score|probability of fraud/);
  });

  it("states disagreement when the models disagree", () => {
    const models: CaseT["models"] = { ...theCase.models, disagreement: true, flagged: 1 };
    render(<ModelComparison models={models} />);
    expect(screen.getByText("Models disagree")).toBeInTheDocument();
  });

  it("collapses older timeline events and marks the case event", () => {
    render(<Timeline items={theCase.timeline} />);
    expect(screen.getByText("This case")).toBeInTheDocument();
    const toggle = screen.getByRole("button", { name: /Show \d+ earlier event/ });
    const before = screen.getAllByTestId("timeline-event").length;
    fireEvent.click(toggle);
    expect(screen.getAllByTestId("timeline-event").length).toBeGreaterThan(before);
  });
});

describe("analyst assistance", () => {
  it("keeps the case usable when the local model is unavailable", async () => {
    mockFetch({
      "/api/fraud/analyst/system": system,
      "/api/fraud/assessments/": () => Response.json({ error: { code: "LLM_UNAVAILABLE", message: "no local LLM runtime" } }, { status: 503 }),
      "/api/fraud/analyst/cases/": fixture("case"),
    });
    renderWithClient(<Investigation assessmentId={theCase.assessment.assessment_id} investigation={theCase.investigation} />);
    expect(screen.getByText("ANALYST ASSISTANCE")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("run-investigation"));
    expect(await screen.findByText("Local analyst model unavailable")).toBeInTheDocument();
    expect(screen.getByText(/Scoring, decisions and the rest of this case are unaffected/)).toBeInTheDocument();
    // the stored investigation is still shown
    expect(screen.getByTestId("investigation-result")).toBeInTheDocument();
  });
});

describe("analyst decision", () => {
  const open = theCase.review!;

  it("requires confirmation and submits once, however often it is clicked", async () => {
    const calls: RequestInit[] = [];
    mockFetch({
      "/api/session": session,
      [`/api/reviews/${open.review_id}/resolve`]: async (_url: string, init?: RequestInit) => {
        calls.push(init!);
        await new Promise((r) => setTimeout(r, 30));
        return Response.json({ review: { review_id: open.review_id, status: "resolved", outcome: "fraud" }, outcomes: [{ resolution: "fraud", reviewer: "operator:rita", created_at: "2026-09-30T22:00:00Z" }] });
      },
      "/api/fraud/analyst/cases/": fixture("case"),
    });
    renderWithClient(<Actions data={{ ...theCase, review: { ...open, status: "open", outcomes: [] } }} />);
    await screen.findByText(/DEMO MODE: resolutions are signed/);
    fireEvent.click(screen.getByTestId("resolve-fraud"));
    expect(calls).toHaveLength(0); // nothing is sent before confirming
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByText(/This is final/)).toBeInTheDocument();
    const confirm = within(dialog).getByTestId("confirm-action");
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
    expect(calls).toHaveLength(1);
    expect(JSON.parse(String(calls[0]!.body))).toEqual({ resolution: "fraud" });
  });

  it("Esc cancels without sending anything", async () => {
    const fetch = mockFetch({ "/api/session": session });
    renderWithClient(<Actions data={{ ...theCase, review: { ...open, status: "open", outcomes: [] } }} />);
    fireEvent.click(screen.getByTestId("resolve-legitimate"));
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
    expect(fetch.mock.calls.every(([u]) => !String(u).includes("/resolve"))).toBe(true);
  });

  it("shows a resolved case as final, with the reviewer, and no actions", () => {
    mockFetch({ "/api/session": session });
    renderWithClient(
      <Actions data={{ ...theCase, review: { ...open, status: "resolved", outcome: "legitimate", outcomes: [{ resolution: "legitimate", note: "checked", reviewer: "operator:rita", created_at: "2026-09-30T22:00:00Z" }] } }} />,
    );
    expect(screen.getByTestId("resolution-reviewer")).toHaveTextContent("operator:rita");
    expect(screen.getByText("Final")).toBeInTheDocument();
    expect(screen.queryByTestId("resolve-fraud")).not.toBeInTheDocument();
    expect(screen.getByText(/Outcomes are immutable/)).toBeInTheDocument();
  });

  it("outside DEMO MODE asks for the analyst's own assertion", async () => {
    mockFetch({ "/api/session": { ...(session as object), demo_mode: false, operator: { mode: "assertion", operator_id: null, note: "" } } });
    renderWithClient(<Actions data={{ ...theCase, review: { ...open, status: "open", outcomes: [] } }} />);
    await screen.findByText(/needs your own single-use signed operator assertion/);
    fireEvent.click(screen.getByTestId("resolve-legitimate"));
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByText(/fraud-ai operators assert/)).toBeInTheDocument();
    expect(within(dialog).getByTestId("confirm-action")).toBeDisabled();
  });

  it("offers nothing when the assessment is not in the queue", () => {
    mockFetch({ "/api/session": session });
    renderWithClient(<Actions data={{ ...theCase, review: null }} />);
    expect(screen.getByText("Not in the review queue")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
