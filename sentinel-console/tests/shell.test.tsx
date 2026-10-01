import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CommandPalette } from "@/components/CommandPalette";
import { LiveIndicator } from "@/components/LiveIndicator";
import { StartupScreen } from "@/components/shell/StartupScreen";
import type { GroupId, HealthGroup } from "@/features/system/groups";

import { mockFetch, renderWithClient } from "./utils";

const push = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }), usePathname: () => "/", useSearchParams: () => new URLSearchParams() }));

beforeEach(() => sessionStorage.clear());
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const group = (id: GroupId, state: HealthGroup["state"]): HealthGroup => ({ id, title: id, action: `Checking ${id}`, state, cause: `${id} cause` });
const ALL: GroupId[] = ["service", "trust", "data", "models", "policy", "audit", "analyst"];

describe("command palette", () => {
  it("offers navigation and view actions only — nothing consequential", () => {
    mockFetch({});
    renderWithClient(<CommandPalette onClose={() => {}} demoMode={true} onToggleDensity={() => {}} />);
    const text = screen.getByRole("listbox").textContent!.toLowerCase();
    expect(text).toContain("review queue");
    for (const word of ["resolve", "reset", "fraud", "legitimate", "delete", "activate", "approve"]) expect(text).not.toContain(word);
  });

  it("looks up an ID and opens the case", async () => {
    mockFetch({ "/api/fraud/analyst/search": { query: "49044c7e", matches: [{ kind: "assessment", id: "49044c7e-adcc-448b-8633-c0c91edb1c4c", assessment_id: "49044c7e-adcc-448b-8633-c0c91edb1c4c", decision: "MANUAL_REVIEW" }] } });
    const onClose = vi.fn();
    renderWithClient(<CommandPalette onClose={onClose} demoMode={false} onToggleDensity={() => {}} />);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "49044c7e" } });
    await screen.findByText(/Assessment 49044c7eadcc/);
    fireEvent.keyDown(screen.getByRole("combobox"), { key: "Enter" });
    expect(push).toHaveBeenCalledWith("/investigations/49044c7e-adcc-448b-8633-c0c91edb1c4c");
  });

  it("does not search free text (no personal data search)", () => {
    const fetch = mockFetch({});
    renderWithClient(<CommandPalette onClose={() => {}} demoMode={false} onToggleDensity={() => {}} />);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "jane doe" } });
    expect(fetch.mock.calls.some(([u]) => String(u).includes("search"))).toBe(false);
  });
});

describe("start-up screen", () => {
  it("leaves by itself, quickly, when every group is online", () => {
    vi.useFakeTimers();
    renderWithClient(<StartupScreen groups={ALL.map((id) => group(id, "online"))} overall="operational" versions="v" demoMode={false} />);
    expect(screen.getByText("SECURE ANALYST ENVIRONMENT")).toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "7");
    act(() => vi.advanceTimersByTime(800)); // never a long animation to sit through
    expect(screen.queryByText("SECURE ANALYST ENVIRONMENT")).not.toBeInTheDocument();
    expect(sessionStorage.getItem("sentinel.startup.done")).toBe("1");
  });

  it("shows a line as CHECKING until its group has answered", () => {
    renderWithClient(<StartupScreen groups={ALL.map((id) => group(id, id === "audit" ? "checking" : "online"))} overall="checking" versions="v" demoMode={true} />);
    const audit = screen.getByTestId("startup").querySelector('[data-check="audit"]')!;
    expect(audit).toHaveAttribute("data-state", "checking");
    expect(audit.textContent).toContain("CHECKING");
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "6");
    expect(screen.getByText("DEMO MODE · SYNTHETIC DATA")).toBeInTheDocument();
  });

  it("stays, and says so, when a group is degraded", () => {
    vi.useFakeTimers();
    renderWithClient(<StartupScreen groups={ALL.map((id) => group(id, id === "audit" ? "degraded" : "online"))} overall="degraded" versions="v" demoMode={false} />);
    act(() => vi.advanceTimersByTime(5000));
    expect(screen.getByText(/1 group degraded/)).toBeInTheDocument();
    expect(screen.getByText("audit cause")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Enter console \(degraded\)/ }));
    act(() => vi.advanceTimersByTime(400));
    expect(screen.queryByTestId("startup")).not.toBeInTheDocument();
  });

  it("is skipped once seen in this browser session", () => {
    sessionStorage.setItem("sentinel.startup.done", "1");
    renderWithClient(<StartupScreen groups={[]} overall="checking" versions="v" demoMode={false} />);
    expect(screen.queryByTestId("startup")).not.toBeInTheDocument();
  });
});

describe("liveness", () => {
  it("never shows stale data as live", () => {
    render(<LiveIndicator state="stale" ageMs={120_000} />);
    expect(screen.getByRole("status")).toHaveTextContent("Stale");
    expect(screen.getByRole("status")).toHaveTextContent("last update 2m ago");
  });
});
