import path from "node:path";

import { expect, test, type Page } from "@playwright/test";

/**
 * The analyst flow on the synthetic demo world, end to end against the real service:
 * start the demo → overview → live feed → queue → open a case → timeline → models → run the
 * investigation → resolve → the resolution is final and shows the authenticated reviewer →
 * system → metrics. Every page visited is audited for WCAG 2.1 A/AA.
 * With SENTINEL_SCREENSHOTS=1 it also writes the ten README screenshots (demo data only).
 */
const SHOTS = process.env.SENTINEL_SCREENSHOTS === "1";
const AXE = path.join(process.cwd(), "node_modules", "axe-core", "axe.min.js"); // run from sentinel-console

/** WCAG 2.1 A/AA audit of the current page (axe-core); any serious or critical issue fails. */
async function accessible(page: Page, where: string) {
  // audit settled colours, not an animation frame (a freshly polled row is briefly tinted)
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.waitForTimeout(350);
  await page.addScriptTag({ path: AXE });
  const violations = await page.evaluate(async () => {
    // @ts-expect-error axe is injected above
    const r = await window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] } });
    return r.violations
      .filter((v: { impact: string }) => v.impact === "serious" || v.impact === "critical")
      .map((v: { id: string; nodes: Array<{ target: string[] }> }) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`);
  });
  await page.emulateMedia({ reducedMotion: "no-preference" });
  expect(violations, `accessibility on ${where}`).toEqual([]);
  // the app shell is exactly one viewport: only the main region scrolls, never the document
  // (a positioned element escaping .main once let a long case drag the whole shell away)
  const overflow = await page.evaluate(() => document.documentElement.scrollHeight - window.innerHeight);
  expect(overflow, `document-level overflow on ${where}`).toBeLessThanOrEqual(0);
}

async function shot(page: Page, name: string) {
  if (!SHOTS) return;
  await page.waitForTimeout(400); // let transitions settle
  await page.screenshot({ path: `docs/screenshots/${name}.png` });
}

test.describe.configure({ mode: "serial" });

test("analyst flow", async ({ page }) => {
  const problems: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error" || m.type() === "warning") problems.push(`${m.type()}: ${m.text()}`);
  });
  page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));

  // --- start-up: one line per group, each resolved by real readiness data
  await page.goto("/");
  const startup = page.getByTestId("startup");
  await expect(startup.getByText("SECURE ANALYST ENVIRONMENT")).toBeVisible();
  for (const id of ["service", "trust", "data", "models", "policy", "analyst"]) {
    await expect(startup.locator(`[data-check="${id}"][data-state="online"]`)).toBeVisible();
  }
  await expect(startup.locator('[data-check="data"]')).toContainText("Redis not used");
  await expect(startup.locator('[data-state="checking"]')).toHaveCount(0);
  await accessible(page, "start-up");
  await shot(page, "01-startup");
  // a fresh demo world has no external audit anchor yet, so the console reports DEGRADED and waits
  const enter = page.getByRole("button", { name: /Enter console/ });
  if (await enter.isVisible()) await enter.click();
  await expect(startup).toBeHidden();

  // --- start the demo: score the manual-review scenario through the real service
  await page.getByRole("link", { name: "Demo" }).click();
  await expect(page.getByText("DEMO MODE · SYNTHETIC DATA").first()).toBeVisible();
  const card = page.getByTestId("scenario-manual_review");
  const play = card.getByTestId("play-manual_review");
  const opened = card.getByTestId("open-manual_review");
  await expect(play.or(opened)).toBeVisible(); // the catalogue loads asynchronously
  if (await play.isVisible()) await play.click();
  await expect(card.getByText("Service decided")).toBeVisible({ timeout: 60_000 });
  await expect(card.getByText("= measured")).toBeVisible();
  const href = await card.getByTestId("open-manual_review").getAttribute("href");
  const assessmentId = href!.split("/").pop()!;

  // --- overview: live numbers from the service
  await page.getByRole("link", { name: "Overview" }).click();
  const metrics = page.getByTestId("overview-metrics");
  await expect(metrics.getByRole("group", { name: /Assessments/ })).not.toContainText("—");
  await expect(page.getByTestId("feed-table")).toBeVisible();
  await accessible(page, "overview");
  await shot(page, "02-overview");

  // --- live feed: every recent assessment, newest first
  await page.getByRole("link", { name: "Live Feed", exact: true }).click();
  await expect(page.getByTestId("feed-table")).toBeVisible();
  await accessible(page, "live feed");
  await shot(page, "03-live-feed");

  // --- queue: the new item, found by its assessment ID
  await page.getByRole("link", { name: /Review Queue/ }).click();
  await expect(page.getByTestId("queue-table")).toBeVisible();
  await accessible(page, "queue");
  await shot(page, "04-review-queue");
  await page.getByLabel("Filter by case, assessment or event ID").fill(assessmentId.slice(0, 8));
  const rows = page.getByTestId("case-row");
  await expect(rows).toHaveCount(1);
  await rows.first().click();

  // --- the case workspace
  await expect(page).toHaveURL(new RegExp(`/queue\\?case=${assessmentId}`));
  const ws = page.getByTestId("case-workspace");
  await expect(ws.getByTestId("case-header")).toContainText("Manual review");
  await expect(ws.getByTestId("case-summary")).toContainText("Sent to manual review");
  await expect(ws.getByTestId("timeline-event").filter({ hasText: "This case" })).toHaveCount(1);
  await expect(ws.getByTestId("model-comparison")).toContainText("Shadow · never decides");
  await expect(ws.getByTestId("model-comparison")).toContainText("Recorded for comparison · never decides");
  // DEMO.md's interview script relies on this: in the default world the models disagree here
  await expect(ws.getByTestId("model-comparison")).toContainText("Models disagree");
  await accessible(page, "case workspace");
  await shot(page, "05-case");

  // --- keyboard: R opens the resolve panel and never submits
  await page.locator("body").click({ position: { x: 5, y: 5 } });
  await page.keyboard.press("r");
  await expect(ws.getByTestId("resolve-legitimate")).toBeFocused();
  await expect(page.getByRole("alertdialog")).toHaveCount(0);

  // --- the behavioural timeline: the whole history up to the case event
  await ws.getByRole("button", { name: /Show \d+ earlier events?/ }).click();
  await expect(ws.getByRole("button", { name: "Collapse earlier events" })).toBeVisible();
  await ws.getByTestId("timeline-event").filter({ hasText: "This case" }).evaluate((el) => el.scrollIntoView({ block: "end" }));
  await shot(page, "06-timeline");

  // --- analyst assistance
  await ws.getByTestId("run-investigation").click();
  await expect(ws.getByTestId("investigation-result")).toBeVisible({ timeout: 90_000 });
  await expect(ws.getByTestId("investigation-result")).toContainText("Reference template");
  await expect(ws.getByTestId("investigation-result")).toContainText("Observed evidence");
  await expect(ws.getByTestId("investigation-result")).toContainText("Limitations");
  await ws.getByTestId("model-comparison").scrollIntoViewIfNeeded();
  await shot(page, "07-model-comparison");
  await ws.getByText("ANALYST ASSISTANCE").evaluate((el) => el.scrollIntoView({ block: "start" }));
  await shot(page, "08-analyst-assistance");
  await accessible(page, "analyst assistance");

  // --- resolve (confirmation required), then it is final
  await ws.getByTestId("resolve-legitimate").click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("This is final");
  await expect(dialog).toContainText("What will happen");
  await dialog.getByRole("textbox").first().fill("Demo walkthrough: known device and home network.");
  await dialog.getByTestId("confirm-action").click();
  await expect(dialog).toBeHidden();
  const resolution = ws.getByTestId("resolution");
  await expect(resolution).toContainText("Legitimate");
  await expect(ws.getByTestId("resolution-reviewer")).toHaveText("operator:rita");
  await expect(ws.getByTestId("resolve-legitimate")).toHaveCount(0); // no longer editable

  // reload: the outcome comes back from the service, not local state
  await page.reload();
  await expect(page.getByTestId("resolution")).toContainText("Legitimate");
  await expect(page.getByTestId("resolution")).toContainText("Final");

  // --- system health
  await page.getByRole("link", { name: "System" }).click();
  await expect(page.getByTestId("models-table")).toContainText("Verified");
  await expect(page.getByTestId("ops-rail").locator('[data-group="trust"][data-state="online"]')).toBeVisible();
  await accessible(page, "system");
  await shot(page, "09-system");

  // --- metrics: the same service summary, over time
  await page.getByRole("link", { name: "Metrics", exact: true }).click();
  await expect(page.getByLabel("Main content").getByRole("heading", { name: "Metrics" })).toBeVisible();
  await expect(page.getByText("Decision distribution")).toBeVisible();
  await accessible(page, "metrics");
  await shot(page, "10-metrics");

  // a clean browser console through the whole flow: no React, hydration or runtime errors
  expect(problems).toEqual([]);
});

test("the proxy refuses routes outside the allow-list", async ({ request }) => {
  const score = await request.post("/api/fraud/score", { data: {}, headers: { Origin: "http://127.0.0.1:3100" } });
  expect(score.status()).toBe(403);
  const session = await request.get("/api/session");
  const text = await session.text();
  expect(text).not.toMatch(/fak_[A-Za-z0-9]/);
});
