import { expect, test, type Page } from "@playwright/test";

/**
 * The analyst flow on the synthetic demo world, end to end against the real service:
 * start the demo → overview → queue → open a case → timeline → run the investigation →
 * resolve → the resolution is final and shows the authenticated reviewer.
 * With SENTINEL_SCREENSHOTS=1 it also writes the README screenshots (demo data only).
 */
const SHOTS = process.env.SENTINEL_SCREENSHOTS === "1";

async function shot(page: Page, name: string) {
  if (!SHOTS) return;
  await page.waitForTimeout(400); // let transitions settle
  await page.screenshot({ path: `docs/screenshots/${name}.png` });
}

test.describe.configure({ mode: "serial" });

test("analyst flow", async ({ page }) => {
  // --- start-up: real readiness checks
  await page.goto("/");
  const startup = page.getByTestId("startup");
  await expect(startup.getByText("INITIALIZING FRAUD INTELLIGENCE ENVIRONMENT")).toBeVisible();
  await expect(startup.locator('[data-check="database"][data-state="online"]')).toBeVisible();
  await expect(startup.locator('[data-check="model"][data-state="online"]')).toBeVisible();
  await expect(startup.locator('[data-check="signatures"][data-state="online"]')).toBeVisible();
  await expect(startup.locator('[data-check="analyst"][data-state="online"]')).toBeVisible();
  await expect(startup.locator('[data-state="checking"]')).toHaveCount(0);
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
  await shot(page, "02-overview");

  // --- queue: the new item, found by its assessment ID
  await page.getByRole("link", { name: /Review Queue/ }).click();
  await expect(page.getByTestId("queue-table")).toBeVisible();
  await shot(page, "03-queue");
  await page.getByLabel("Filter by case, assessment or event ID").fill(assessmentId.slice(0, 8));
  const rows = page.getByTestId("case-row");
  await expect(rows).toHaveCount(1);
  await rows.first().click();

  // --- the case workspace
  await expect(page).toHaveURL(new RegExp(`/queue\\?case=${assessmentId}`));
  const ws = page.getByTestId("case-workspace");
  await expect(ws.getByTestId("case-header")).toContainText("Manual review");
  await expect(ws.getByTestId("timeline-event").filter({ hasText: "This case" })).toHaveCount(1);
  await expect(ws.getByTestId("model-comparison")).toContainText("Shadow · never decides");
  await shot(page, "04-case");

  // --- analyst assistance
  await ws.getByTestId("run-investigation").click();
  await expect(ws.getByTestId("investigation-result")).toBeVisible({ timeout: 90_000 });
  await expect(ws.getByTestId("investigation-result")).toContainText("Reference template");
  await ws.getByTestId("model-comparison").scrollIntoViewIfNeeded();
  await shot(page, "05-model-comparison");

  // --- resolve (confirmation required), then it is final
  await ws.getByTestId("resolve-legitimate").click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("This is final");
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
  await shot(page, "06-system");
});

test("the proxy refuses routes outside the allow-list", async ({ request }) => {
  const score = await request.post("/api/fraud/score", { data: {}, headers: { Origin: "http://127.0.0.1:3100" } });
  expect(score.status()).toBe(403);
  const session = await request.get("/api/session");
  const text = await session.text();
  expect(text).not.toMatch(/fak_[A-Za-z0-9]/);
});
