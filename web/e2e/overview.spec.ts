import type { FindingOut, GuardrailOut, ScanOut } from "../src/api";
import { LANE_THRESHOLDS } from "../src/lanes";
import {
  expect,
  getJson,
  isActive,
  listedRows,
  showing,
  test,
  trailingNumber,
} from "./fixtures";

test.beforeEach(async ({ request }) => {
  const scans = await getJson<ScanOut[]>(request, "/api/scans");
  test.skip(
    !scans.some((scan) => scan.status === "completed"),
    "No scan has completed, so the Overview has no results to check.",
  );
});

const inBand = (f: FindingOut, low: number, high: number) =>
  isActive(f) && f.risk_score !== null && f.risk_score >= low && f.risk_score < high;

test("the headline says how many are fixed and how many to fix now", async ({
  page,
  request,
}) => {
  const findings = await getJson<FindingOut[]>(request, "/api/findings");
  const fixed = findings.filter((f) => f.status === "RESOLVED").length;
  const now = findings.filter((f) => inBand(f, LANE_THRESHOLDS.fixNow, 1000)).length;

  await page.goto("/");

  const headline = page.getByRole("heading", { level: 1 });
  await expect(headline).toContainText(`${fixed} fixed.`);
  await expect(headline).toContainText(
    now === 0 ? "Nothing to fix now." : `${now} to fix now.`,
  );
});

test("each lane shows the number of findings its score band holds", async ({
  page,
  request,
}) => {
  const findings = await getJson<FindingOut[]>(request, "/api/findings");
  const { fixNow, next } = LANE_THRESHOLDS;
  const expected = {
    "Fix now": findings.filter((f) => inBand(f, fixNow, 1000)).length,
    Next: findings.filter((f) => inBand(f, next, fixNow)).length,
    Later: findings.filter((f) => inBand(f, 0, next)).length,
  };

  await page.goto("/");

  for (const [name, count] of Object.entries(expected)) {
    const lane = page.getByRole("region", { name, exact: true });
    await expect(lane).toBeVisible();
    const shown = trailingNumber(await lane.locator("header").innerText());
    expect(shown, `${name} lane count`).toBe(count);
  }
});

test("every count link opens Findings with a list as long as its number", async ({
  page,
}) => {
  await page.goto("/");
  const links = page.getByTestId("lane-counts").getByRole("link");
  await expect(links.first()).toBeVisible();
  const total = await links.count();
  expect(total).toBe(4);

  for (let index = 0; index < total; index++) {
    await page.goto("/");
    const link = page.getByTestId("lane-counts").getByRole("link").nth(index);
    const text = await link.innerText();
    const href = (await link.getAttribute("href")) ?? "";
    const number = Number(text.split(" ")[0]);

    await link.click();

    expect(page.url().endsWith(href), `${text} opens ${href}`).toBe(true);
    await showing(page, number);
    await expect(listedRows(page), text).toHaveCount(number);
  }
});

test("the source count links open Findings with a list as long as their number", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.getByTestId("lane-counts")).toBeVisible();
  const line = page.getByTestId("source-counts");
  test.skip(
    (await line.count()) === 0,
    "No imported findings exist, so there is no source line.",
  );
  const total = await line.getByRole("link").count();

  for (let index = 0; index < total; index++) {
    await page.goto("/");
    const link = page.getByTestId("source-counts").getByRole("link").nth(index);
    const text = await link.innerText();
    const number = Number(text.split(" ")[0]);

    await link.click();

    await showing(page, number);
    await expect(listedRows(page), text).toHaveCount(number);
  }
});

test("the Guardrails line counts what the guardrails API reports", async ({
  page,
  request,
}) => {
  const guardrails = await getJson<GuardrailOut[]>(request, "/api/guardrails");
  const count = (status: string) => guardrails.filter((g) => g.status === status).length;

  await page.goto("/");

  await expect(page.getByTestId("guardrail-line")).toHaveText(
    `Guardrails: ${count("active")} active, ${count("unknown")} unknown.`,
  );
});

test("Start with opens the finding it names", async ({ page }) => {
  await page.goto("/");
  const start = page.locator("main p", { hasText: /^Start with/ }).getByRole("link");
  await expect(page.getByTestId("hero")).toBeVisible();
  test.skip(
    (await start.count()) === 0,
    "Nothing is open, so there is nothing to start with.",
  );
  const title = await start.innerText();

  await start.click();

  await expect(page.getByRole("heading", { level: 1 })).toHaveText(title);
});
