import type { Page } from "@playwright/test";
import type { ExtendedStatusOut, ImportOut, ResourceOut, ScanOut } from "../src/api";
import { expect, getJson, test, trailingNumber } from "./fixtures";

test("the header says the API is online", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("status").filter({ hasText: "API" })).toContainText(
    /^API online v\S+/,
  );
  for (const name of ["Overview", "Findings", "Resources", "Scans"]) {
    await expect(
      page.getByRole("navigation", { name: "Main" }).getByRole("link", { name }),
    ).toBeVisible();
  }
});

test.describe("Resources", () => {
  test.beforeEach(async ({ request }) => {
    const resources = await getJson<ResourceOut[]>(request, "/api/resources");
    test.skip(resources.length === 0, "There are no resources.");
  });

  test("the list is as long as the count it shows, and a type chip narrows it", async ({
    page,
    request,
  }) => {
    const resources = await getJson<ResourceOut[]>(request, "/api/resources");
    await page.goto("/resources");
    const rows = page.getByRole("table", { name: "Resources" }).getByRole("row");
    await expect(page.getByText(/Showing \d+ of \d+ resources/)).toContainText(
      `Showing ${resources.length} of ${resources.length}`,
    );
    // One row is the header.
    await expect(rows).toHaveCount(resources.length + 1);

    const chips = page.getByRole("group", { name: "Resource type" }).getByRole("button");
    const chip = chips.nth(1);
    const number = trailingNumber(await chip.innerText());
    await chip.click();

    await expect(page.getByText(/Showing \d+ of \d+ resources/)).toContainText(
      `Showing ${number} of`,
    );
    await expect(rows).toHaveCount(number + 1);
  });

  test("a resource opens its detail page", async ({ page }) => {
    await page.goto("/resources");
    const link = page.getByRole("table", { name: "Resources" }).getByRole("link").first();
    const name = await link.innerText();

    await link.click();

    await expect(page).toHaveURL(/\/resources\/.+/);
    await expect(page.getByRole("heading", { level: 1 })).toContainText(name);
    await expect(page.getByText("Stored attributes")).toBeVisible();
    await expect(
      page
        .getByRole("navigation", { name: "Breadcrumb" })
        .getByRole("link", { name: "Resources" }),
    ).toBeVisible();
  });
});

const SCAN_COLUMNS = [
  "Scan",
  "Status",
  "Started",
  "Duration",
  "Regions",
  "Resources",
  "Findings",
  "Errors",
];
const IMPORT_COLUMNS = [
  "File",
  "Origin",
  "Version",
  "Imported",
  "Duration",
  "Pass",
  "Fail",
  "Added",
  "Resolved",
  "Rejected",
];

async function headings(page: Page, table: string): Promise<string[]> {
  const cells = await page
    .getByRole("table", { name: table, exact: true })
    .getByRole("columnheader")
    .allInnerTexts();
  return cells.map((text) => text.trim());
}

test.describe("Scans", () => {
  test("the Scans table has its columns and one row for each scan", async ({
    page,
    request,
  }) => {
    const scans = await getJson<ScanOut[]>(request, "/api/scans");
    test.skip(scans.length === 0, "There are no scans.");

    await page.goto("/scans");

    await expect(page.getByRole("table", { name: "Scans", exact: true })).toBeVisible();
    expect(await headings(page, "Scans")).toEqual(SCAN_COLUMNS);
    await expect(
      page.getByRole("table", { name: "Scans", exact: true }).getByRole("row"),
    ).toHaveCount(scans.length + 1);
  });

  test("the Imports table has its columns and one row for each import", async ({
    page,
    request,
  }) => {
    const imports = await getJson<ImportOut[]>(request, "/api/imports");
    test.skip(imports.length === 0, "No file has been imported.");

    await page.goto("/scans");

    await expect(page.getByRole("table", { name: "Imports", exact: true })).toBeVisible();
    expect(await headings(page, "Imports")).toEqual(IMPORT_COLUMNS);
    await expect(
      page.getByRole("table", { name: "Imports", exact: true }).getByRole("row"),
    ).toHaveCount(imports.length + 1);
  });
});

test("the import dialog opens with its text and Escape closes it", async ({ page }) => {
  await page.goto("/scans");

  await page.getByRole("button", { name: "Import a results file" }).click();

  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByRole("heading", { name: "Import a results file" }),
  ).toBeVisible();
  await expect(dialog).toContainText("Nothing in this file leaves your computer");
  await expect(dialog).toContainText("when Run full scan cannot work on this computer");
  await expect(dialog.getByTestId("drop-zone")).toBeVisible();

  await page.keyboard.press("Escape");

  await expect(dialog).toBeHidden();
});

test("the Run scan menu lists its three choices and Escape closes it", async ({
  page,
  request,
}) => {
  const status = await getJson<ExtendedStatusOut>(request, "/api/extended/status");
  await page.goto("/");

  await page.getByRole("button", { name: "More ways to scan" }).click();

  const menu = page.getByRole("menu", { name: "Ways to scan" });
  await expect(menu).toBeVisible();
  await expect(menu.getByRole("menuitem", { name: /^Run scan/ })).toBeEnabled();
  const full = menu.getByRole("menuitem", { name: /^Run full scan/ });
  await expect(full).toBeVisible();
  if (status.available) await expect(full).toBeEnabled();
  else await expect(full).toBeDisabled();
  await expect(
    menu.getByRole("menuitem", { name: /^Import a results file/ }),
  ).toBeVisible();
  if (status.reason) await expect(menu).toContainText(status.reason);
  if (status.hint) await expect(menu).toContainText(status.hint);
  if (status.warning) await expect(menu).toContainText(status.warning);

  await page.keyboard.press("Escape");

  await expect(menu).toBeHidden();
});

interface Focused {
  name: string;
  tag: string;
  type: string;
  href: string;
  visibleFocus: boolean;
}

// Presses Tab and describes what has focus after each press. Nothing is activated.
async function tabThrough(page: Page, presses: number): Promise<Focused[]> {
  const seen: Focused[] = [];
  for (let press = 0; press < presses; press++) {
    await page.keyboard.press("Tab");
    seen.push(
      await page.evaluate(() => {
        const element = document.activeElement as HTMLElement;
        const style = getComputedStyle(element);
        const outline =
          style.outlineStyle !== "none" && parseFloat(style.outlineWidth) > 0;
        return {
          name: (element.getAttribute("aria-label") ?? element.textContent ?? "")
            .trim()
            .slice(0, 80),
          tag: element.tagName,
          type: element.getAttribute("type") ?? "",
          href: element.getAttribute("href") ?? "",
          visibleFocus: outline || style.boxShadow !== "none",
        };
      }),
    );
  }
  return seen;
}

function expectVisibleFocus(seen: Focused[]) {
  const hidden = seen
    .filter((item) => !item.visibleFocus)
    .map((item) => `${item.tag} "${item.name}"`);
  expect(hidden, "Elements that took focus without a visible focus indicator").toEqual(
    [],
  );
}

test("Tab walks the Overview header in order and every stop shows focus", async ({
  page,
  request,
}) => {
  const scans = await getJson<ScanOut[]>(request, "/api/scans");
  test.skip(!scans.some((s) => s.status === "completed"), "No scan has completed.");
  await page.goto("/");
  await expect(page.getByTestId("hero")).toBeVisible();

  const seen = await tabThrough(page, 40);

  expectVisibleFocus(seen);
  const names = seen.map((item) => item.name);
  const order = [
    "cloudshield",
    "Overview",
    "Findings",
    "Resources",
    "Scans",
    "Run scan",
    "More ways to scan",
  ];
  const positions = order.map((name) => names.indexOf(name));
  expect(positions, `Tab order of ${order.join(", ")}`).not.toContain(-1);
  expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  expect(
    names.some((name) => /^\d+ (next|later|informational|dismissed)$/.test(name)),
  ).toBe(true);
});

test("Tab reaches the Findings filters and the first finding, each showing focus", async ({
  page,
}) => {
  await page.goto("/findings");
  await expect(page.getByRole("group", { name: "Lane" })).toBeVisible();

  const seen = await tabThrough(page, 45);

  expectVisibleFocus(seen);
  expect(seen.some((item) => item.tag === "INPUT" && item.type === "search")).toBe(true);
  expect(seen.filter((item) => item.tag === "SELECT").length).toBeGreaterThanOrEqual(5);
  expect(seen.some((item) => item.name === "Group by check")).toBe(true);
  expect(seen.some((item) => item.href.startsWith("/findings/"))).toBe(true);
});
