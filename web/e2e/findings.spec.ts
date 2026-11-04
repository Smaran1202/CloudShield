import type { Page } from "@playwright/test";
import type { FindingOut } from "../src/api";
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

// The default list: open findings with a score of Next or higher.
const inFocus = (f: FindingOut) =>
  isActive(f) && f.risk_score !== null && f.risk_score >= LANE_THRESHOLDS.next;

test.beforeEach(async ({ request }) => {
  const findings = await getJson<FindingOut[]>(request, "/api/findings");
  test.skip(findings.length === 0, "There are no findings to check.");
});

test.describe("Findings list", () => {
  test("the tabs show counts that match the list they open", async ({
    page,
    request,
  }) => {
    const findings = await getJson<FindingOut[]>(request, "/api/findings");
    await page.goto("/findings");
    const chips = page.getByRole("group", { name: "Lane" }).getByRole("button");
    await expect(chips.first()).toBeVisible();
    const total = await chips.count();
    // A tab with nothing in it is left out.
    const expected = [
      ["To do", findings.filter(inFocus).length],
      [
        "Later",
        findings.filter(
          (f) =>
            isActive(f) && f.risk_score !== null && f.risk_score < LANE_THRESHOLDS.next,
        ).length,
      ],
      ["Done", findings.filter((f) => f.status === "RESOLVED").length],
      [
        "Dismissed",
        findings.filter((f) => f.status === "OPEN" && f.dismissed && !f.merged_into)
          .length,
      ],
    ].filter(([, count]) => count !== 0);
    expect(total).toBe(expected.length);

    for (let index = 0; index < total; index++) {
      const [name, count] = expected[index];
      const text = await chips.nth(index).innerText();
      expect(text, "tab name").toContain(String(name));
      expect(trailingNumber(text), `${name} tab`).toBe(count);
    }

    for (let index = 0; index < total; index++) {
      const chip = chips.nth(index);
      const text = await chip.innerText();
      const number = trailingNumber(text);

      await chip.click();

      await expect(chip, text).toHaveAttribute("aria-pressed", "true");
      await showing(page, number);
      await expect(listedRows(page), text).toHaveCount(number);
    }
  });

  test("the severity filter shows the open findings of that severity", async ({
    page,
    request,
  }) => {
    const open = (await getJson<FindingOut[]>(request, "/api/findings")).filter(isActive);
    const severities = [...new Set(open.map((f) => f.severity))];
    test.skip(severities.length === 0, "No finding is open.");
    await page.goto("/findings?lane=open");
    await openFilters(page);

    for (const severity of severities) {
      const expected = open.filter((f) => f.severity === severity).length;

      await select(page, "Severity").selectOption(severity);

      await showing(page, expected);
      await expect(listedRows(page), severity).toHaveCount(expected);
    }
  });

  test("the source filter separates CloudShield findings from imported ones", async ({
    page,
    request,
  }) => {
    const open = (await getJson<FindingOut[]>(request, "/api/findings")).filter(isActive);
    await page.goto("/findings?lane=open");
    await openFilters(page);

    for (const source of ["cloudshield", "prowler"]) {
      const expected = open.filter((f) => f.source === source).length;

      await select(page, "Source").selectOption(source);

      await showing(page, expected);
      await expect(listedRows(page), source).toHaveCount(expected);
    }
  });

  test("the informational filter hides or isolates INFO findings", async ({
    page,
    request,
  }) => {
    const open = (await getJson<FindingOut[]>(request, "/api/findings")).filter(isActive);
    const info = open.filter((f) => f.severity === "INFO").length;
    await page.goto("/findings?lane=open");
    await openFilters(page);

    await select(page, "Informational").selectOption("hide");
    await showing(page, open.length - info);

    await select(page, "Informational").selectOption("only");
    await showing(page, info);
  });

  test("Clear filters brings back the default list", async ({ page, request }) => {
    const focus = (await getJson<FindingOut[]>(request, "/api/findings")).filter(inFocus);
    await page.goto("/findings?lane=open&severity=CRITICAL&source=cloudshield");

    await page.getByRole("button", { name: "Clear filters" }).click();

    await showing(page, focus.length);
    await expect(page.getByRole("button", { name: "Clear filters" })).toHaveCount(0);
  });

  test("the default list is Fix now and Next, with Later grouped by check and informational behind a count", async ({
    page,
    request,
  }) => {
    const open = (await getJson<FindingOut[]>(request, "/api/findings")).filter(isActive);
    const later = open.filter(
      (f) => f.risk_score !== null && f.risk_score < LANE_THRESHOLDS.next,
    );
    const info = open.filter((f) => f.severity === "INFO");

    await page.goto("/findings");

    const focus = open.filter(inFocus).length;
    await showing(page, focus);
    await expect(listedRows(page)).toHaveCount(focus);
    const grouped = page.getByRole("table", { name: "Later, grouped by check" });
    if (later.length > 0) {
      const checks = new Set(later.map((f) => f.rule_id)).size;
      await expect(grouped.getByRole("row")).toHaveCount(checks);
    } else {
      await expect(grouped).toHaveCount(0);
    }
    const link = page.getByRole("link", { name: /^\d+ informational findings?$/ });
    if (info.length > 0) await expect(link).toContainText(String(info.length));
    else await expect(link).toHaveCount(0);
  });

  test("Group by check can be switched on and off", async ({ page }) => {
    await page.goto("/findings");
    const group = page.getByRole("button", { name: "Group by check" });

    await group.click();
    await expect(group).toHaveAttribute("aria-pressed", "true");
    await group.click();
    await expect(group).toHaveAttribute("aria-pressed", "false");
  });
});

// The label holds the chosen option too, so it is found by what it starts with. The filters are
// in a fold that starts closed unless the link already sets one.
const select = (page: Page, label: string) =>
  page
    .locator("label")
    .filter({ hasText: new RegExp(`^${label}`) })
    .locator("select");

async function openFilters(page: Page) {
  const fold = page.getByRole("button", { name: /^Filters/ });
  if ((await fold.getAttribute("aria-expanded")) === "false") await fold.click();
}

const TABS = ["Summary", "Evidence", "Risk", "Fix"];

async function openFromList(page: Page, finding: FindingOut) {
  await page.goto("/findings?lane=all");
  const href = `/findings/${encodeURIComponent(finding.finding_id)}`;
  await page.locator(`a[href="${href}"]`).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(finding.title);
}

async function visitEveryTab(page: Page) {
  for (const label of TABS) {
    const tab = page.getByRole("tab", { name: label, exact: true });
    await tab.click();
    await expect(tab).toHaveAttribute("aria-selected", "true");
    await expect(page).toHaveURL(new RegExp(`tab=${label.toLowerCase()}`));
    await expect(page.getByRole("tabpanel")).not.toBeEmpty();
  }
}

test.describe("Finding detail", () => {
  test("a CloudShield finding opens from the list and every tab opens", async ({
    page,
    request,
  }) => {
    const findings = await getJson<FindingOut[]>(request, "/api/findings");
    const own = findings.find((f) => f.source === "cloudshield");
    test.skip(!own, "There is no CloudShield finding.");

    await openFromList(page, own!);
    await visitEveryTab(page);

    // The fix is only made when someone asks. These tests never ask.
    await expect(page.getByRole("button", { name: "Generate fix" })).toBeVisible();
    await expect(page.getByText("Nothing is generated until you ask")).toBeVisible();
  });

  test("an imported finding opens from the list and every tab opens", async ({
    page,
    request,
  }) => {
    const findings = await getJson<FindingOut[]>(request, "/api/findings");
    const imported = findings.find((f) => f.source === "prowler");
    test.skip(!imported, "There is no imported finding.");

    await openFromList(page, imported!);
    await visitEveryTab(page);

    await expect(
      page.getByText(
        "No patch for this finding. This is guidance from an imported scan.",
      ),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: "Generate fix" })).toBeVisible();
  });

  test("imported evidence is labelled Reported and shows no raw ** or backticks", async ({
    page,
    request,
  }) => {
    const findings = await getJson<FindingOut[]>(request, "/api/findings");
    const imported = findings.find(
      (f) => f.source === "prowler" && f.evidence.items.length > 0,
    );
    test.skip(!imported, "No imported finding has evidence.");

    await openFromList(page, imported!);
    await page.getByRole("tab", { name: "Evidence", exact: true }).click();

    await expect(
      page.getByText("Reported by an imported scan, not verified by CloudShield."),
    ).toBeVisible();
    const text = await page.getByRole("tabpanel").innerText();
    expect(text).not.toContain("**");
    expect(text).not.toContain("`");
  });

  test("an imported finding with a score shows how the score was made", async ({
    page,
    request,
  }) => {
    const findings = await getJson<FindingOut[]>(request, "/api/findings");
    const scored = findings.find(
      (f) => f.source === "prowler" && f.risk_score !== null && f.score_breakdown,
    );
    test.skip(!scored, "No imported finding has a score and a score breakdown.");

    await openFromList(page, scored!);

    await expect(page.getByTestId("score-how-header")).toHaveText(
      /^\d+ = \d+ from .+ \+ \d+ from CloudShield context\./,
    );
    await page.getByRole("tab", { name: "Risk", exact: true }).click();
    await expect(page.getByTestId("score-how")).toBeVisible();
  });

  // The text of an imported fix (What to do, Plain words, the formatted guidance) only appears
  // after Generate fix, which sends a POST. Read-only tests never press it.
  test.skip("imported fix text: What to do, Plain words and formatted guidance", () => {});
});
