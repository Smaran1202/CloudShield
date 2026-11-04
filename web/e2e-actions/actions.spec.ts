import { randomBytes } from "node:crypto";
import type { Page } from "@playwright/test";
import type {
  ExtendedStatusOut,
  FindingOut,
  FixOut,
  ImportOut,
  ScanOut,
} from "../src/api";
import { LANE_THRESHOLDS } from "../src/lanes";
import {
  expect,
  findingPath,
  getJson,
  headline,
  isActive,
  test,
  waitForScan,
} from "./fixtures";

// These tests run in order, one at a time, against one throwaway database. Each one builds on
// what the one before it left behind. After a failure the rest are skipped.
test.describe.configure({ mode: "serial" });

const BAND_OF = (score: number) =>
  score >= LANE_THRESHOLDS.fixNow
    ? "now"
    : score >= LANE_THRESHOLDS.next
      ? "next"
      : "later";

interface Numbers {
  now: number;
  next: number;
  later: number;
  informational: number;
  dismissed: number;
}

// The headline and the count line of the Overview, as numbers.
async function overviewNumbers(page: Page): Promise<Numbers> {
  await page.goto("/");
  await expect(page.getByTestId("lane-counts")).toBeVisible();
  const text = await headline(page).innerText();
  const toFix = /(\d+) to fix now/.exec(text);
  const numbers: Numbers = {
    now: toFix ? Number(toFix[1]) : 0,
    next: 0,
    later: 0,
    informational: 0,
    dismissed: 0,
  };
  for (const link of await page
    .getByTestId("lane-counts")
    .getByRole("link")
    .allInnerTexts()) {
    const match = /^(\d+) (next|later|informational|dismissed)/.exec(link);
    if (match)
      numbers[match[2] as "next" | "later" | "informational" | "dismissed"] = Number(
        match[1],
      );
  }
  return numbers;
}

test("a. the header says the API is online, on an empty test database", async ({
  page,
  request,
}) => {
  const scans = await getJson<ScanOut[]>(request, "/api/scans");
  expect(scans, "The test database must start empty. Is this the throwaway one?").toEqual(
    [],
  );

  await page.goto("/");

  await expect(page.getByRole("status").filter({ hasText: "API" })).toContainText(
    /^API online v\S+/,
  );
});

test("b. Run scan completes and the Overview shows findings", async ({
  page,
  request,
}) => {
  test.setTimeout(15 * 60_000);
  await page.goto("/");

  await page.getByRole("button", { name: "Run scan", exact: true }).click();
  const scan = await waitForScan(request, null, 12);

  expect(scan.status, scan.failure_message ?? "the scan failed").toBe("completed");
  await page.goto("/");
  await expect(page.getByTestId("hero")).toBeVisible();
  const open = (await getJson<FindingOut[]>(request, "/api/findings")).filter(isActive);
  if (open.length === 0) {
    test
      .info()
      .annotations.push({ type: "note", description: "The account has no findings." });
    await expect(headline(page)).toContainText("Nothing to fix now.");
    return;
  }
  await expect(headline(page)).toContainText("0 fixed.");
  await expect(page.locator('main a[href^="/findings/"]').first()).toBeVisible();
  await expect(page.getByTestId("lane-counts")).toBeVisible();
});

test("c. the fix of a CIS-S3-001 finding has patches, what was not checked and guardrails", async ({
  page,
  request,
}) => {
  test.setTimeout(5 * 60_000);
  const findings = await getJson<FindingOut[]>(request, "/api/findings");
  const finding = findings.find((f) => f.rule_id === "CIS-S3-001" && isActive(f));
  test.skip(
    !finding,
    "The scan found no open CIS-S3-001 finding, so there is no such fix.",
  );

  await page.goto(`${findingPath(finding!)}?tab=fix`);
  await page.getByRole("button", { name: "Generate fix" }).click();

  await expect(page.getByRole("region", { name: "Patches", exact: true })).toBeVisible({
    timeout: 2 * 60_000,
  });
  const fix = await getJson<FixOut>(
    request,
    `/api/findings/${encodeURIComponent(finding!.finding_id)}/fix`,
  );
  expect(fix.patches.length).toBeGreaterThan(0);
  const patches = page.getByRole("region", { name: "Patches", exact: true });
  await expect(patches).toBeVisible();
  await expect(patches.getByRole("tab")).toHaveCount(fix.patches.length);
  expect(fix.not_checked.length).toBeGreaterThan(0);
  // The first view is short. What was not checked is in full under More detail.
  await page.getByRole("button", { name: /^More detail/ }).click();
  await expect(
    page.getByRole("heading", { name: "CloudShield did not check" }),
  ).toBeVisible();
  // The same words also appear in the explanation, so the first match is enough.
  for (const item of fix.not_checked)
    await expect(page.getByText(item).first()).toBeVisible();
  expect(fix.guardrails.length).toBeGreaterThan(0);
  await expect(
    page.getByRole("region", { name: "Prevent it coming back" }),
  ).toBeVisible();
  // The guardrails CloudShield cannot read are together in one fold.
  const cannotCheck = page.getByRole("button", {
    name: /guardrails? CloudShield cannot check/,
  });
  if ((await cannotCheck.count()) > 0) await cannotCheck.click();
  for (const guardrail of fix.guardrails) {
    await expect(
      page.getByRole("article", { name: guardrail.title, exact: true }),
    ).toBeVisible();
  }
});

test("d. dismissing a finding takes it out of the counts and undoing brings it back", async ({
  page,
  request,
}) => {
  const findings = await getJson<FindingOut[]>(request, "/api/findings");
  const scored = findings
    .filter((f) => isActive(f) && f.risk_score !== null)
    .sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0));
  test.skip(
    scored.length === 0,
    "No open finding has a score, so there is nothing to dismiss.",
  );
  const target = scored[0];
  const band = BAND_OF(target.risk_score ?? 0);
  const before = await overviewNumbers(page);

  await page.goto(findingPath(target));
  await page.getByRole("button", { name: "Dismiss", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel(/Reason/).fill("Dismissed by an automated browser test.");
  await dialog.getByRole("button", { name: "Dismiss finding" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText(/^Dismissed as/)).toBeVisible();

  const during = await overviewNumbers(page);
  expect(during.dismissed, "dismissed count").toBe(before.dismissed + 1);
  expect(during[band], `the ${band} count (the headline, for the Fix now lane)`).toBe(
    before[band] - 1,
  );

  await page.goto(findingPath(target));
  await page.getByRole("button", { name: "Undo dismissal" }).click();
  await expect(page.getByRole("button", { name: "Dismiss", exact: true })).toBeVisible();
  expect(await overviewNumbers(page)).toEqual(before);
});

// Made up for this test: a fake account, fake resources and a made-up check. The suffix makes
// every file different, so it is never taken for one that was imported before.
function syntheticResults(suffix: string): Buffer {
  const entry = (check: string, status: "FAIL" | "PASS") => ({
    message: "synthetic",
    metadata: {
      event_code: check,
      version: "1.5.0",
      product: { name: "Prowler", version: "0.0.0-synthetic" },
    },
    severity: "Low",
    severity_id: 2,
    status: "New",
    status_code: status,
    status_detail: `Synthetic detail for ${check}.`,
    unmapped: { categories: [] },
    finding_info: {
      uid: `synthetic-${check}`,
      title: `Synthetic check ${check}`,
      desc: "A made-up check for a browser test.",
    },
    cloud: { account: { uid: "000000000000" }, region: "us-east-1" },
    remediation: { desc: "Nothing to do. This is test data.", references: [] },
    risk_details: "No risk. This is test data.",
    resources: [
      {
        uid: `arn:aws:s3:::synthetic-${suffix}-${status.toLowerCase()}`,
        region: "us-east-1",
        group: { name: "s3" },
        type: "AwsS3Bucket",
      },
    ],
  });
  const results = [
    entry(`synthetic_fail_${suffix}`, "FAIL"),
    entry(`synthetic_pass_${suffix}`, "PASS"),
  ];
  return Buffer.from(JSON.stringify(results));
}

test("e. a synthetic results file is imported, and the same file again is refused", async ({
  page,
  guard,
}) => {
  const suffix = randomBytes(4).toString("hex");
  const file = {
    name: `synthetic-${suffix}.ocsf.json`,
    mimeType: "application/json",
    buffer: syntheticResults(suffix),
  };
  await page.goto("/scans");
  await page.getByRole("button", { name: "Import a results file" }).click();
  const dialog = page.getByRole("dialog");
  // The file input itself: its label text is also in the name of the Step 2 section.
  const picker = dialog.getByTestId("drop-zone").locator('input[type="file"]');

  await picker.setInputFiles(file);

  // The result line has its own test id: the copy buttons above it also have status elements.
  const result = dialog.getByTestId("import-result");
  await expect(result).toHaveText(/^Imported 1, 1 passed, \d+ resolved$/);

  guard.allowStatus(409);
  await picker.setInputFiles(file);

  await expect(result).toContainText("already imported");
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  const imports = page.getByRole("table", { name: "Imports", exact: true });
  await expect(imports).toContainText(file.name);
  await expect(imports).toContainText("Upload");
});

test("f. Run full scan adds an import made in the dashboard", async ({
  page,
  request,
}) => {
  test.setTimeout(35 * 60_000);
  const status = await getJson<ExtendedStatusOut>(request, "/api/extended/status");
  test.skip(
    !status.available,
    `Run full scan cannot run here: ${[status.reason, status.hint].filter(Boolean).join(" ")}`,
  );
  const [previous] = await getJson<ScanOut[]>(request, "/api/scans");
  const importsBefore = await getJson<ImportOut[]>(request, "/api/imports");
  await page.goto("/");

  await page.getByRole("button", { name: "More ways to scan" }).click();
  await page.getByRole("menuitem", { name: /^Run full scan/ }).click();
  const scan = await waitForScan(request, previous?.id ?? null, 30);

  expect(scan.status, scan.failure_message ?? "the scan failed").toBe("completed");
  expect(scan.extended_status, `${scan.extended_message} ${scan.extended_hint}`).toBe(
    "ok",
  );
  await expect(page.getByText(scan.extended_message ?? "").first()).toBeVisible();
  const importsAfter = await getJson<ImportOut[]>(request, "/api/imports");
  expect(importsAfter.length).toBe(importsBefore.length + 1);
  await page.goto("/scans");
  const newest = page
    .getByRole("table", { name: "Imports", exact: true })
    .getByRole("row")
    .nth(1);
  await expect(newest).toContainText("Dashboard");
});
