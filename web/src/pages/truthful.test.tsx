import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { FindingOut } from "../api";
import { formatDate } from "../format";
import { countLanes, inLane, isActive } from "../lanes";
import { finding, findingDetail, fix, scan } from "../test/factories";
import { callsTo, fail, networkDown } from "../test/mockApi";
import { renderApp } from "../test/render";

const ID = "F-OWN";
const IMPORTED_ID = "F-PRW-x";
const REASON = "AWS owns this policy.";

const own = finding({ finding_id: ID, title: "Public bucket", risk_score: 85 });

function many(count: number, score: number, overrides: Partial<FindingOut> = {}) {
  return Array.from({ length: count }, (_, i) =>
    finding({
      finding_id: `F-${score}-${i}`,
      title: `Finding ${score}-${i}`,
      risk_score: score - i / 10,
      resource_id: `res-${score}-${i}`,
      ...overrides,
    }),
  );
}

function row(name: string): HTMLElement {
  return screen.getByText(name).closest("[role=row]") as HTMLElement;
}

describe("lane rule", () => {
  const rows = [
    finding({ finding_id: "a", risk_score: 90 }),
    finding({ finding_id: "b", risk_score: 90, dismissed: true }),
    finding({ finding_id: "c", risk_score: 90, merged_into: "a" }),
    finding({ finding_id: "d", risk_score: 65 }),
    finding({ finding_id: "e", risk_score: null, severity: "INFO" }),
    finding({ finding_id: "f", risk_score: 90, status: "RESOLVED" }),
  ];

  it("leaves dismissed, merged and unscored findings out of the lanes", () => {
    expect(inLane(rows, "now").map((r) => r.finding_id)).toEqual(["a"]);
    expect(inLane(rows, "next").map((r) => r.finding_id)).toEqual(["d"]);
    expect(inLane(rows, "later")).toEqual([]);
    expect(inLane(rows, "done").map((r) => r.finding_id)).toEqual(["f"]);
  });

  it("makes the counts equal to what the lanes hold", () => {
    expect(countLanes(rows)).toEqual({ now: 1, next: 1, later: 0, done: 1 });
  });

  it("calls a finding active only when open, not dismissed and not merged", () => {
    expect(rows.filter(isActive).map((r) => r.finding_id)).toEqual(["a", "d", "e"]);
  });
});

describe("Overview: headline and counts", () => {
  const rows = [
    ...many(2, 90),
    ...many(1, 70, { source: "prowler" }),
    finding({ finding_id: "i", severity: "INFO", risk_score: null, title: "Info" }),
    finding({ finding_id: "x", dismissed: true, title: "Dismissed one" }),
    finding({ finding_id: "m", merged_into: "F-90-0", title: "Merged one" }),
    finding({ finding_id: "r", status: "RESOLVED", title: "Fixed one" }),
  ];
  const routes = { "GET /api/scans": [scan()], "GET /api/findings": rows };

  it("counts to go without informational, dismissed or merged findings", async () => {
    renderApp("/", routes);

    const headline = await screen.findByRole("heading", { level: 1 });

    expect(within(headline).getByText("3 to go.")).toBeInTheDocument();
    expect(within(headline).getByText("1 fixed.")).toBeInTheDocument();
  });

  it("splits them by source, informational and dismissed, in one line", async () => {
    renderApp("/", routes);

    const line = await screen.findByTestId("source-counts");

    expect(line).toHaveTextContent(
      "2 found by CloudShield, 1 imported, 1 informational, 1 dismissed",
    );
  });

  it("links each part to the Findings filter that shows exactly those findings", async () => {
    renderApp("/", routes);

    const line = await screen.findByTestId("source-counts");
    const links = within(line).getAllByRole("link");

    expect(links.map((l) => l.getAttribute("href"))).toEqual([
      "/findings?source=cloudshield&info=hide",
      "/findings?source=prowler&info=hide",
      "/findings?info=only",
      "/findings?lane=dismissed",
    ]);
  });

  it("makes each link open a list as long as the number it was clicked on", async () => {
    const all = { ...routes, "GET /api/findings": rows };
    for (const [path, shown] of [
      ["/findings?source=cloudshield&info=hide", "Showing 2 of 7"],
      ["/findings?source=prowler&info=hide", "Showing 1 of 7"],
      ["/findings?info=only", "Showing 1 of 7"],
      ["/findings?lane=dismissed", "Showing 1 of 7"],
    ]) {
      const { unmount } = renderApp(path, all) as unknown as { unmount?: () => void };
      expect(await screen.findByText(new RegExp(shown))).toBeInTheDocument();
      unmount?.();
      document.body.innerHTML = "";
    }
  });

  it("shows the same number in a lane header, its tiles and its See all link", async () => {
    renderApp("/", {
      ...routes,
      "GET /api/findings": [...many(8, 90), ...many(2, 90, { dismissed: true })],
    });

    const lane = await screen.findByRole("region", { name: "Fix now" });

    expect(
      within(lane).getByRole("heading", { name: "Fix now" }).nextElementSibling,
    ).toHaveTextContent("8");
    expect(within(lane).getAllByRole("heading", { level: 3 })).toHaveLength(5);
    expect(within(lane).getByRole("link", { name: /See all 8/ })).toHaveAttribute(
      "href",
      "/findings?lane=now",
    );
  });

  it("opens a Findings list for See all with as many findings as the lane count", async () => {
    renderApp("/findings?lane=now", {
      "GET /api/findings": [...many(8, 90), ...many(2, 90, { dismissed: true })],
    });

    expect(await screen.findByText(/Showing 8 of 10 findings/)).toBeInTheDocument();
  });
});

describe("Findings: chips for merged and disputed findings", () => {
  const confirmed = finding({
    finding_id: "F-C",
    title: "Confirmed finding",
    corroborated_by: [
      {
        source: "prowler",
        check_id: "c",
        status: "FAIL",
        last_imported_at: "2026-10-05T04:42:00Z",
      },
    ],
  });
  const oursOpen = finding({
    finding_id: "F-D",
    title: "Ours is open",
    tools_disagree: true,
    corroborated_by: [
      {
        source: "prowler",
        check_id: "c",
        status: "PASS",
        last_imported_at: "2026-10-05T04:42:00Z",
      },
    ],
  });
  const theirsOpen = finding({
    finding_id: "F-T",
    title: "Theirs fails",
    source: "prowler",
    tools_disagree: true,
  });
  const routes = { "GET /api/findings": [confirmed, oursOpen, theirsOpen] };

  it("shows Confirmed by 2 tools when another scan reports the same failure", async () => {
    renderApp("/findings", routes);
    await screen.findByRole("table");

    expect(
      within(row("Confirmed finding")).getByText("Confirmed by 2 tools"),
    ).toBeInTheDocument();
    expect(within(row("Ours is open")).queryByText("Confirmed by 2 tools")).toBeNull();
  });

  it("shows Tools disagree with both results when ours is open and the import passes", async () => {
    renderApp("/findings", routes);
    await screen.findByRole("table");

    const ours = row("Ours is open");

    expect(within(ours).getByText("Tools disagree")).toBeInTheDocument();
    expect(
      within(ours).getByText("CloudShield: open. Imported scan: passed."),
    ).toBeInTheDocument();
  });

  it("shows both results when the import fails and ours has no open finding", async () => {
    renderApp("/findings", routes);
    await screen.findByRole("table");

    expect(
      within(row("Theirs fails")).getByText(
        "CloudShield: no open finding. Imported scan: failed.",
      ),
    ).toBeInTheDocument();
  });

  it("shows the same chips on the finding page", async () => {
    renderApp(`/findings/${ID}`, {
      [`GET /api/findings/${ID}`]: findingDetail({ ...oursOpen, finding_id: ID }),
    });

    expect(await screen.findByText("Tools disagree")).toBeInTheDocument();
    expect(
      screen.getByText("CloudShield: open. Imported scan: passed."),
    ).toBeInTheDocument();
  });
});

describe("Finding page: an imported finding", () => {
  const path = `/api/findings/${IMPORTED_ID}`;
  const imported = findingDetail({
    finding_id: IMPORTED_ID,
    rule_id: "PRW-iam_x",
    source: "prowler",
    title: "Password policy is weak",
    last_scan_id: null,
    resource: null,
    evidence: {
      items: [
        {
          fact: "Failing statement",
          value: "Too short.",
          source: "imported scan output",
          certainty: "reported",
        },
        {
          fact: "Resource",
          value: { type: "Account" },
          source: "imported scan output",
          certainty: "reported",
        },
      ],
    },
  });
  const importedFix = fix({
    finding_id: IMPORTED_ID,
    patches: [],
    guidance: ["Set the minimum length to 14.", "Reference: https://example.com/c"],
    blast_radius: {
      level: "unknown",
      factors: [],
      notes: ["Nothing is known about dependents."],
    },
    generated_by: "template",
    model: null,
  });
  const routes = { [`GET ${path}`]: imported, [`POST ${path}/fix`]: importedFix };

  it("starts the Fix tab with the line saying there is no patch", async () => {
    renderApp(`/findings/${IMPORTED_ID}?tab=fix`, routes);

    const line = await screen.findByText(
      "No patch for this finding. This is guidance from an imported scan.",
    );
    const card = line.closest("section") as HTMLElement;

    expect(card.querySelector("h2")?.nextElementSibling).toBe(line);
  });

  it("shows the guidance and links, an unknown blast radius with its note, and how to check", async () => {
    const user = renderApp(`/findings/${IMPORTED_ID}?tab=fix`, routes);

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    await screen.findByText("Set the minimum length to 14.");
    expect(
      screen.getByRole("link", { name: "https://example.com/c" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Nothing is known about dependents.")).toBeInTheDocument();
    expect(
      screen.getByText(/Run the scan again, then import the new file/),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Rescan/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Verify" })).not.toBeInTheDocument();
  });

  it("shows every evidence item with a Reported chip and the line saying it is not verified", async () => {
    renderApp(`/findings/${IMPORTED_ID}?tab=evidence`, routes);

    const panel = await screen.findByRole("tabpanel");
    const chips = panel.querySelectorAll('[data-certainty="reported"]');

    expect(chips).toHaveLength(2);
    for (const chip of chips) {
      expect(chip).toHaveClass("capitalize");
      expect(chip.querySelector('svg[data-icon="external"]')).not.toBeNull();
    }
    expect(
      within(panel).getByText(
        "Reported by an imported scan, not verified by CloudShield.",
      ),
    ).toBeInTheDocument();
  });

  it("does not say reported-by-import on the evidence of our own finding", async () => {
    renderApp(`/findings/${ID}?tab=evidence`, {
      [`GET /api/findings/${ID}`]: findingDetail({ finding_id: ID }),
    });

    await screen.findByRole("tabpanel");

    expect(screen.queryByText(/Reported by an imported scan/)).not.toBeInTheDocument();
  });
});

describe("Finding page: dismissing", () => {
  const path = `/api/findings/${ID}`;
  const detail = findingDetail({ finding_id: ID, title: "Public bucket" });
  const dismissed = findingDetail({
    finding_id: ID,
    dismissed: true,
    disposition: "accepted",
    disposition_reason: "We accept this for the test bucket.",
    disposition_at: "2026-10-05T04:42:00Z",
    disposition_until: "2026-12-01T23:59:59Z",
  });

  async function open(routes: Record<string, unknown> = {}) {
    const user = renderApp(`/findings/${ID}`, { [`GET ${path}`]: detail, ...routes });
    await user.click(await screen.findByRole("button", { name: "Dismiss" }));
    return user;
  }

  it("offers Dismiss on an open finding and not on a resolved one", async () => {
    renderApp(`/findings/${ID}`, {
      [`GET ${path}`]: findingDetail({ finding_id: ID, status: "RESOLVED" }),
    });

    await screen.findByRole("heading", { level: 1 });

    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
  });

  it("opens a dialog that needs a reason of 10 characters or more", async () => {
    const user = await open();
    const dialog = screen.getByRole("dialog");
    const submit = within(dialog).getByRole("button", { name: "Dismiss finding" });

    expect(submit).toBeDisabled();
    expect(
      within(dialog).getByText(/At least 10 characters. 0 so far./),
    ).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText(/Reason/), "too short");
    expect(submit).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Reason/), " and now long enough");

    expect(submit).toBeEnabled();
    expect(callsTo("PATCH", `${path}/disposition`)).toHaveLength(0);
  });

  it("counts only the characters that are not blank at the ends", async () => {
    const user = await open();
    const dialog = screen.getByRole("dialog");

    await user.type(within(dialog).getByLabelText(/Reason/), "     ab     ");

    expect(
      within(dialog).getByRole("button", { name: "Dismiss finding" }),
    ).toBeDisabled();
  });

  it("sends the reason, the kind and the optional review date, then refreshes", async () => {
    let reads = 0;
    const user = await open({
      [`GET ${path}`]: () => (++reads === 1 ? detail : dismissed),
      [`PATCH ${path}/disposition`]: dismissed,
    });
    const dialog = screen.getByRole("dialog");

    await user.click(within(dialog).getByLabelText("Not applicable"));
    await user.type(
      within(dialog).getByLabelText(/Reason/),
      "  The bucket is a test one.  ",
    );
    await user.type(within(dialog).getByLabelText(/Review date/), "2030-01-31");
    await user.click(within(dialog).getByRole("button", { name: "Dismiss finding" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    const [call] = callsTo("PATCH", `${path}/disposition`);
    expect(call.body).toEqual({
      disposition: "not_applicable",
      disposition_reason: "The bucket is a test one.",
      disposition_until: "2030-01-31",
    });
    expect(await screen.findByText(/Reason: We accept this/)).toBeInTheDocument();
    expect(screen.getByText("Dismissed")).toBeInTheDocument();
  });

  it("sends no review date when the field is left empty", async () => {
    const user = await open({ [`PATCH ${path}/disposition`]: dismissed });

    await user.type(screen.getByLabelText(/Reason/), "Accepted for a while.");
    await user.click(screen.getByRole("button", { name: "Dismiss finding" }));

    await waitFor(() => expect(callsTo("PATCH", `${path}/disposition`)).toHaveLength(1));
    expect(callsTo("PATCH", `${path}/disposition`)[0].body).toMatchObject({
      disposition: "accepted",
      disposition_until: null,
    });
  });

  it("shows the backend's message when it refuses, and keeps the dialog open", async () => {
    const user = await open({
      [`PATCH ${path}/disposition`]: fail(409, "Only an open finding can be dismissed."),
    });

    await user.type(screen.getByLabelText(/Reason/), "Long enough reason.");
    await user.click(screen.getByRole("button", { name: "Dismiss finding" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Only an open finding can be dismissed.",
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("closes with Cancel or Escape and sends nothing", async () => {
    const user = await open();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Dismiss" }));
    await user.keyboard("{Escape}");

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(callsTo("PATCH", `${path}/disposition`)).toHaveLength(0);
  });

  it("shows a dismissed finding with its reason, its review date and a way back", async () => {
    let reads = 0;
    const user = renderApp(`/findings/${ID}`, {
      [`GET ${path}`]: () => (++reads === 1 ? dismissed : detail),
      [`DELETE ${path}/disposition`]: detail,
    });

    expect(await screen.findByText(/Dismissed as accepted risk/)).toHaveTextContent(
      formatDate("2026-12-01T23:59:59Z"),
    );
    expect(screen.getByText(/We accept this for the test bucket/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Undo dismissal" }));

    expect(await screen.findByRole("button", { name: "Dismiss" })).toBeInTheDocument();
    expect(callsTo("DELETE", `${path}/disposition`)).toHaveLength(1);
  });

  it("shows a suggestion that only opens the dialog, and sends nothing by itself", async () => {
    const user = renderApp(`/findings/${ID}`, {
      [`GET ${path}`]: findingDetail({
        finding_id: ID,
        suggested_not_applicable: { reason: "This is an AWS-managed policy." },
      }),
      [`PATCH ${path}/disposition`]: dismissed,
    });

    const banner = await screen.findByRole("note");

    expect(banner).toHaveTextContent(
      "This is an AWS-managed policy. Dismiss as not applicable?",
    );
    expect(callsTo("PATCH", `${path}/disposition`)).toHaveLength(0);
    await user.click(within(banner).getByRole("button", { name: "Review and dismiss" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("Not applicable")).toBeChecked();
    expect(
      within(dialog).getByRole("button", { name: "Dismiss finding" }),
    ).toBeDisabled();
    expect(callsTo("PATCH", `${path}/disposition`)).toHaveLength(0);
  });

  it("shows no suggestion banner when there is none", async () => {
    renderApp(`/findings/${ID}`, { [`GET ${path}`]: detail });

    await screen.findByRole("heading", { level: 1 });

    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });
});

describe("Findings: dismissed filter", () => {
  const gone = finding({
    finding_id: "F-G",
    title: "Hidden for now",
    dismissed: true,
    disposition: "not_applicable",
    disposition_reason: REASON,
  });
  const routes = { "GET /api/findings": [own, gone] };

  it("keeps dismissed findings out of the default list and the Open count", async () => {
    renderApp("/findings", routes);

    await screen.findByRole("table");

    expect(screen.queryByText("Hidden for now")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Open\s*1$/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Dismissed\s*1$/ })).toBeInTheDocument();
  });

  it("lists them under Dismissed with a chip and the reason", async () => {
    const user = renderApp("/findings", routes);
    await screen.findByRole("table");

    await user.click(screen.getByRole("button", { name: /^Dismissed/ }));

    const dismissedRow = row("Hidden for now");
    expect(within(dismissedRow).getByText("Dismissed")).toBeInTheDocument();
    expect(
      within(dismissedRow).getByText(/Not applicable: AWS owns this policy/),
    ).toBeInTheDocument();
    expect(screen.queryByText("Public bucket")).not.toBeInTheDocument();
  });

  it("shows them under All as well", async () => {
    renderApp("/findings?lane=all", routes);

    expect(await screen.findByText("Hidden for now")).toBeInTheDocument();
    expect(screen.getByText("Public bucket")).toBeInTheDocument();
  });
});

describe("Findings: table grid and grouping", () => {
  const routes = {
    "GET /api/findings": [
      finding({
        finding_id: "1",
        rule_id: "PRW-a_check",
        resource_id: "res-1",
        title: "Failing one",
        details: { check_title: "The check" },
      }),
      finding({
        finding_id: "2",
        rule_id: "PRW-a_check",
        resource_id: "res-2",
        title: "Failing two",
        risk_score: 40,
        details: { check_title: "The check" },
      }),
      finding({ finding_id: "3", rule_id: "CIS-S3-001", title: "Alone", risk_score: 30 }),
    ],
  };

  it("puts every header cell in the grid, so the rule ids sit under the Rule header", async () => {
    renderApp("/findings", routes);

    const header = await screen.findByTestId("findings-header");
    const cells = within(header).getAllByRole("columnheader");

    expect(cells).toHaveLength(7);
    for (const cell of cells) expect(cell).not.toHaveClass("sr-only");
    expect(header.className).toContain("240px");
    expect(header.className).toContain("minmax(0,1fr)");
    const body = screen.getAllByRole("row")[1];
    expect(within(body).getAllByRole("cell", { hidden: true })).toHaveLength(
      cells.length,
    );
    expect(within(cells[3]).getByText("Rule")).toBeInTheDocument();
    expect(within(body).getAllByRole("cell")[3]).toHaveTextContent("a_check");
  });

  it("is not grouped until the toggle is pressed", async () => {
    renderApp("/findings", routes);

    await screen.findByRole("table");

    expect(screen.getByRole("button", { name: "Group by check" })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
    expect(screen.getByText("Failing one")).toBeInTheDocument();
  });

  it("collapses a repeated check into one row with a count, and expands to its resources", async () => {
    const user = renderApp("/findings", routes);
    await screen.findByRole("table");

    await user.click(screen.getByRole("button", { name: "Group by check" }));

    expect(screen.getByTestId("location")).toHaveTextContent("group=check");
    const group = screen.getByText("The check").closest("[role=row]") as HTMLElement;
    expect(within(group).getByText("2 resources")).toBeInTheDocument();
    expect(within(group).getByText("a_check")).toBeInTheDocument();
    expect(screen.queryByText("Failing one")).not.toBeInTheDocument();
    expect(screen.getByText("Alone")).toBeInTheDocument();

    const toggle = within(group).getByRole("button", { name: /Show the 2 resources/ });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("Failing one")).toBeInTheDocument();
    expect(screen.getByText("Failing two")).toBeInTheDocument();
  });

  it("opens already grouped from the link", async () => {
    renderApp("/findings?group=check", routes);

    expect(await screen.findByText("2 resources")).toBeInTheDocument();
  });

  it("keeps a long rule id on one line with the full value in a title", async () => {
    const long = "iam_password_policy_expires_passwords_within_90_days_or_less";
    renderApp("/findings", {
      "GET /api/findings": [finding({ rule_id: `PRW-${long}` })],
    });

    const tag = await screen.findByTitle(long);

    expect(tag).toHaveClass("truncate");
  });
});

describe("Resources: seen only in imports", () => {
  const imported = [
    {
      resource_id: "arn:aws:iam::123456789012:policy/x",
      resource_type: "IAM Policy",
      region: null,
      open_count: 2,
      highest_risk: 70,
    },
    {
      resource_id: "sg-9",
      resource_type: "Security Group",
      region: "ap-southeast-2",
      open_count: 0,
      highest_risk: null,
    },
  ];

  it("shows a second section labelled as not scanned by CloudShield", async () => {
    renderApp("/resources", {
      "GET /api/resources": [],
      "GET /api/findings": [],
      "GET /api/resources/imported": imported,
    });

    const section = await screen.findByRole("region", { name: "Seen only in imports" });

    expect(within(section).getByText("Not scanned by CloudShield.")).toBeInTheDocument();
    const header = within(section).getByTestId("imported-resources-header");
    expect(
      within(header)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual(["Resource", "Type", "Region", "Open findings", "Highest risk"]);
    const first = within(section).getAllByRole("row")[1];
    expect(first).toHaveTextContent("...:policy/x");
    expect(first).toHaveTextContent("IAM Policy");
    expect(first).toHaveTextContent("global");
    expect(first).toHaveTextContent("70");
    const second = within(section).getAllByRole("row")[2];
    expect(second).toHaveTextContent("ap-southeast-2");
  });

  it("says so when there are none, and shows the backend's message when it cannot load", async () => {
    renderApp("/resources", {
      "GET /api/resources": [],
      "GET /api/findings": [],
      "GET /api/resources/imported": fail(500, "imports exploded"),
    });

    const section = await screen.findByRole("region", { name: "Seen only in imports" });

    expect(await within(section).findByRole("alert")).toHaveTextContent(
      "imports exploded",
    );
  });
});

describe("Scans: imports", () => {
  it("shows a table of imports with the file, version, time, counts and results", async () => {
    renderApp("/scans", {
      "GET /api/scans": [scan()],
      "GET /api/imports": [
        {
          id: 2,
          file_name: "second.json",
          tool_name: "X",
          tool_version: "5.44.0",
          imported_at: "2026-10-05T04:42:00Z",
          pass_count: 15,
          fail_count: 25,
          findings_added: 20,
          already_seen: 5,
          resolved: 3,
          rejected: 1,
          ignored: 0,
          regions_covered: ["ap-southeast-2"],
        },
        {
          id: 1,
          file_name: null,
          tool_name: null,
          tool_version: null,
          imported_at: "2026-10-01T04:42:00Z",
          pass_count: null,
          fail_count: null,
          findings_added: 4,
          already_seen: 0,
          resolved: 0,
          rejected: 0,
          ignored: 0,
          regions_covered: [],
        },
      ],
    });

    const section = await screen.findByRole("region", { name: "Imports" });
    const header = within(section).getByTestId("imports-header");

    expect(
      within(header)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual([
      "File",
      "Version",
      "Imported",
      "Pass",
      "Fail",
      "Added",
      "Resolved",
      "Rejected",
    ]);
    const [, newest, oldest] = within(section).getAllByRole("row");
    const cells = within(newest)
      .getAllByRole("cell")
      .map((c) => c.textContent);
    expect(cells[0]).toBe("second.json");
    expect(cells[1]).toBe("5.44.0");
    expect(cells[2]).toContain(formatDate("2026-10-05T04:42:00Z"));
    expect(cells.slice(3)).toEqual(["15", "25", "20", "3", "1"]);
    expect(
      within(oldest)
        .getAllByRole("cell")
        .map((c) => c.textContent)
        .slice(0, 2),
    ).toEqual(["-", "-"]);
  });

  it("says when nothing was imported", async () => {
    renderApp("/scans", { "GET /api/scans": [scan()] });

    expect(await screen.findByText("No file has been imported yet")).toBeInTheDocument();
  });
});

describe("Header: API status", () => {
  function health(failures: number) {
    let calls = 0;
    return () =>
      ++calls <= failures ? networkDown() : { status: "ok", version: "1.2.3" };
  }

  it("does not say offline after one failed check", async () => {
    let calls = 0;
    renderApp("/scans", {
      "GET /api/health": () => {
        calls += 1;
        return calls === 1 ? networkDown() : { status: "ok", version: "1.2.3" };
      },
    });

    expect(await screen.findByText("API online v1.2.3")).toBeInTheDocument();
    expect(screen.queryByText("API offline")).not.toBeInTheDocument();
  });

  it("says offline after two failed checks in a row", async () => {
    renderApp("/scans", { "GET /api/health": networkDown() });

    expect(await screen.findByText("API offline")).toBeInTheDocument();
    expect(callsTo("GET", "/api/health").length).toBeGreaterThanOrEqual(2);
  });

  it("goes back to online on the first success", async () => {
    renderApp("/scans", { "GET /api/health": health(2) });

    await screen.findByText("API offline");

    expect(await screen.findByText("API online v1.2.3")).toBeInTheDocument();
  });
});
