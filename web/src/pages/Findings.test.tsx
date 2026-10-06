import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { formatDate } from "../format";
import { applyFilters, FINDINGS_GRID, type Filters } from "./Findings";
import { finding } from "../test/factories";
import { fail } from "../test/mockApi";
import { never, renderApp } from "../test/render";

const ARN = "arn:aws:iam::123456789012:policy/deploy";

const rows = [
  finding({ finding_id: "F-A", title: "Open SSH to the world", risk_score: 95 }),
  finding({
    finding_id: "F-B",
    rule_id: "CIS-S3-001",
    resource_id: "my-bucket",
    resource_type: "S3",
    title: "Public bucket",
    risk_score: 85,
  }),
  finding({
    finding_id: "F-C",
    rule_id: "CIS-IAM-001",
    resource_id: ARN,
    resource_type: "IAM Policy",
    title: "Wildcard policy",
    risk_score: 70,
  }),
  finding({
    finding_id: "F-D",
    rule_id: "CIS-S3-003",
    resource_id: "old-bucket",
    resource_type: "S3",
    title: "No versioning",
    severity: "MEDIUM",
    risk_score: 40,
  }),
  finding({
    finding_id: "F-I",
    rule_id: "CIS-S3-002",
    resource_id: "my-bucket",
    resource_type: "S3",
    title: "Default encryption",
    severity: "INFO",
    risk_score: null,
    risk_factors: [],
  }),
  finding({
    finding_id: "F-R",
    title: "Fixed finding",
    status: "RESOLVED",
    risk_score: 75,
    resolved_at: "2026-10-03T10:00:00Z",
  }),
];

function titles(): string[] {
  return screen
    .getAllByRole("row")
    .slice(1)
    .map((r) => within(r).getAllByRole("link")[0].textContent ?? "");
}

function chip(name: string, count: number): HTMLElement {
  return screen.getByRole("button", { name: new RegExp(`^${name}\\s*${count}$`) });
}

describe("Findings: states", () => {
  it("shows loading while findings are fetched", async () => {
    renderApp("/findings", { "GET /api/findings": never });

    expect(screen.getByText("Loading findings...")).toBeInTheDocument();
    await screen.findByText(/API online/);
  });

  it("shows the backend's message when findings cannot be loaded", async () => {
    renderApp("/findings", { "GET /api/findings": fail(500, "database is locked") });

    expect(await screen.findByRole("alert")).toHaveTextContent("database is locked");
  });

  it("says there are no findings yet, without numbers", async () => {
    renderApp("/findings", { "GET /api/findings": [] });

    expect(await screen.findByText("No findings yet.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^All/ })).not.toBeInTheDocument();
  });
});

describe("Findings: page", () => {
  it("has a heading with the count, and says how many are open and fixed", async () => {
    renderApp("/findings", { "GET /api/findings": rows });

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "6 findings.",
    );
    expect(
      screen.getByText("5 open, 1 fixed. Ordered by what to fix first."),
    ).toBeInTheDocument();
  });

  it("uses the singular for one finding", async () => {
    renderApp("/findings", { "GET /api/findings": [rows[0]] });

    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent(
      "1 finding.",
    );
  });

  it("shows filter chips with their counts, and marks Open as pressed", async () => {
    renderApp("/findings", { "GET /api/findings": rows });

    await screen.findByRole("table");
    expect(chip("Open", 5)).toHaveAttribute("aria-pressed", "true");
    expect(chip("All", 6)).toHaveAttribute("aria-pressed", "false");
    const chips = within(screen.getByRole("group", { name: "Lane" })).getAllByRole(
      "button",
    );
    expect(chips.map((c) => c.textContent?.replace(/\d+$/, ""))).toEqual([
      "Open",
      "Fix now",
      "Next",
      "Later",
      "Done",
      "All",
    ]);
    expect(chip("Fix now", 2)).toHaveAttribute("aria-pressed", "false");
    expect(chip("Next", 1)).toHaveAttribute("aria-pressed", "false");
    expect(chip("Later", 2)).toHaveAttribute("aria-pressed", "false");
    expect(chip("Done", 1)).toHaveAttribute("aria-pressed", "false");
  });

  it("filters by lane when a chip is pressed, and keeps the choice in the URL", async () => {
    const user = renderApp("/findings", { "GET /api/findings": rows });
    await screen.findByRole("table");

    await user.click(chip("Fix now", 2));

    expect(chip("Fix now", 2)).toHaveAttribute("aria-pressed", "true");
    expect(chip("Open", 5)).toHaveAttribute("aria-pressed", "false");
    expect(titles()).toEqual(["Open SSH to the world", "Public bucket"]);
    expect(screen.getByTestId("location")).toHaveTextContent("/findings?lane=now");

    await user.click(chip("Open", 5));

    expect(screen.getByTestId("location")).toHaveTextContent(/^\/findings$/);
    expect(chip("Open", 5)).toHaveAttribute("aria-pressed", "true");
  });

  it("puts a finding with no score in Later, and a resolved finding in Done", async () => {
    const user = renderApp("/findings", { "GET /api/findings": rows });
    await screen.findByRole("table");

    await user.click(chip("Later", 2));
    expect(titles()).toEqual(["No versioning", "Default encryption"]);
    await user.click(chip("Done", 1));

    expect(titles()).toEqual(["Fixed finding"]);
  });

  it("starts from the filters in the link", async () => {
    renderApp("/findings?lane=now&severity=HIGH", { "GET /api/findings": rows });

    await screen.findByRole("table");

    expect(chip("Fix now", 2)).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByLabelText("Severity")).toHaveValue("HIGH");
    expect(titles()).toHaveLength(2);
  });

  it("keeps the other filters in the URL too", async () => {
    const user = renderApp("/findings", { "GET /api/findings": rows });
    await screen.findByRole("table");

    await user.selectOptions(screen.getByLabelText("Severity"), "HIGH");
    await user.type(screen.getByLabelText("Search"), "ssh");

    expect(screen.getByTestId("location")).toHaveTextContent("severity=HIGH");
    expect(screen.getByTestId("location")).toHaveTextContent("q=ssh");
  });

  it("orders by risk score, high to low, with findings that have no score last", async () => {
    renderApp("/findings", { "GET /api/findings": rows });

    await screen.findByRole("table");

    expect(titles()).toEqual([
      "Open SSH to the world",
      "Public bucket",
      "Wildcard policy",
      "No versioning",
      "Default encryption",
    ]);
  });

  it("reverses the order from the Risk heading, keeping findings without a score last", async () => {
    const user = renderApp("/findings", { "GET /api/findings": rows });
    await screen.findByRole("table");

    await user.click(screen.getByRole("button", { name: /Risk/ }));

    expect(titles()).toEqual([
      "No versioning",
      "Wildcard policy",
      "Public bucket",
      "Open SSH to the world",
      "Default encryption",
    ]);
    expect(screen.getByRole("columnheader", { name: /Risk/ })).toHaveAttribute(
      "aria-sort",
      "ascending",
    );
  });

  it("shows each row's lane, score, title, resource, rule, status and a link to the finding", async () => {
    renderApp("/findings", { "GET /api/findings": rows });

    const first = (await screen.findAllByRole("row"))[1];
    const cells = within(first).getAllByRole("cell");
    expect(first).toHaveAttribute("data-lane", "now");
    expect(within(cells[0]).getByText("Fix now")).toBeInTheDocument();
    expect(cells[1]).toHaveTextContent("95");
    expect(
      within(first).getByRole("link", { name: "Open SSH to the world" }),
    ).toHaveAttribute("href", "/findings/F-A");
    expect(within(first).getByText("CIS-SG-001")).toBeInTheDocument();
    expect(within(first).getByText("Open")).toBeInTheDocument();
  });

  it("shows resolved findings as Resolved and shortens ARNs, keeping the full value in the title", async () => {
    const user = renderApp("/findings", { "GET /api/findings": rows });
    await screen.findByRole("table");
    await user.click(chip("All", 6));
    const done = screen
      .getByRole("link", { name: "Fixed finding" })
      .closest("[role=row]");
    expect(within(done as HTMLElement).getByText("Resolved")).toBeInTheDocument();
    expect(screen.getByText("...:policy/deploy")).toHaveAttribute("title", ARN);
  });

  it("shows INFO findings in dim text, with no score", async () => {
    renderApp("/findings", { "GET /api/findings": rows });

    const info = (
      await screen.findByRole("link", { name: "Default encryption" })
    ).closest("[role=row]") as HTMLElement;
    const high = screen
      .getByRole("link", { name: "Open SSH to the world" })
      .closest("[role=row]") as HTMLElement;
    expect(info).toHaveAttribute("data-muted", "true");
    expect(within(info).getAllByRole("cell")[1]).toHaveTextContent("-");
    expect(high).toHaveAttribute("data-muted", "false");
  });

  it("puts the table in a scrolling box with a sticky header and a minimum width", async () => {
    renderApp("/findings", { "GET /api/findings": rows });

    const table = await screen.findByRole("table");

    expect(table).toHaveClass("min-w-[900px]");
    expect(table.parentElement).toHaveClass("overflow-auto");
    expect(table.parentElement).toHaveClass("max-h-[75vh]");
    expect(table.parentElement).toHaveClass("border-2");
    expect(screen.getByTestId("findings-header")).toHaveClass("sticky");
    expect(screen.getByTestId("findings-header")).toHaveClass("top-0");
  });

  it("gives the header and every row the same grid, so the columns line up", async () => {
    renderApp("/findings", { "GET /api/findings": rows });

    const header = await screen.findByTestId("findings-header");
    const body = screen.getAllByRole("row").slice(1);

    expect(FINDINGS_GRID).toContain(
      "grid-cols-[20px_88px_minmax(0,1fr)_200px_112px_120px_28px]",
    );
    expect(header.className).toContain(FINDINGS_GRID);
    expect(body.length).toBe(5);
    for (const r of body) expect(r.className).toContain(FINDINGS_GRID);
  });

  it("marks the sort column with aria-sort, and only that one, and never wraps the heading", async () => {
    const user = renderApp("/findings", { "GET /api/findings": rows });
    await screen.findByRole("table");
    const risk = screen.getByRole("columnheader", { name: /Risk/ });
    const seen = screen.getByRole("columnheader", { name: /Last seen/ });

    expect(risk).toHaveAttribute("aria-sort", "descending");
    expect(seen).toHaveAttribute("aria-sort", "none");
    expect(within(seen).getByRole("button")).toHaveClass("whitespace-nowrap");

    await user.click(within(seen).getByRole("button"));

    expect(seen).toHaveAttribute("aria-sort", "descending");
    expect(risk).toHaveAttribute("aria-sort", "none");
  });

  it("shows last seen as a relative time with the full date as its tooltip", async () => {
    renderApp("/findings", { "GET /api/findings": rows });

    const first = (await screen.findAllByRole("row"))[1];
    const seen = within(first).getAllByRole("cell")[5];

    expect(seen).toHaveAttribute("title", formatDate("2026-10-01T10:00:42Z"));
    expect(seen.textContent).toMatch(/ago|just now|yesterday|in /);
  });

  it("uses styled selects with a chevron icon, 44px tall, and 13px labels", async () => {
    renderApp("/findings", { "GET /api/findings": rows });
    await screen.findByRole("table");

    for (const name of ["Severity", "Rule", "Resource type"]) {
      const select = screen.getByLabelText(name);
      expect(select).toHaveClass("styled-select");
      expect(select).toHaveClass("h-11");
      expect(select).toHaveClass("border-[1.5px]");
      expect(
        select.parentElement?.querySelector('svg[data-icon="chevron"]'),
      ).not.toBeNull();
      expect(select.closest("label")).toHaveClass("text-label");
    }
  });

  it("shows Clear filters only while a filter is set, and clears them", async () => {
    const user = renderApp("/findings?q=bucket", { "GET /api/findings": rows });
    await screen.findByRole("table");

    await user.click(screen.getByRole("button", { name: "Clear filters" }));

    expect(
      screen.queryByRole("button", { name: "Clear filters" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Showing 5 of/)).toBeInTheDocument();
  });

  it("shows lane chips with counts and aria-pressed", async () => {
    renderApp("/findings", { "GET /api/findings": rows });
    await screen.findByRole("table");
    const chips = within(screen.getByRole("group", { name: "Lane" }));

    expect(chips.getByRole("button", { name: /^Open/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(chips.getByRole("button", { name: /^Fix now\s*2$/ })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
  });

  it("shows only open findings by default, and says how many are shown", async () => {
    renderApp("/findings", { "GET /api/findings": rows });

    await screen.findByRole("table");

    expect(titles()).toHaveLength(5);
    expect(titles()).not.toContain("Fixed finding");
    expect(screen.getByText("Showing 5 of 6 findings")).toBeInTheDocument();
  });

  it("treats an address with no lane as Open", async () => {
    renderApp("/findings?severity=HIGH", { "GET /api/findings": rows });

    await screen.findByRole("table");

    expect(chip("Open", 5)).toHaveAttribute("aria-pressed", "true");
    expect(titles()).toHaveLength(3);
    expect(titles()).not.toContain("Fixed finding");
  });

  it("shows every finding under All, with resolved findings after every open one", async () => {
    const user = renderApp("/findings", { "GET /api/findings": rows });
    await screen.findByRole("table");

    await user.click(chip("All", 6));

    expect(chip("All", 6)).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("location")).toHaveTextContent("/findings?lane=all");
    expect(titles()).toEqual([
      "Open SSH to the world",
      "Public bucket",
      "Wildcard policy",
      "No versioning",
      "Default encryption",
      "Fixed finding",
    ]);
  });

  it("keeps resolved findings last under All when the order is reversed", async () => {
    const user = renderApp("/findings?lane=all", { "GET /api/findings": rows });
    await screen.findByRole("table");

    await user.click(screen.getByRole("button", { name: /Risk/ }));

    expect(titles()).toEqual([
      "No versioning",
      "Wildcard policy",
      "Public bucket",
      "Open SSH to the world",
      "Default encryption",
      "Fixed finding",
    ]);
  });

  it("filters by severity, rule and resource type", async () => {
    const user = renderApp("/findings", { "GET /api/findings": rows });
    await screen.findByRole("table");

    await user.selectOptions(screen.getByLabelText("Severity"), "INFO");
    expect(titles()).toEqual(["Default encryption"]);
    await user.selectOptions(screen.getByLabelText("Severity"), "");
    await user.selectOptions(screen.getByLabelText("Rule"), "CIS-S3-001");
    expect(titles()).toEqual(["Public bucket"]);
    await user.selectOptions(screen.getByLabelText("Rule"), "");
    await user.selectOptions(screen.getByLabelText("Resource type"), "IAM Policy");

    expect(titles()).toEqual(["Wildcard policy"]);
  });

  it("searches title, rule and resource, and says when nothing matches", async () => {
    const user = renderApp("/findings", { "GET /api/findings": rows });
    await screen.findByRole("table");

    await user.type(screen.getByLabelText("Search"), "old-bucket");
    expect(titles()).toEqual(["No versioning"]);
    await user.clear(screen.getByLabelText("Search"));
    await user.type(screen.getByLabelText("Search"), "nothing like this");

    expect(
      await screen.findByText("No findings match these filters"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByRole("table")).toBeInTheDocument();
  });
});

describe("applyFilters", () => {
  const all: Filters = {
    q: "",
    severity: "",
    lane: "all",
    rule: "",
    type: "",
    sort: "risk",
    order: "desc",
  };

  it("sorts by risk score and keeps findings without a score last in both directions", () => {
    const descending = applyFilters(rows, all).map((r) => r.risk_score);
    const ascending = applyFilters(rows, { ...all, order: "asc" }).map(
      (r) => r.risk_score,
    );

    // Open findings first, then the resolved one, which had a higher score than some.
    expect(descending).toEqual([95, 85, 70, 40, null, 75]);
    expect(ascending).toEqual([40, 70, 85, 95, null, 75]);
  });

  it("shows only open findings for the open filter", () => {
    const titles = applyFilters(rows, { ...all, lane: "open" }).map((r) => r.title);

    expect(titles).not.toContain("Fixed finding");
    expect(titles).toHaveLength(5);
  });

  it("filters by lane at the thresholds", () => {
    const edge = [79, 80, 59, 60].map((score) =>
      finding({ finding_id: `F-${score}`, risk_score: score }),
    );

    const names = (lane: "now" | "next" | "later") =>
      applyFilters(edge, { ...all, lane }).map((r) => r.risk_score);

    expect(names("now")).toEqual([80]);
    expect(names("next")).toEqual([79, 60]);
    expect(names("later")).toEqual([59]);
  });
});
