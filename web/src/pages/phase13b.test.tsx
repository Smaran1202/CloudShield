import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { finding } from "../test/factories";
import { renderApp } from "../test/render";

const row = (id: string, overrides = {}) =>
  finding({ finding_id: id, title: `Finding ${id}`, ...overrides });

// To do 3 (now 2, next 1), Later 3, Done 1, Dismissed 1, informational 1.
const rows = [
  row("A", { risk_score: 95 }),
  row("B", { rule_id: "CIS-S3-001", risk_score: 85 }),
  row("C", { rule_id: "CIS-IAM-001", risk_score: 70 }),
  row("D1", { rule_id: "CIS-S3-003", severity: "MEDIUM", risk_score: 40 }),
  row("D2", { rule_id: "CIS-S3-003", severity: "MEDIUM", risk_score: 40 }),
  row("E", { rule_id: "CIS-SG-002", risk_score: 30 }),
  row("I", {
    rule_id: "CIS-S3-002",
    severity: "INFO",
    risk_score: null,
    risk_factors: [],
  }),
  row("R", { status: "RESOLVED", risk_score: 75 }),
  row("X", { dismissed: true, risk_score: 65 }),
];
const routes = { "GET /api/findings": rows };

const listLength = () =>
  within(screen.getByRole("table", { name: "Findings" })).getAllByRole("row").length - 1;
const tab = (name: string) =>
  within(screen.getByRole("group", { name: "Lane" })).getByRole("button", {
    name: new RegExp(`^${name}\\s*\\d+$`),
  });
const pressed = () =>
  within(screen.getByRole("group", { name: "Lane" }))
    .getAllByRole("button")
    .filter((b) => b.getAttribute("aria-pressed") === "true")
    .map((b) => b.textContent?.replace(/\d+$/, ""));

describe("Findings tabs", () => {
  it("has a tab for each non-empty view, and each tab's count is the length of its list", async () => {
    const user = renderApp("/findings", routes);
    await screen.findByRole("table", { name: "Findings" });

    for (const [name, count] of [
      ["To do", 3],
      ["Later", 3],
      ["Done", 1],
      ["Dismissed", 1],
    ] as const) {
      await user.click(tab(name));
      expect(tab(name)).toHaveTextContent(String(count));
      expect(listLength()).toBe(count);
      expect(pressed()).toEqual([name]);
    }
  });

  it("leaves out a tab with nothing in it", async () => {
    renderApp("/findings", { "GET /api/findings": rows.slice(0, 3) });
    await screen.findByRole("table", { name: "Findings" });

    expect(
      within(screen.getByRole("group", { name: "Lane" }))
        .getAllByRole("button")
        .map((b) => b.textContent?.replace(/\d+$/, "")),
    ).toEqual(["To do"]);
    expect(
      screen.getByRole("heading", { level: 1 }).nextElementSibling,
    ).toHaveTextContent(/^3 to do$/);
  });

  it("keeps the Later tab when it is empty but chosen, and says so", async () => {
    renderApp("/findings?lane=later", { "GET /api/findings": rows.slice(0, 3) });

    expect(await screen.findByRole("button", { name: /^Later\s*0$/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(screen.getByText("No findings match these filters")).toBeInTheDocument();
  });

  it("writes the counts line with a link to each tab, and the counts equal the tabs", async () => {
    renderApp("/findings", routes);
    await screen.findByRole("table", { name: "Findings" });

    const line = screen.getByRole("heading", { level: 1 }).nextElementSibling;

    expect(line).toHaveTextContent("3 to do, 3 later, 1 done, 1 dismissed");
    expect(screen.getByRole("link", { name: "3 later" })).toHaveAttribute(
      "href",
      "/findings?lane=later",
    );
    expect(screen.getByRole("link", { name: "1 dismissed" })).toHaveAttribute(
      "href",
      "/findings?lane=dismissed",
    );
    expect(screen.getByText(/Showing 3 of 9 findings/)).toBeInTheDocument();
  });

  it("follows a link in the counts line", async () => {
    const user = renderApp("/findings", routes);
    await screen.findByRole("table", { name: "Findings" });

    await user.click(screen.getByRole("link", { name: "1 done" }));

    expect(screen.getByTestId("location")).toHaveTextContent("/findings?lane=done");
    expect(tab("Done")).toHaveAttribute("aria-pressed", "true");
    expect(listLength()).toBe(1);
  });
});

describe("Findings: old links still open the same list", () => {
  // The list length each link promised before the tabs were reduced.
  it.each([
    ["/findings", 3, "", "To do"],
    ["/findings?lane=now", 2, "now", null],
    ["/findings?lane=next", 1, "next", null],
    ["/findings?lane=later", 3, "", "Later"],
    ["/findings?lane=done", 1, "", "Done"],
    ["/findings?lane=dismissed", 1, "", "Dismissed"],
    ["/findings?lane=open", 7, "open", null],
    ["/findings?lane=all", 9, "all", null],
  ])("%s lists %i findings", async (url, length, status, tabName) => {
    renderApp(url, routes);
    await screen.findByRole("table", { name: "Findings" });

    expect(listLength()).toBe(length);
    expect(screen.getByLabelText("Status")).toHaveValue(status);
    expect(pressed()).toEqual(tabName ? [tabName] : []);
  });

  it("opens only the informational findings from lane=open&info=only, with both filters shown", async () => {
    renderApp("/findings?lane=open&info=only", routes);
    await screen.findByRole("table", { name: "Findings" });

    expect(listLength()).toBe(1);
    expect(screen.getByLabelText("Status")).toHaveValue("open");
    expect(screen.getByLabelText("Informational")).toHaveValue("only");
    expect(screen.getByRole("button", { name: "Filters (2)" })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
  });
});

describe("Findings: the Filters fold", () => {
  it("keeps the search box visible and the filters folded away", async () => {
    renderApp("/findings", routes);
    await screen.findByRole("table", { name: "Findings" });

    expect(screen.getByLabelText("Search")).toBeVisible();
    expect(screen.getByRole("button", { name: "Filters" })).toHaveAttribute(
      "aria-expanded",
      "false",
    );
    for (const name of [
      "Severity",
      "Rule",
      "Source",
      "Resource type",
      "Informational",
      "Status",
    ])
      expect(screen.getByLabelText(name)).not.toBeVisible();
    expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
  });

  it("opens with the keyboard and shows all six filters", async () => {
    const user = renderApp("/findings", routes);
    await screen.findByRole("table", { name: "Findings" });
    const fold = screen.getByRole("button", { name: "Filters" });

    fold.focus();
    await user.keyboard("{Enter}");

    expect(fold).toHaveAttribute("aria-expanded", "true");
    for (const name of [
      "Severity",
      "Rule",
      "Source",
      "Resource type",
      "Informational",
      "Status",
    ])
      expect(screen.getByLabelText(name)).toBeVisible();
    await user.keyboard(" ");
    expect(fold).toHaveAttribute("aria-expanded", "false");
  });

  it("shows how many filters are active on its label, and counts each once", async () => {
    const user = renderApp("/findings", routes);
    await screen.findByRole("table", { name: "Findings" });

    await user.click(screen.getByRole("button", { name: "Filters" }));
    await user.selectOptions(screen.getByLabelText("Severity"), "MEDIUM");
    expect(screen.getByRole("button", { name: "Filters (1)" })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Status"), "open");
    expect(screen.getByRole("button", { name: "Filters (2)" })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Informational"), "hide");

    expect(screen.getByRole("button", { name: "Filters (3)" })).toBeInTheDocument();
    expect(listLength()).toBe(2);
  });

  it("does not count the search box, but still offers Clear filters for it", async () => {
    const user = renderApp("/findings?q=Finding", routes);
    await screen.findByRole("table", { name: "Findings" });

    expect(screen.getByRole("button", { name: "Filters" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear filters" }));

    expect(screen.getByLabelText("Search")).toHaveValue("");
    expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
  });

  it("clears the filters and keeps the tab", async () => {
    const user = renderApp(
      "/findings?lane=later&severity=MEDIUM&rule=CIS-S3-003",
      routes,
    );
    await screen.findByRole("table", { name: "Findings" });
    expect(listLength()).toBe(2);

    await user.click(screen.getByRole("button", { name: "Clear filters" }));

    expect(screen.getByTestId("location")).toHaveTextContent("/findings?lane=later");
    expect(tab("Later")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Filters" })).toBeInTheDocument();
    expect(listLength()).toBe(3);
  });

  it("clears a Status choice back to the To do tab", async () => {
    const user = renderApp("/findings?lane=all", routes);
    await screen.findByRole("table", { name: "Findings" });

    await user.click(screen.getByRole("button", { name: "Clear filters" }));

    expect(screen.getByTestId("location")).toHaveTextContent(/^\/findings$/);
    expect(tab("To do")).toHaveAttribute("aria-pressed", "true");
  });
});

describe("Findings: the More menu", () => {
  const managed = [
    ...rows,
    row("S", { risk_score: 62, suggested_not_applicable: { reason: "AWS owns this." } }),
  ];

  it("has no More button when nothing was suggested", async () => {
    renderApp("/findings", routes);
    await screen.findByRole("table", { name: "Findings" });

    expect(screen.queryByRole("button", { name: "More" })).toBeNull();
  });

  it("opens with the keyboard, shows the count, and closes with Escape", async () => {
    const user = renderApp("/findings", { "GET /api/findings": managed });
    await screen.findByRole("table", { name: "Findings" });
    const more = screen.getByRole("button", { name: "More" });
    expect(more).toHaveAttribute("aria-expanded", "false");

    more.focus();
    await user.keyboard("{Enter}");

    expect(more).toHaveAttribute("aria-expanded", "true");
    expect(
      screen.getByRole("menuitem", { name: "Dismiss all AWS-managed (1)" }),
    ).toBeVisible();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).toBeNull();
    expect(more).toHaveFocus();
  });

  it("opens the bulk dialog from the menu item and closes the menu", async () => {
    const user = renderApp("/findings", { "GET /api/findings": managed });
    await user.click(await screen.findByRole("button", { name: "More" }));

    await user.click(screen.getByRole("menuitem", { name: /^Dismiss all AWS-managed/ }));

    expect(screen.getByRole("dialog")).toHaveTextContent(
      "Dismiss all AWS-managed findings",
    );
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("keeps Group by check beside the tabs, not in the menu", async () => {
    const user = renderApp("/findings", { "GET /api/findings": managed });
    await user.click(await screen.findByRole("button", { name: "More" }));

    expect(screen.getByRole("menu")).not.toHaveTextContent("Group by check");
    await user.click(screen.getByRole("button", { name: "Group by check" }));

    expect(screen.getByTestId("location")).toHaveTextContent("group=check");
  });
});

describe("Findings: no list is lost", () => {
  it("reaches all nine findings through the tabs and the Status choice", async () => {
    const user = renderApp("/findings", routes);
    await screen.findByRole("table", { name: "Findings" });
    const seen = new Set<string>();
    const collect = () => {
      for (const link of within(
        screen.getByRole("table", { name: "Findings" }),
      ).getAllByRole("link"))
        seen.add(link.textContent ?? "");
    };

    for (const name of ["To do", "Later", "Done", "Dismissed"]) {
      await user.click(tab(name));
      collect();
    }
    await user.selectOptions(screen.getByLabelText("Status"), "open");
    collect();

    expect(seen.size).toBe(9);
  });
});
