import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { finding, findingDetail, fix, guardrail, scan } from "../test/factories";
import { callsTo, fail } from "../test/mockApi";
import { renderApp } from "../test/render";

type User = ReturnType<typeof renderApp>;

const row = (id: string, overrides = {}) =>
  finding({ finding_id: id, title: `Finding ${id}`, ...overrides });

const A = row("A", { title: "Open SSH to the world", risk_score: 95 });
const B = row("B", { title: "Public bucket", rule_id: "CIS-S3-001", risk_score: 85 });
const C = row("C", { title: "Wildcard policy", rule_id: "CIS-IAM-001", risk_score: 70 });
const D1 = row("D1", {
  title: "No versioning",
  rule_id: "CIS-S3-003",
  resource_id: "bucket-1",
  severity: "MEDIUM",
  risk_score: 40,
});
const D2 = row("D2", {
  title: "No versioning",
  rule_id: "CIS-S3-003",
  resource_id: "bucket-2",
  severity: "MEDIUM",
  risk_score: 40,
});
const E = row("E", { title: "Another low one", rule_id: "CIS-SG-002", risk_score: 30 });
const INFO = row("I", {
  title: "Default encryption",
  rule_id: "CIS-S3-002",
  severity: "INFO",
  risk_score: null,
  risk_factors: [],
});
const DONE = row("R", { title: "Fixed finding", status: "RESOLVED", risk_score: 75 });
const rows = [A, B, C, D1, D2, E, INFO, DONE];
const routes = { "GET /api/scans": [scan()], "GET /api/findings": rows };

const titlesIn = (table: HTMLElement) =>
  within(table)
    .getAllByRole("row")
    .map((r) => within(r).queryAllByRole("link")[0]?.textContent ?? "");

const mainTable = () => screen.getByRole("table", { name: "Findings" });
const laterTable = () => screen.getByRole("table", { name: "Later, grouped by check" });
const chip = (name: string, count: number) =>
  screen.getByRole("button", { name: new RegExp(`^${name}\\s*${count}$`) });

describe("Findings: the default list is Fix now and Next", () => {
  it("lists only the Fix now and Next findings in the main table", async () => {
    renderApp("/findings", routes);

    await screen.findByRole("table", { name: "Findings" });

    expect(titlesIn(mainTable()).slice(1)).toEqual([
      "Open SSH to the world",
      "Public bucket",
      "Wildcard policy",
    ]);
    expect(screen.getByText(/Showing 3 of 8 findings/)).toBeInTheDocument();
    expect(chip("To do", 3)).toHaveAttribute("aria-pressed", "true");
  });

  it("groups Later by check: one collapsed row for each check, with its resources", async () => {
    renderApp("/findings", routes);

    await screen.findByRole("table", { name: "Later, grouped by check" });

    const rowsLater = within(laterTable()).getAllByRole("row");
    expect(rowsLater).toHaveLength(2);
    const group = within(laterTable()).getByText("No versioning").closest("[role=row]");
    expect(within(group as HTMLElement).getByText("2 resources")).toBeInTheDocument();
    expect(within(laterTable()).getByText("Another low one")).toBeInTheDocument();
    expect(screen.getByText(/3 findings across 2 checks/)).toBeInTheDocument();
    expect(within(laterTable()).queryByRole("columnheader")).not.toBeInTheDocument();
  });

  it("opens a Later group with the keyboard, and its findings are the ones the count says", async () => {
    const user = renderApp("/findings", routes);
    await screen.findByRole("table", { name: "Later, grouped by check" });
    const toggle = within(laterTable()).getByRole("button", {
      name: /Show the 2 resources/,
    });

    toggle.focus();
    await user.keyboard("{Enter}");

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(
      within(laterTable()).getAllByRole("link", { name: "No versioning" }),
    ).toHaveLength(2);
  });

  it("keeps informational findings behind a count link that opens exactly those", async () => {
    const user = renderApp("/findings", routes);
    const link = await screen.findByRole("link", { name: "1 informational finding" });

    expect(link).toHaveAttribute("href", "/findings?lane=open&info=only");
    await user.click(link);

    expect(screen.getByTestId("location")).toHaveTextContent(
      "/findings?lane=open&info=only",
    );
    expect(screen.getByText(/Showing 1 of 8 findings/)).toBeInTheDocument();
    expect(titlesIn(mainTable()).slice(1)).toEqual(["Default encryption"]);
    expect(screen.queryByRole("table", { name: "Later, grouped by check" })).toBeNull();
  });

  it("has counts that equal the lists they open", async () => {
    const user = renderApp("/findings", routes);
    await screen.findByRole("table", { name: "Findings" });
    const shown = () => within(mainTable()).getAllByRole("row").length - 1;

    expect(shown()).toBe(3);
    await user.click(chip("Later", 3));
    expect(shown()).toBe(3);
    await user.selectOptions(screen.getByLabelText("Status"), "open");
    expect(shown()).toBe(7);
    await user.click(chip("Done", 1));
    expect(shown()).toBe(1);
    await user.selectOptions(screen.getByLabelText("Status"), "all");
    expect(shown()).toBe(8);
  });

  it("says nothing is in Fix now or Next, and still shows Later", async () => {
    renderApp("/findings", { ...routes, "GET /api/findings": [D1, D2] });

    expect(await screen.findByText("Nothing is in Fix now or Next")).toBeInTheDocument();
    expect(screen.getByText(/2 findings across 1 check\b/)).toBeInTheDocument();
  });

  it("keeps the other filters working in the default view, in the main list and in Later", async () => {
    renderApp("/findings?severity=MEDIUM", routes);

    await screen.findByRole("table", { name: "Later, grouped by check" });

    expect(screen.queryByRole("table", { name: "Findings" })).toBeNull();
    expect(screen.getByText(/2 findings across 1 check\b/)).toBeInTheDocument();
  });

  it("leaves a flat list behind every explicit lane, so lane links keep their numbers", async () => {
    renderApp("/findings?lane=later", routes);

    await screen.findByRole("table", { name: "Findings" });

    expect(within(mainTable()).getAllByRole("row")).toHaveLength(4);
    expect(screen.queryByRole("table", { name: "Later, grouped by check" })).toBeNull();
  });
});

describe("Overview: Later is one collapsed row for each check", () => {
  it("opens a check with the keyboard and links to its findings", async () => {
    const user = renderApp("/", routes);
    const later = await screen.findByRole("region", { name: "Later" });
    const toggle = within(later).getByRole("button", { name: /No versioning/ });

    expect(toggle).toHaveTextContent("No versioning, 2 resources");
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    toggle.focus();
    await user.keyboard("{Enter}");

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(within(later).getAllByRole("link", { name: "No versioning" })).toHaveLength(2);
    expect(
      within(later).getByRole("link", { name: "Open these 2 in Findings" }),
    ).toHaveAttribute("href", "/findings?lane=later&rule=CIS-S3-003");
  });

  it("keeps the Later count, and a link to all of them", async () => {
    renderApp("/", routes);

    const later = await screen.findByRole("region", { name: "Later" });

    expect(
      within(later).getByRole("heading", { name: "Later" }).nextElementSibling,
    ).toHaveTextContent("3");
    expect(within(later).getByRole("link", { name: /See all 3/ })).toHaveAttribute(
      "href",
      "/findings?lane=later",
    );
  });
});

describe("Bulk dismissal of AWS-managed findings", () => {
  const managed = (id: string, reason: string) =>
    row(id, {
      title: `Managed policy ${id}`,
      risk_score: 60,
      suggested_not_applicable: { reason },
    });
  const S1 = managed("S1", "AWS owns this policy.");
  const S2 = managed("S2", "This is a service-linked role.");
  const S3 = row("S3", {
    title: "Already dismissed",
    dismissed: true,
    suggested_not_applicable: { reason: "AWS owns this policy." },
  });
  const base = {
    "GET /api/scans": [scan()],
    "GET /api/findings": [A, S1, S2, S3],
    "PATCH /api/findings/S1/disposition": S1,
    "PATCH /api/findings/S2/disposition": S2,
    "DELETE /api/findings/S1/disposition": S1,
    "DELETE /api/findings/S2/disposition": S2,
  };

  async function open(extra: Record<string, unknown> = {}): Promise<User> {
    const user = renderApp("/findings?lane=open", { ...base, ...extra });
    await user.click(await screen.findByRole("button", { name: "More" }));
    await user.click(screen.getByRole("menuitem", { name: /^Dismiss all AWS-managed/ }));
    return user;
  }

  it("shows the action only when something was suggested, with its count", async () => {
    renderApp("/findings?lane=open", { ...base, "GET /api/findings": [A] });
    await screen.findByRole("table");

    expect(screen.queryByRole("button", { name: "More" })).toBeNull();
  });

  it("counts only open findings that were suggested, not ones already dismissed", async () => {
    const user = renderApp("/findings?lane=open", base);

    await user.click(await screen.findByRole("button", { name: "More" }));

    expect(
      screen.getByRole("menuitem", { name: "Dismiss all AWS-managed (2)" }),
    ).toBeInTheDocument();
  });

  it("lists what will be dismissed, with the reasons, before anything is sent", async () => {
    await open();

    const dialog = screen.getByRole("dialog");
    const list = within(dialog).getByRole("list", {
      name: "Findings that will be dismissed",
    });

    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    expect(list).toHaveTextContent("Managed policy S1");
    expect(list).toHaveTextContent("AWS owns this policy.");
    expect(list).toHaveTextContent("Managed policy S2");
    expect(list).not.toHaveTextContent("Already dismissed");
    expect(callsTo("PATCH", "/api/findings/S1/disposition")).toHaveLength(0);
  });

  it("needs a reason of at least 10 characters", async () => {
    const user = await open();
    const dialog = screen.getByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: "Dismiss 2 findings" });

    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Reason/), "too short");
    expect(confirm).toBeDisabled();
    expect(dialog).toHaveTextContent("At least 10 characters. 9 so far.");
    await user.type(within(dialog).getByLabelText(/Reason/), "!");

    expect(confirm).toBeEnabled();
    expect(callsTo("PATCH", "/api/findings/S1/disposition")).toHaveLength(0);
  });

  it("does not count blanks at the ends of the reason", async () => {
    const user = await open();
    const dialog = screen.getByRole("dialog");

    await user.type(within(dialog).getByLabelText(/Reason/), "     ab     ");

    expect(
      within(dialog).getByRole("button", { name: "Dismiss 2 findings" }),
    ).toBeDisabled();
  });

  it("sends one dismissal for each finding to the usual endpoint, each with the reason", async () => {
    const user = await open();
    const dialog = screen.getByRole("dialog");

    await user.type(within(dialog).getByLabelText(/Reason/), "  AWS manages these.  ");
    await user.type(within(dialog).getByLabelText(/Review date/), "2030-01-31");
    await user.click(within(dialog).getByRole("button", { name: "Dismiss 2 findings" }));

    expect(await within(dialog).findByRole("status")).toHaveTextContent(
      "Dismissed 2 of 2.",
    );
    for (const id of ["S1", "S2"]) {
      const [call] = callsTo("PATCH", `/api/findings/${id}/disposition`);
      expect(call.body).toEqual({
        disposition: "not_applicable",
        disposition_reason: "AWS manages these.",
        disposition_until: "2030-01-31",
      });
    }
  });

  it("sends no end date when the field is left empty", async () => {
    const user = await open();
    const dialog = screen.getByRole("dialog");

    await user.type(within(dialog).getByLabelText(/Reason/), "AWS manages these.");
    await user.click(within(dialog).getByRole("button", { name: "Dismiss 2 findings" }));

    await within(dialog).findByRole("status");
    const [call] = callsTo("PATCH", "/api/findings/S1/disposition");
    expect((call.body as { disposition_until: unknown }).disposition_until).toBeNull();
  });

  it("undoes one finding on its own", async () => {
    const user = await open();
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText(/Reason/), "AWS manages these.");
    await user.click(within(dialog).getByRole("button", { name: "Dismiss 2 findings" }));
    await within(dialog).findByRole("status");

    await user.click(
      within(dialog).getByRole("button", { name: "Undo dismissal of Managed policy S1" }),
    );

    expect(await within(dialog).findByText("Dismissal undone.")).toBeInTheDocument();
    expect(callsTo("DELETE", "/api/findings/S1/disposition")).toHaveLength(1);
    expect(callsTo("DELETE", "/api/findings/S2/disposition")).toHaveLength(0);
    expect(
      within(dialog).getByRole("button", { name: "Undo dismissal of Managed policy S2" }),
    ).toBeInTheDocument();
  });

  it("says which finding was not dismissed and why, and carries on with the rest", async () => {
    const user = await open({
      "PATCH /api/findings/S1/disposition": fail(
        409,
        "Only an open finding can be dismissed.",
      ),
    });
    const dialog = screen.getByRole("dialog");

    await user.type(within(dialog).getByLabelText(/Reason/), "AWS manages these.");
    await user.click(within(dialog).getByRole("button", { name: "Dismiss 2 findings" }));

    expect(await within(dialog).findByRole("status")).toHaveTextContent(
      "Dismissed 1 of 2.",
    );
    expect(within(dialog).getByRole("alert")).toHaveTextContent(
      "Not dismissed: Only an open finding can be dismissed.",
    );
    expect(callsTo("PATCH", "/api/findings/S2/disposition")).toHaveLength(1);
  });

  it("loads the list again when it is closed after a dismissal", async () => {
    const user = await open();
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText(/Reason/), "AWS manages these.");
    await user.click(within(dialog).getByRole("button", { name: "Dismiss 2 findings" }));
    await within(dialog).findByRole("status");
    expect(callsTo("GET", "/api/findings")).toHaveLength(1);

    await user.click(within(dialog).getByRole("button", { name: "Close" }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(callsTo("GET", "/api/findings")).toHaveLength(2);
  });

  it("sends nothing when it is cancelled or closed with Escape", async () => {
    const user = await open();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "More" }));
    await user.click(screen.getByRole("menuitem", { name: /^Dismiss all AWS-managed/ }));
    await user.keyboard("{Escape}");

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(callsTo("PATCH", "/api/findings/S1/disposition")).toHaveLength(0);
    expect(callsTo("GET", "/api/findings")).toHaveLength(1);
  });
});

describe("Fix tab: the first view", () => {
  const ID = "F-OWN-P13";
  const path = `/api/findings/${ID}`;
  const full = fix({
    finding_id: ID,
    pre_checks: [
      "Check one.",
      "Check two.",
      "Check three.",
      "Check four.",
      "Check five.",
    ],
    explanation: {
      why_it_matters: "Anyone on the internet can try to reach this port.",
      what_changes: "The open rule is removed. A second sentence about the change.",
      what_could_break: "Break one. Break two. Break three. Break four.",
      cited: ["e1"],
      skipped_reason: null,
    },
    guidance: ["Some guidance for the owner."],
    guardrails: [
      guardrail({ id: "g1", title: "A guardrail we can read", status: "active" }),
      guardrail({ id: "g2", title: "A guardrail we cannot read", status: "unknown" }),
      guardrail({
        id: "g3",
        title: "An organization guardrail",
        status: "needs_org_admin",
      }),
    ],
  });

  async function openFix(extra: Record<string, unknown> = {}): Promise<User> {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      [`GET ${path}`]: findingDetail({ finding_id: ID }),
      [`POST ${path}/fix`]: full,
      ...extra,
    });
    await user.click(await screen.findByRole("button", { name: "Generate fix" }));
    await screen.findByRole("region", { name: "Patches" });
    return user;
  }

  it("shows the one-line action, the patch with Copy, the checks, what could break and Verify", async () => {
    await openFix();

    const card = screen
      .getByRole("heading", { name: "What this fix does" })
      .closest("section") as HTMLElement;
    expect(within(card).getByText("The open rule is removed.")).toBeVisible();
    expect(within(card).queryByText(/A second sentence/)).toBeNull();
    const patches = screen.getByRole("region", { name: "Patches" });
    expect(patches).toBeVisible();
    expect(
      within(patches).getByRole("button", {
        name: /^Copy Remove the open ingress rules/,
      }),
    ).toBeVisible();
    expect(screen.getByRole("heading", { name: "Before you apply it" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "What could break" })).toBeVisible();
    expect(screen.getByRole("region", { name: "Verify" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Rescan to verify" })).toBeVisible();
  });

  it("keeps everything heavy out of the first view", async () => {
    await openFix();

    for (const text of [
      "Anyone on the internet can try to reach this port.",
      "To add the rules back",
      "Some guidance for the owner.",
      "Who connects to these ports",
      "Inbound rule exposes SSH",
      "Cited evidence:",
    ]) {
      for (const found of screen.getAllByText(new RegExp(text)))
        expect(found).not.toBeVisible();
    }
    expect(screen.queryByRole("heading", { name: "Rollback" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Evidence" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Why it matters" })).toBeNull();
  });

  it("removes nothing: all of it is in the page and shows once the folds are open", async () => {
    const user = await openFix();
    const everything = [
      "Anyone on the internet can try to reach this port.",
      "A second sentence about the change.",
      "Check four.",
      "Check five.",
      "Break three. Break four.",
      "To add the rules back",
      "Some guidance for the owner.",
      "Who connects to these ports",
      "Inbound rule exposes SSH (port 22)",
      "A guardrail we can read",
      "A guardrail we cannot read",
      "An organization guardrail",
    ];
    for (const text of everything) expect(document.body.textContent).toContain(text);

    await user.click(screen.getByRole("button", { name: /^More detail/ }));
    await user.click(screen.getByRole("button", { name: "Show all (5)" }));
    await user.click(screen.getByRole("button", { name: "Show more" }));
    await user.click(
      screen.getByRole("button", { name: /guardrails CloudShield cannot check/ }),
    );

    for (const text of [
      "Anyone on the internet can try to reach this port.",
      "Check five.",
      "Some guidance for the owner.",
      "Who connects to these ports",
    ]) {
      for (const found of screen.getAllByText(new RegExp(text)))
        expect(found).toBeVisible();
    }
    expect(screen.getByText(/Break three\. Break four\./)).toBeVisible();
    expect(
      screen.getByRole("article", { name: "A guardrail we cannot read" }),
    ).toBeVisible();
  });

  it("limits Before you apply to three checks and shows all of them from one button", async () => {
    const user = await openFix();

    expect(screen.getByText("Check three.")).toBeVisible();
    expect(screen.getByText("Check four.")).not.toBeVisible();
    const button = screen.getByRole("button", { name: "Show all (5)" });
    expect(button).toHaveAttribute("aria-expanded", "false");
    button.focus();
    await user.keyboard("{Enter}");

    expect(screen.getByText("Check five.")).toBeVisible();
    expect(screen.getByRole("button", { name: "Show fewer" })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
  });

  it("shows no Show all button when there are three checks or fewer", async () => {
    await openFix({
      [`POST ${path}/fix`]: fix({ finding_id: ID, pre_checks: ["Only one."] }),
    });

    expect(screen.queryByRole("button", { name: /Show all/ })).toBeNull();
  });

  it("shows two sentences of What could break and the rest after Show more", async () => {
    const user = await openFix();

    expect(screen.getByText(/Break one\. Break two\./)).toBeVisible();
    expect(screen.getByText(/Break three\. Break four\./)).not.toBeVisible();
    const more = screen.getByRole("button", { name: "Show more" });
    more.focus();
    await user.keyboard(" ");

    expect(screen.getByText(/Break three\. Break four\./)).toBeVisible();
    expect(screen.getByRole("button", { name: "Show less" })).toBeInTheDocument();
  });

  it("shows a short What could break whole, with no button", async () => {
    await openFix({
      [`POST ${path}/fix`]: fix({
        finding_id: ID,
        explanation: { ...full.explanation, what_could_break: "Only one sentence here." },
      }),
    });

    expect(screen.getByText("Only one sentence here.")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Show more" })).toBeNull();
  });

  it("opens More detail with the keyboard", async () => {
    const user = await openFix();
    const fold = screen.getByRole("button", { name: /^More detail/ });

    expect(fold).toHaveAttribute("aria-expanded", "false");
    fold.focus();
    await user.keyboard("{Enter}");

    expect(fold).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("heading", { name: "Why it matters" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "Rollback" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "Evidence" })).toBeVisible();
  });

  it("remembers the chosen patch format in the browser", async () => {
    const user = await openFix();

    await user.click(
      within(screen.getByRole("region", { name: "Patches" })).getByRole("tab", {
        name: "cli",
      }),
    );

    expect(window.localStorage.getItem("cloudshield.patchFormat")).toBe("cli");
  });

  it("opens on the remembered format the next time", async () => {
    window.localStorage.setItem("cloudshield.patchFormat", "cli");

    await openFix();

    const patches = screen.getByRole("region", { name: "Patches" });
    expect(within(patches).getByRole("tab", { name: "cli" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(
      within(patches).getByText(/aws ec2 revoke-security-group-ingress/),
    ).toBeInTheDocument();
  });

  it("starts on the first format when the remembered one is not offered", async () => {
    window.localStorage.setItem("cloudshield.patchFormat", "cloudformation");

    await openFix();

    expect(
      within(screen.getByRole("region", { name: "Patches" })).getByRole("tab", {
        name: "terraform",
      }),
    ).toHaveAttribute("aria-selected", "true");
  });

  it("still works when the browser blocks storage", async () => {
    const blocked = () => {
      throw new Error("blocked");
    };
    const getItem = window.Storage.prototype.getItem;
    const setItem = window.Storage.prototype.setItem;
    window.Storage.prototype.getItem = blocked;
    window.Storage.prototype.setItem = blocked;
    try {
      const user = await openFix();

      await user.click(
        within(screen.getByRole("region", { name: "Patches" })).getByRole("tab", {
          name: "cli",
        }),
      );

      expect(
        within(screen.getByRole("region", { name: "Patches" })).getByRole("tab", {
          name: "cli",
        }),
      ).toHaveAttribute("aria-selected", "true");
    } finally {
      window.Storage.prototype.getItem = getItem;
      window.Storage.prototype.setItem = setItem;
    }
  });

  it("does not remember the format of a guardrail's patches", async () => {
    const user = await openFix();
    await user.click(screen.getByRole("button", { name: /A guardrail we can read/ }));
    const panel = screen.getByRole("region", {
      name: "Patches for A guardrail we can read",
    });

    await user.click(within(panel).getByRole("tab", { name: "cli" }));

    expect(window.localStorage.getItem("cloudshield.patchFormat")).toBeNull();
  });

  it("shows the guidance in the first view when there is no patch", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      [`GET ${path}`]: findingDetail({ finding_id: ID }),
      [`POST ${path}/fix`]: fix({
        finding_id: ID,
        patches: [],
        guidance: ["Do this by hand."],
      }),
    });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    expect(await screen.findByText("Do this by hand.")).toBeVisible();
    expect(screen.getByText("No patch is generated for this finding.")).toBeVisible();
    expect(screen.queryByRole("region", { name: "Patches" })).toBeNull();
  });
});

describe("Fix tab: the stepper opens only the current step", () => {
  const ID = "F-OWN-STEP";
  const path = `/api/findings/${ID}`;

  it("shows a hint on the first step only, before a fix is made", async () => {
    renderApp(`/findings/${ID}?tab=fix`, {
      [`GET ${path}`]: findingDetail({ finding_id: ID }),
    });

    const list = await screen.findByRole("list", { name: "Progress" });

    const items = within(list).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("Read what was found");
    expect(
      list.textContent?.match(
        /Read what was found|Go through|Apply the patch|Run a scan/g,
      ),
    ).toHaveLength(1);
  });

  it("moves the hint to the third step once the fix is shown", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      [`GET ${path}`]: findingDetail({ finding_id: ID }),
      [`POST ${path}/fix`]: fix({ finding_id: ID }),
    });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));
    await screen.findByRole("region", { name: "Patches" });

    const items = within(screen.getByRole("list", { name: "Progress" })).getAllByRole(
      "listitem",
    );
    expect(items[2]).toHaveTextContent("Apply the patch to your account yourself.");
    expect(items[0]).not.toHaveTextContent("Read what was found");
  });
});

describe("Fix tab: an imported finding keeps its layout", () => {
  const ID = "F-PRW-P13";
  const path = `/api/findings/${ID}`;

  it("has the one-line caveat, no More detail fold and no patch", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      [`GET ${path}`]: findingDetail({
        finding_id: ID,
        source: "prowler",
        rule_id: "PRW-iam_x",
        resource: null,
      }),
      [`POST ${path}/fix`]: fix({
        finding_id: ID,
        patches: [],
        guardrails: [],
        guidance: ["Fix it in the console."],
        pre_checks: ["One.", "Two.", "Three.", "Four.", "Five."],
        explanation: {
          why_it_matters: "A risk the scanner reported.",
          what_changes: "",
          what_could_break: "",
          cited: [],
          skipped_reason: "CloudShield did not collect this evidence.",
        },
      }),
    });
    expect(
      await screen.findByText(
        "No patch for this finding. This is guidance from an imported scan.",
      ),
    ).toBeVisible();

    await user.click(screen.getByRole("button", { name: "Generate fix" }));

    await screen.findByRole("region", { name: "Risk reported by the scanner" });
    expect(screen.queryByRole("button", { name: /^More detail/ })).toBeNull();
    expect(screen.queryByRole("region", { name: "Patches" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Show all/ })).toBeNull();
    expect(screen.getByText("Five.")).toBeVisible();
    expect(
      screen.getByText(
        "This comes from an external scanner. CloudShield did not collect this evidence.",
      ),
    ).toBeVisible();
  });
});
