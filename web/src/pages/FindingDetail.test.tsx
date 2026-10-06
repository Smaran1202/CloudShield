import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { finding, findingDetail, fix, scan } from "../test/factories";
import { callsTo, fail } from "../test/mockApi";
import { never, renderApp } from "../test/render";

const ID = "F-CIS-SG-001-aaaaaaaa";
const path = `/api/findings/${ID}`;
const detail = { [`GET ${path}`]: findingDetail() };
const fixRoute = { [`POST ${path}/fix`]: fix() };

function openFix(routes: Record<string, unknown> = {}) {
  return renderApp(`/findings/${ID}?tab=fix`, { ...detail, ...fixRoute, ...routes });
}

async function generated(routes: Record<string, unknown> = {}) {
  const user = openFix(routes);
  await user.click(await screen.findByRole("button", { name: "Generate fix" }));
  await screen.findByText("Why it matters");
  return user;
}

function steps(): string[] {
  return within(screen.getByRole("list", { name: "Progress" }))
    .getAllByRole("listitem")
    .map((item) => item.getAttribute("data-state") ?? "");
}

const verifyPanel = () => screen.getByRole("region", { name: "Verify" });

// The list items inside the open tab, not the ones in the stepper.
const panelItems = () => within(screen.getByRole("tabpanel")).getAllByRole("listitem");
const findPanelItems = async () => {
  await screen.findByRole("tabpanel");
  return within(screen.getByRole("tabpanel")).findAllByRole("listitem");
};

// Three findings, one of them resolved, as the list endpoint would return after a rescan.
const afterRescan = [
  finding({ finding_id: ID, status: "RESOLVED" }),
  finding({ finding_id: "F-2", risk_score: 80 }),
  finding({ finding_id: "F-3", risk_score: 61 }),
];

describe("Finding detail: page", () => {
  it("shows loading while the finding is fetched", async () => {
    renderApp(`/findings/${ID}`, { [`GET ${path}`]: never });

    expect(screen.getByText("Loading finding...")).toBeInTheDocument();
    await screen.findByText(/API online/);
  });

  it("shows the backend's message when the finding is not found", async () => {
    renderApp(`/findings/${ID}`, { [`GET ${path}`]: fail(404, "Finding not found.") });

    expect(await screen.findByRole("alert")).toHaveTextContent("Finding not found.");
  });

  it("shows a breadcrumb, the title, and chips for status, resource and severity", async () => {
    renderApp(`/findings/${ID}`, detail);

    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading).toHaveTextContent("Security group allows SSH or all traffic");
    const crumb = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(crumb).toHaveTextContent("Findings / CIS-SG-001");
    expect(within(crumb).getByRole("link", { name: "Findings" })).toHaveAttribute(
      "href",
      "/findings",
    );
    expect(screen.getByText("Open")).toBeInTheDocument();
    expect(screen.getByTitle("sg-0abc123")).toBeInTheDocument();
    expect(screen.getByText("HIGH")).toBeInTheDocument();
  });

  it("shows the Verified evidence chip only when the evidence has a verified item", async () => {
    renderApp(`/findings/${ID}`, detail);
    expect(await screen.findByText("Verified evidence")).toBeInTheDocument();
  });

  it("leaves the Verified evidence chip out when nothing is verified", async () => {
    const heuristic = findingDetail({
      evidence: {
        items: [{ fact: "A guess", value: null, source: "x", certainty: "heuristic" }],
      },
    });
    renderApp(`/findings/${ID}`, { [`GET ${path}`]: heuristic });

    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByText("Verified evidence")).not.toBeInTheDocument();
  });

  it("shows the score in a tile in the colour of its lane", async () => {
    renderApp(`/findings/${ID}`, detail);

    await screen.findByRole("heading", { level: 1 });
    const tile = document.querySelector('[data-lane="now"]') as HTMLElement;
    expect(tile).toHaveTextContent("95");
    expect(tile).toHaveClass("bg-red");
  });

  it("shows a resolved finding in a green tile with a check and its last score", async () => {
    renderApp(`/findings/${ID}`, {
      [`GET ${path}`]: findingDetail({ status: "RESOLVED", risk_score: 88 }),
    });

    await screen.findByRole("heading", { level: 1 });
    const tile = document.querySelector('[data-lane="done"]') as HTMLElement;
    expect(tile).toHaveTextContent("Fixed, last score 88");
    expect(tile).toHaveClass("bg-green");
    expect(tile.querySelector("svg.check")).not.toBeNull();
  });

  it("shows no score for a finding that does not count toward risk", async () => {
    renderApp(`/findings/${ID}`, {
      [`GET ${path}`]: findingDetail({ risk_score: null, severity: "INFO" }),
    });

    expect(await screen.findByText("No risk score")).toBeInTheDocument();
  });

  it("moves between tabs with the arrow keys", async () => {
    const user = renderApp(`/findings/${ID}`, detail);
    await screen.findByRole("tab", { name: "Summary" });

    screen.getByRole("tab", { name: "Summary" }).focus();
    await user.keyboard("{ArrowRight}");

    expect(
      await screen.findByRole("tab", { name: "Evidence", selected: true }),
    ).toHaveFocus();
  });

  it("explains a resolved finding on the summary", async () => {
    renderApp(`/findings/${ID}`, {
      [`GET ${path}`]: findingDetail({
        status: "RESOLVED",
        resolved_at: "2026-10-03T10:00:00Z",
        resolution_reason: "no longer detected",
      }),
    });

    expect(await screen.findByText("Why resolved")).toBeInTheDocument();
    expect(screen.getByText("no longer detected")).toBeInTheDocument();
  });
});

describe("Finding detail: stepper", () => {
  it("starts on the first step, before any fix is generated", async () => {
    renderApp(`/findings/${ID}`, detail);

    await screen.findByRole("heading", { level: 1 });

    expect(steps()).toEqual(["current", "todo", "todo", "todo"]);
    const items = within(screen.getByRole("list", { name: "Progress" })).getAllByRole(
      "listitem",
    );
    expect(items.map((i) => i.textContent)).toEqual([
      expect.stringContaining("Review the evidence"),
      expect.stringContaining("Check the blast radius"),
      expect.stringContaining("Apply the fix yourself"),
      expect.stringContaining("Rescan to verify"),
    ]);
    expect(items[0]).toHaveAttribute("aria-current", "step");
  });

  it("moves to the third step once the fix is shown", async () => {
    await generated();

    expect(steps()).toEqual(["done", "done", "current", "todo"]);
  });

  it("does not move while the fix is still being generated", async () => {
    const user = openFix({ [`POST ${path}/fix`]: never });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    expect(await screen.findByText(/Generating the fix/)).toBeInTheDocument();
    expect(steps()).toEqual(["current", "todo", "todo", "todo"]);
  });

  it("is on the fourth step while a rescan runs", async () => {
    const user = await generated({
      "POST /api/scans": scan({ id: 9, status: "running", progress: "Scanning AWS" }),
      "GET /api/scans/9": scan({ id: 9, status: "running", progress: "Scanning AWS" }),
    });

    await user.click(screen.getByRole("button", { name: "Rescan to verify" }));

    await waitFor(() => expect(steps()).toEqual(["done", "done", "done", "current"]));
  });

  it("has every step done for a finding that is already resolved", async () => {
    renderApp(`/findings/${ID}`, {
      [`GET ${path}`]: findingDetail({ status: "RESOLVED" }),
    });

    await screen.findByRole("heading", { level: 1 });

    expect(steps()).toEqual(["done", "done", "done", "done"]);
  });

  it("has every step done once a rescan finds the finding resolved", async () => {
    let reads = 0;
    const user = await generated({
      [`GET ${path}`]: () =>
        ++reads === 1 ? findingDetail() : findingDetail({ status: "RESOLVED" }),
      "POST /api/scans": scan({ id: 9, status: "queued" }),
      "GET /api/scans/9": scan({ id: 9 }),
      "GET /api/findings": afterRescan,
    });

    await user.click(screen.getByRole("button", { name: "Rescan to verify" }));

    await waitFor(() => expect(steps()).toEqual(["done", "done", "done", "done"]));
  });
});

describe("Finding detail: evidence and risk tabs", () => {
  it("shows each evidence item with its source and a certainty chip", async () => {
    const user = renderApp(`/findings/${ID}`, detail);

    await user.click(await screen.findByRole("tab", { name: "Evidence" }));

    const items = panelItems();
    expect(items).toHaveLength(3);
    expect(within(items[0]).getByText("e1")).toBeInTheDocument();
    expect(within(items[0]).getByText("attributes.inbound")).toBeInTheDocument();
    expect(items[0].querySelector('[data-certainty="verified"]')).toHaveTextContent(
      "verified",
    );
    expect(items[1].querySelector('[data-certainty="unknown"]')).toHaveTextContent(
      "unknown",
    );
    expect(items[2].querySelector('[data-certainty="heuristic"]')).toHaveTextContent(
      "heuristic",
    );
    expect(within(items[1]).getByText("no value")).toBeInTheDocument();
  });

  it("says when no evidence is stored", async () => {
    const user = renderApp(`/findings/${ID}`, {
      [`GET ${path}`]: findingDetail({ evidence: { items: [] } }),
    });

    await user.click(await screen.findByRole("tab", { name: "Evidence" }));

    expect(
      screen.getByText("No evidence is stored for this finding yet"),
    ).toBeInTheDocument();
  });

  it("highlights the evidence item named in the link", async () => {
    renderApp(`/findings/${ID}?tab=evidence&item=e2`, detail);

    const item = (await findPanelItems())[1];

    expect(item).toHaveClass("ring-4");
  });

  it("lists each risk factor with its adjustment, certainty and reason", async () => {
    const user = renderApp(`/findings/${ID}`, detail);

    await user.click(await screen.findByRole("tab", { name: "Risk" }));

    const items = panelItems();
    expect(within(items[0]).getByText("+15")).toBeInTheDocument();
    expect(
      within(items[0]).getByText("An inbound rule allows 0.0.0.0/0 or ::/0."),
    ).toBeInTheDocument();
    expect(items[0].querySelector('[data-certainty="verified"]')).not.toBeNull();
    expect(items[1].querySelector('[data-certainty="unknown"]')).not.toBeNull();
  });

  it("says so when there are no stored risk factors", async () => {
    const user = renderApp(`/findings/${ID}`, {
      [`GET ${path}`]: findingDetail({ risk_factors: [] }),
    });

    await user.click(await screen.findByRole("tab", { name: "Risk" }));

    expect(
      screen.getByText("No risk factors are stored for this finding"),
    ).toBeInTheDocument();
  });
});

describe("Finding detail: Fix tab", () => {
  it("does not request the fix until the button is clicked, and says CloudShield never changes AWS", async () => {
    const user = openFix();

    await screen.findByRole("button", { name: "Generate fix" });
    expect(
      screen.getAllByText(/CloudShield never changes your AWS account/).length,
    ).toBeGreaterThan(0);
    expect(callsTo("POST", `${path}/fix`)).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Generate fix" }));
    await screen.findByText("Why it matters");

    expect(callsTo("POST", `${path}/fix`)).toHaveLength(1);
    expect(callsTo("POST", `${path}/fix`)[0].search).toBe("?refresh=false");
  });

  it("does not request the fix when the tab is opened, or when other tabs are used", async () => {
    const user = renderApp(`/findings/${ID}`, { ...detail, ...fixRoute });
    await user.click(await screen.findByRole("tab", { name: "Evidence" }));
    await user.click(screen.getByRole("tab", { name: "Risk" }));
    await user.click(screen.getByRole("tab", { name: "Fix" }));

    await screen.findByRole("button", { name: "Generate fix" });

    expect(callsTo("POST", `${path}/fix`)).toHaveLength(0);
  });

  it("shows loading while the fix is generated", async () => {
    const user = openFix({ [`POST ${path}/fix`]: never });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    expect(await screen.findByText(/Generating the fix/)).toBeInTheDocument();
  });

  it("shows the backend's message when the fix cannot be generated", async () => {
    const user = openFix({
      [`POST ${path}/fix`]: fail(409, "This finding is resolved and has no fix."),
    });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "This finding is resolved and has no fix.",
    );
  });

  it("shows the AI badge with the model name and the three explanation sections", async () => {
    await generated();

    const card = screen
      .getByRole("heading", { name: "What this fix does" })
      .closest("section");
    expect(within(card as HTMLElement).getByText("AI explanation")).toBeInTheDocument();
    expect(screen.getByText("written by model-a")).toBeInTheDocument();
    expect(
      screen.getByText("Anyone on the internet can try to reach this port."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("The open rule is removed from the group."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("People who connect through the rule lose access."),
    ).toBeInTheDocument();
  });

  it("shows a template badge with the reason Gemini was not used", async () => {
    const template = fix({
      generated_by: "template",
      model: null,
      explanation: {
        ...fix().explanation,
        skipped_reason: "no GEMINI_API_KEY in this process",
      },
    });
    await generated({ [`POST ${path}/fix`]: template });

    expect(screen.getByText("Template explanation")).toBeInTheDocument();
    expect(
      screen.getByText("Gemini was not used: no GEMINI_API_KEY in this process"),
    ).toBeInTheDocument();
    expect(screen.queryByText("AI explanation")).not.toBeInTheDocument();
  });

  it("links cited evidence ids back to the evidence tab", async () => {
    const user = await generated();

    const cited = screen.getByText("Cited evidence:").closest("p") as HTMLElement;
    const link = within(cited).getByRole("link", { name: "e2" });
    expect(link).toHaveAttribute("href", `/findings/${ID}?tab=evidence&item=e2`);
    await user.click(link);

    expect(
      await screen.findByRole("tab", { name: "Evidence", selected: true }),
    ).toBeInTheDocument();
    expect((await findPanelItems())[1]).toHaveClass("ring-4");
  });

  it("shows the blast radius level and each factor with its certainty chip", async () => {
    await generated();

    const card = screen
      .getByRole("heading", { name: "Blast radius" })
      .closest("section") as HTMLElement;
    expect(card.querySelector('[data-level="medium"]')).toHaveTextContent("medium");
    expect(
      within(card).getByText("Running instances using this group"),
    ).toBeInTheDocument();
    expect(card.querySelector('[data-certainty="verified"]')).not.toBeNull();
    expect(card.querySelector('[data-certainty="unknown"]')).not.toBeNull();
    expect(
      within(card).getByText("Use SSM Session Manager instead of SSH."),
    ).toBeInTheDocument();
  });

  it("draws an unknown blast radius with a dashed border", async () => {
    const unknown = fix({ blast_radius: { level: "unknown", factors: [], notes: [] } });
    await generated({ [`POST ${path}/fix`]: unknown });

    const chip = document.querySelector('[data-level="unknown"]') as HTMLElement;

    expect(chip).toHaveTextContent("unknown");
    expect(chip).toHaveClass("border-dashed");
  });

  it("shows the evidence card next to the fix, with certainty chips", async () => {
    await generated();

    const card = screen
      .getByRole("heading", { name: "Evidence" })
      .closest("section") as HTMLElement;
    expect(
      within(card).getByText("Inbound rule exposes SSH (port 22)"),
    ).toBeInTheDocument();
    expect(card.querySelector('[data-certainty="heuristic"]')).not.toBeNull();
  });

  it("shows the patch panel with a tab for each format and a review notice", async () => {
    const user = await generated();

    const panel = screen.getByRole("region", { name: "Patches" });
    const formats = within(panel).getAllByRole("tab");
    expect(formats.map((t) => t.textContent)).toEqual(["terraform", "cli"]);
    expect(within(panel).getByRole("note")).toHaveTextContent(
      "Review before you run it. CloudShield never changes your AWS account.",
    );
    expect(
      within(panel).getByText(/Remove these ingress rules from the Terraform/),
    ).toBeInTheDocument();

    await user.click(within(panel).getByRole("tab", { name: "cli" }));

    expect(
      within(panel).getByText(/aws ec2 revoke-security-group-ingress/),
    ).toBeInTheDocument();
    expect(within(panel).getByText("sg-0abc123-rule1.json")).toBeInTheDocument();
    expect(panel.querySelector(".fade-up")).not.toBeNull();
  });

  it("copies the patch, says Copied, and goes back to Copy after a moment", async () => {
    const user = await generated();
    const writeText = vi.spyOn(navigator.clipboard, "writeText");
    await user.click(screen.getByRole("tab", { name: "cli" }));

    await user.click(
      screen.getByRole("button", {
        name: "Copy Remove the open ingress rules (AWS CLI)",
      }),
    );

    expect(writeText).toHaveBeenCalledWith(fix().patches[1].content);
    const button = screen.getByRole("button", {
      name: "Copy Remove the open ingress rules (AWS CLI)",
    });
    await waitFor(() => expect(button).toHaveTextContent("Copied"));
    await waitFor(() => expect(button).toHaveTextContent(/^Copy$/), { timeout: 3000 });
  });

  it("says plainly when the clipboard refuses the copy", async () => {
    const user = await generated();
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("denied"));

    await user.click(
      screen.getByRole("button", {
        name: "Copy Remove the open ingress rules (Terraform)",
      }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("Copy failed");
    expect(screen.queryByText("Copied")).not.toBeInTheDocument();
  });

  it("says plainly when there is no clipboard at all", async () => {
    const user = await generated();
    Object.defineProperty(navigator, "clipboard", {
      value: undefined,
      configurable: true,
    });

    await user.click(
      screen.getByRole("button", {
        name: "Copy Remove the open ingress rules (Terraform)",
      }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("Copy failed");
  });

  it("marks patches that need input and says what to fill in", async () => {
    const needsKey = fix({
      patches: [
        {
          format: "cli",
          title: "Use a KMS key for default encryption (AWS CLI)",
          content: "aws s3api put-bucket-encryption --bucket b\n",
          files: [],
          needs_input: true,
          inputs_needed: ["The ARN of the KMS key to use for default encryption"],
          instructions_only: false,
        },
      ],
    });
    await generated({ [`POST ${path}/fix`]: needsKey });

    const notes = screen.getAllByRole("note");
    const needs = notes.find((n) =>
      n.textContent?.includes("Needs your input"),
    ) as HTMLElement;

    expect(needs).toHaveTextContent(
      "The ARN of the KMS key to use for default encryption",
    );
  });

  it("builds the checklist from the real pre-checks, with ticks that stay on the page", async () => {
    const user = await generated();
    const callsBefore = callsTo("POST", `${path}/fix`).length;

    const box = screen.getByRole("checkbox", {
      name: "Find out who connects to the instances today.",
    });
    expect(box).not.toBeChecked();
    await user.click(box);

    expect(box).toBeChecked();
    expect(callsTo("POST", `${path}/fix`)).toHaveLength(callsBefore);
  });

  it("shows the rollback and verify text", async () => {
    await generated();

    expect(screen.getByText(/To add the rules back/)).toBeInTheDocument();
    expect(
      screen.getByText("Rescan (POST /api/scans). This finding should resolve."),
    ).toBeInTheDocument();
  });

  it("shows guidance, and no patch panel, for findings that have no patch", async () => {
    const guidance = fix({
      patches: [],
      guidance: ["Open the policy and read the statements listed in the evidence."],
      pre_checks: [],
    });
    await generated({ [`POST ${path}/fix`]: guidance });

    expect(screen.getByRole("heading", { name: "Guidance" })).toBeInTheDocument();
    expect(
      screen.getByText("Open the policy and read the statements listed in the evidence."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Patches" })).not.toBeInTheDocument();
  });

  it("asks for a refreshed fix when regenerating", async () => {
    const user = await generated();

    await user.click(screen.getByRole("button", { name: "Regenerate explanation" }));

    await waitFor(() => expect(callsTo("POST", `${path}/fix`)).toHaveLength(2));
    expect(callsTo("POST", `${path}/fix`)[1].search).toBe("?refresh=true");
  });
});

describe("Finding detail: Verify panel", () => {
  it("is idle at first: a dark panel with a Rescan to verify button", async () => {
    openFix();

    await screen.findByRole("button", { name: "Generate fix" });

    const panel = verifyPanel();
    expect(panel).toHaveClass("bg-ink");
    expect(within(panel).getByRole("button", { name: "Rescan to verify" })).toBeEnabled();
    expect(panel.querySelector(".spinner")).toBeNull();
  });

  it("shows a spinner and the backend's real progress text while scanning", async () => {
    const user = openFix({
      "POST /api/scans": scan({ id: 9, status: "queued", progress: "Queued" }),
      "GET /api/scans/9": scan({ id: 9, status: "running", progress: "Running rules" }),
    });

    await user.click(await screen.findByRole("button", { name: "Rescan to verify" }));

    const panel = verifyPanel();
    await waitFor(() => expect(panel).toHaveTextContent("Scan 9 running: Running rules"));
    expect(panel.querySelector(".spinner")).not.toBeNull();
    expect(within(panel).getByRole("button", { name: "Scanning..." })).toBeDisabled();
  });

  it("celebrates only after the finding is fetched again and is RESOLVED, with the live counts", async () => {
    let reads = 0;
    const user = openFix({
      [`GET ${path}`]: () =>
        ++reads === 1 ? findingDetail() : findingDetail({ status: "RESOLVED" }),
      "POST /api/scans": scan({ id: 9, status: "queued" }),
      "GET /api/scans/9": scan({ id: 9 }),
      "GET /api/findings": afterRescan,
    });

    await user.click(await screen.findByRole("button", { name: "Rescan to verify" }));

    const panel = await screen.findByText("1 fixed. 2 to go.");
    const region = panel.closest("section") as HTMLElement;
    expect(region).toHaveClass("bg-green");
    expect(region).toHaveClass("pop");
    expect(region.querySelector("svg.check")).not.toBeNull();
    expect(reads).toBeGreaterThanOrEqual(2);
  });

  it("does not celebrate when the scan completes but the fetched finding is still OPEN", async () => {
    const user = openFix({
      "POST /api/scans": scan({ id: 9, status: "queued" }),
      "GET /api/scans/9": scan({ id: 9 }),
      "GET /api/findings": [finding({ finding_id: ID }), finding({ finding_id: "F-2" })],
    });

    await user.click(await screen.findByRole("button", { name: "Rescan to verify" }));

    expect(await screen.findByText("Still open after the rescan.")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Check that you applied the patch to the right resource and region.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/\d+ fixed\./)).not.toBeInTheDocument();
    expect(verifyPanel()).not.toHaveClass("bg-green");
    expect(verifyPanel()).toHaveClass("bg-lane-grey");
  });

  it("shows the backend's message when the scan fails, and does not celebrate", async () => {
    const user = openFix({
      "POST /api/scans": scan({ id: 9, status: "queued" }),
      "GET /api/scans/9": scan({
        id: 9,
        status: "failed",
        failure_message: "RuntimeError: No AWS credentials found.",
      }),
    });

    await user.click(await screen.findByRole("button", { name: "Rescan to verify" }));

    const alert = await screen.findByRole("alert", { name: "Verify" });
    expect(alert).toHaveTextContent("RuntimeError: No AWS credentials found.");
  });

  it("shows the backend's message when the rescan cannot start", async () => {
    const user = openFix({ "POST /api/scans": fail(409, "A scan is already running.") });

    await user.click(await screen.findByRole("button", { name: "Rescan to verify" }));

    await screen.findAllByText("A scan is already running.");
    expect(
      within(screen.getByRole("alert", { name: "Verify" })).getByText(
        "A scan is already running.",
      ),
    ).toBeInTheDocument();
  });

  it("shows the message when the finding cannot be fetched again after the scan", async () => {
    let reads = 0;
    const user = openFix({
      [`GET ${path}`]: () =>
        ++reads === 1 ? findingDetail() : fail(500, "finding exploded"),
      "POST /api/scans": scan({ id: 9, status: "queued" }),
      "GET /api/scans/9": scan({ id: 9 }),
      "GET /api/findings": afterRescan,
    });

    await user.click(await screen.findByRole("button", { name: "Rescan to verify" }));

    expect((await screen.findAllByText("finding exploded")).length).toBeGreaterThan(0);
    expect(screen.queryByText(/\d+ fixed\./)).not.toBeInTheDocument();
  });

  it("can rescan again after a still-open result", async () => {
    const user = openFix({
      "POST /api/scans": scan({ id: 9, status: "queued" }),
      "GET /api/scans/9": scan({ id: 9 }),
      "GET /api/findings": [finding({ finding_id: ID })],
    });
    await user.click(await screen.findByRole("button", { name: "Rescan to verify" }));
    await screen.findByText("Still open after the rescan.");

    await user.click(
      within(verifyPanel()).getByRole("button", { name: "Rescan to verify" }),
    );

    await waitFor(() => expect(callsTo("POST", "/api/scans")).toHaveLength(2));
  });
});
