import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CertaintyChip } from "../components/ui";
import { formatDate } from "../format";
import { finding, findingDetail, fix, scan, summary } from "../test/factories";
import { callsTo } from "../test/mockApi";
import { renderApp } from "../test/render";

const IMPORTED = {
  finding_id: "F-PRW-iam_x-aaaaaaaa",
  rule_id: "PRW-iam_x",
  source: "prowler" as const,
  title: "Password policy is weak",
  resource_id: "arn:aws:iam:ap-southeast-2:123456789012:password-policy",
  resource_type: "Account",
  risk_score: 40,
  severity: "MEDIUM" as const,
  last_scan_id: null,
  last_imported_at: "2026-10-05T04:42:00Z",
  evidence: {
    items: [
      {
        fact: "Check result reported by Prowler",
        value: "The policy is too short.",
        source: "prowler: status_detail",
        certainty: "reported" as const,
      },
    ],
  },
};

const own = finding({ finding_id: "F-OWN", title: "Our own finding", risk_score: 95 });
const imported = finding(IMPORTED);
const stale = finding({
  ...IMPORTED,
  finding_id: "F-PRW-stale",
  title: "Not in the newest import",
  not_rechecked: true,
});

describe("Certainty chip", () => {
  it("shows a label and an icon for every kind, so colour is never the only signal", () => {
    const icons = {
      verified: "check",
      heuristic: "alert",
      unknown: "question",
      reported: "external",
    } as const;

    for (const [certainty, icon] of Object.entries(icons)) {
      const { container, unmount } = render(
        <CertaintyChip certainty={certainty as keyof typeof icons} />,
      );
      const chip = container.querySelector(`[data-certainty="${certainty}"]`);
      expect(chip).toHaveTextContent(certainty);
      expect(chip?.querySelector(`svg[data-icon="${icon}"]`)).not.toBeNull();
      unmount();
    }
  });

  it("explains that a reported item comes from an external tool", () => {
    const { container } = render(<CertaintyChip certainty="reported" />);

    expect(container.firstElementChild).toHaveAttribute(
      "title",
      expect.stringContaining("external tool"),
    );
  });
});

describe("Findings: imported findings", () => {
  const routes = { "GET /api/findings": [own, imported, stale] };

  it("shows an Imported badge on imported rows and none on our own", async () => {
    renderApp("/findings", routes);

    const rows = (await screen.findAllByRole("row")).slice(1);
    const ours = rows.find((r) =>
      within(r).queryByText("Our own finding"),
    ) as HTMLElement;
    const theirs = rows.find((r) => within(r).queryByText("Password policy is weak"));

    expect(ours.querySelector("[data-source]")).toBeNull();
    expect(within(theirs as HTMLElement).getByText("Imported")).toBeInTheDocument();
  });

  it("filters by source from a select and keeps it in the URL", async () => {
    const user = renderApp("/findings", routes);
    await screen.findByRole("table");

    await user.selectOptions(screen.getByLabelText("Source"), "prowler");

    expect(screen.getByTestId("location")).toHaveTextContent("source=prowler");
    expect(screen.getByText(/Showing 2 of 3 findings/)).toBeInTheDocument();
    expect(screen.queryByText("Our own finding")).not.toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Source"), "cloudshield");

    expect(screen.getByText(/Showing 1 of 3 findings/)).toBeInTheDocument();
    expect(screen.getByText("Our own finding")).toBeInTheDocument();
  });

  it("names the source filter options CloudShield and Imported", async () => {
    renderApp("/findings", routes);
    await screen.findByRole("table");

    const options = within(screen.getByLabelText("Source")).getAllByRole("option");

    expect(options.map((o) => o.textContent)).toEqual([
      "All sources",
      "CloudShield",
      "Imported",
    ]);
    expect(options[2]).toHaveValue("prowler");
  });

  it("opens with the source filter set when the URL asks for it", async () => {
    renderApp("/findings?source=prowler", routes);

    expect(await screen.findByText(/Showing 2 of 3 findings/)).toBeInTheDocument();
    expect(screen.getByLabelText("Source")).toHaveValue("prowler");
  });

  it("labels a finding the newest import did not mention, with the import date", async () => {
    renderApp("/findings", routes);

    const label = await screen.findByText(/Not rechecked/);

    expect(label).toHaveTextContent(formatDate("2026-10-05T04:42:00Z"));
    expect(screen.getAllByText(/Not rechecked/)).toHaveLength(1);
  });

  it("keeps a long imported rule id on one line with the full id in a tooltip", async () => {
    const check = "iam_password_policy_expires_passwords_within_90_days_or_less";
    renderApp("/findings", {
      "GET /api/findings": [finding({ ...IMPORTED, rule_id: `PRW-${check}` })],
    });

    const tag = await screen.findByTitle(check);

    expect(tag).toHaveTextContent(check);
    expect(tag).not.toHaveTextContent("PRW-");
    expect(tag).toHaveClass("truncate");
  });
});

describe("Overview: lanes show at most five tiles", () => {
  function many(count: number, score: number) {
    return Array.from({ length: count }, (_, i) =>
      finding({
        finding_id: `F-${score}-${i}`,
        title: `Finding ${score}-${i}`,
        risk_score: score - i / 10,
        resource_id: `res-${score}-${i}`,
      }),
    );
  }
  const routes = (rows: ReturnType<typeof many>) => ({
    "GET /api/scans": [scan()],
    "GET /api/findings": rows,
    "GET /api/risk/summary": summary(),
  });

  it("shows five tiles and a See all link to that lane when a lane has more", async () => {
    renderApp("/", routes(many(8, 90)));

    const lane = await screen.findByRole("region", { name: "Fix now" });

    expect(within(lane).getAllByRole("heading", { level: 3 })).toHaveLength(5);
    expect(within(lane).getByRole("link", { name: /See all 8/ })).toHaveAttribute(
      "href",
      "/findings?lane=now",
    );
  });

  it("shows no See all link when the lane has five or fewer", async () => {
    renderApp("/", routes(many(5, 90)));

    const lane = await screen.findByRole("region", { name: "Fix now" });

    expect(within(lane).getAllByRole("heading", { level: 3 })).toHaveLength(5);
    expect(within(lane).queryByRole("link", { name: /See all/ })).not.toBeInTheDocument();
  });

  it("caps Next and Later too, each with its own link", async () => {
    renderApp("/", routes([...many(7, 70), ...many(6, 50)]));

    const next = await screen.findByRole("region", { name: "Next" });
    const later = screen.getByRole("region", { name: "Later" });

    expect(within(next).getByRole("link", { name: /See all 7/ })).toHaveAttribute(
      "href",
      "/findings?lane=next",
    );
    expect(within(later).getByRole("link", { name: /See all 6/ })).toHaveAttribute(
      "href",
      "/findings?lane=later",
    );
  });

  it("counts the open findings by source", async () => {
    renderApp("/", routes([own, imported, { ...imported, finding_id: "F-2" }]));

    expect(await screen.findByTestId("source-counts")).toHaveTextContent(
      "1 found by CloudShield, 2 imported",
    );
  });

  it("shows the check id without the PRW- prefix on an imported tile", async () => {
    renderApp("/", routes([imported]));

    const lane = await screen.findByRole("region", { name: "Later" });
    const tile = within(lane).getByRole("link", { name: "Password policy is weak" });

    expect(
      within(tile.closest("li") as HTMLElement).getByText("iam_x"),
    ).toBeInTheDocument();
  });

  it("puts the Imported badge on an imported tile", async () => {
    renderApp("/", routes([own, imported]));

    const lane = await screen.findByRole("region", { name: "Later" });
    const tile = within(lane).getByRole("link", { name: "Password policy is weak" });

    expect(
      within(tile.closest("li") as HTMLElement).getByText("Imported"),
    ).toBeInTheDocument();
  });
});

describe("Finding detail: imported finding", () => {
  const ID = IMPORTED.finding_id;
  const path = `/api/findings/${ID}`;
  const importedFix = fix({
    finding_id: ID,
    patches: [],
    guidance: ["Set the minimum length to 14.", "Reference: https://example.com/check"],
    blast_radius: {
      level: "unknown",
      factors: [],
      notes: ["Nothing known about dependents."],
    },
    generated_by: "template",
    model: null,
    explanation: {
      why_it_matters: "Short passwords are easy to guess.",
      what_changes: "No patch is generated.",
      what_could_break: "Blast radius: unknown.",
      cited: ["e1"],
      skipped_reason: "imported from an external tool: no AI explanation is generated",
    },
  });
  const routes = {
    [`GET ${path}`]: findingDetail({ ...IMPORTED, resource: null, not_rechecked: true }),
    [`POST ${path}/fix`]: importedFix,
  };

  it("shows the Imported badge and the not rechecked label in the header", async () => {
    renderApp(`/findings/${ID}`, routes);

    const heading = await screen.findByRole("heading", { level: 1 });
    const header = heading.parentElement as HTMLElement;

    expect(within(header).getByText("Imported")).toBeInTheDocument();
    expect(within(header).getByText(/Not rechecked/)).toBeInTheDocument();
  });

  it("shows the imported evidence as reported, never as verified", async () => {
    renderApp(`/findings/${ID}?tab=evidence`, routes);

    const panel = await screen.findByRole("tabpanel");

    expect(within(panel).getByText("reported")).toBeInTheDocument();
    expect(within(panel).queryByText("verified")).not.toBeInTheDocument();
    expect(screen.queryByText("Verified evidence")).not.toBeInTheDocument();
  });

  it("states on the Fix tab that the evidence comes from an external tool", async () => {
    renderApp(`/findings/${ID}?tab=fix`, routes);

    expect(
      await screen.findByText(
        "This comes from an external scanner. CloudShield did not collect this evidence.",
      ),
    ).toBeInTheDocument();
  });

  it("shows the external guidance with its links, no patch, unknown blast radius and no AI", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, routes);

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    await screen.findByText("Set the minimum length to 14.");
    const link = screen.getByRole("link", { name: "https://example.com/check" });
    expect(link).toHaveAttribute("href", "https://example.com/check");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(screen.queryByText("AI explanation")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Regenerate explanation" })).toBeNull();
    expect(callsTo("POST", `${path}/fix`)).toHaveLength(1);
  });

  it("does not offer a rescan to verify, because only a newer import can resolve it", async () => {
    renderApp(`/findings/${ID}?tab=fix`, routes);

    await screen.findByText(/external scanner/);

    expect(screen.queryByRole("region", { name: "Verify" })).not.toBeInTheDocument();
  });

  it("does not make a link from a reference that is not a web address", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      ...routes,
      [`POST ${path}/fix`]: fix({
        ...importedFix,
        guidance: ["Reference: javascript:alert(1)"],
      }),
    });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    expect(await screen.findByText("Reference: javascript:alert(1)")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /javascript/ })).not.toBeInTheDocument();
  });
});
