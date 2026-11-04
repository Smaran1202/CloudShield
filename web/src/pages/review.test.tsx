import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { finding, findingDetail, fix, guardrail, scan } from "../test/factories";
import { renderApp } from "../test/render";

const MASK = "•".repeat(8);
const ID = "F-OWN-REVIEW";
const path = `/api/findings/${ID}`;

describe("Account ids are masked on screen", () => {
  it("masks a 12-digit number in the title of the finding page", async () => {
    renderApp(`/findings/${ID}`, {
      [`GET ${path}`]: findingDetail({
        finding_id: ID,
        title: "Role 123456789012 allows all actions",
      }),
    });

    const heading = await screen.findByRole("heading", { level: 1 });

    expect(heading).toHaveTextContent(`Role ${MASK}9012 allows all actions`);
    expect(heading.textContent).not.toContain("123456789012");
  });

  it("masks a 12-digit number in a title in the Findings list", async () => {
    renderApp("/findings?lane=open", {
      "GET /api/findings": [
        finding({ finding_id: ID, title: "Trail for 123456789012 is off" }),
      ],
    });

    const link = await screen.findByRole("link", { name: /Trail for/ });

    expect(link).toHaveTextContent(`Trail for ${MASK}9012 is off`);
    expect(document.body.textContent).not.toContain("123456789012");
  });

  it("masks a 12-digit number in a title on the Overview", async () => {
    renderApp("/", {
      "GET /api/scans": [scan()],
      "GET /api/findings": [
        finding({
          finding_id: ID,
          title: "Policy of 123456789012 is open",
          risk_score: 90,
        }),
      ],
    });

    await screen.findByRole("region", { name: "Fix now" });

    expect(document.body.textContent).toContain(`Policy of ${MASK}9012 is open`);
    expect(document.body.textContent).not.toContain("123456789012");
  });

  it("masks a 12-digit number in an imported paragraph, and leaves other digit runs alone", async () => {
    const text =
      "Account 123456789012 has **no** trail. Short 12345678901, long 1234567890123.";
    renderApp(`/findings/${ID}?tab=evidence`, {
      [`GET ${path}`]: findingDetail({
        finding_id: ID,
        source: "prowler",
        evidence: {
          items: [
            {
              fact: "Risk",
              value: text,
              source: "imported scan output",
              certainty: "reported",
            },
          ],
        },
      }),
    });

    const panel = await screen.findByRole("tabpanel");

    expect(panel).toHaveTextContent(`Account ${MASK}9012 has no trail.`);
    expect(panel).toHaveTextContent("Short 12345678901, long 1234567890123.");
    // The 13-digit number contains 12 of the same digits, so look for a run of exactly 12.
    expect(panel.textContent).not.toMatch(/(?<!\d)\d{12}(?!\d)/);
  });

  it("masks the fact and the value of an evidence item", async () => {
    renderApp(`/findings/${ID}?tab=evidence`, {
      [`GET ${path}`]: findingDetail({
        finding_id: ID,
        evidence: {
          items: [
            {
              fact: "Policy of 123456789012 allows *",
              value: { arn: "arn:aws:iam::123456789012:policy/p" },
              source: "attributes.document",
              certainty: "verified",
            },
          ],
        },
      }),
    });

    const panel = await screen.findByRole("tabpanel");

    expect(panel).toHaveTextContent(`Policy of ${MASK}9012 allows *`);
    expect(panel.querySelector("pre")).toHaveTextContent(
      `arn:aws:iam::${MASK}9012:policy/p`,
    );
    expect(panel.textContent).not.toContain("123456789012");
  });

  it("masks an evidence fact in the list on the Fix tab", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      [`GET ${path}`]: findingDetail({
        finding_id: ID,
        evidence: {
          items: [
            { fact: "Owner 123456789012", value: 1, source: "s", certainty: "verified" },
          ],
        },
      }),
      [`POST ${path}/fix`]: fix({ finding_id: ID }),
    });
    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    await screen.findByText("Why it matters");

    expect(screen.getByText(`Owner ${MASK}9012`)).toBeInTheDocument();
  });

  it("does not change the patch text a person copies", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      [`GET ${path}`]: findingDetail({ finding_id: ID }),
      [`POST ${path}/fix`]: fix({ finding_id: ID }),
    });
    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    await screen.findByText("Why it matters");

    expect(document.body.textContent).not.toContain(MASK);
  });
});

describe("Mitigated by the account-wide block", () => {
  const CHIP = "Mitigated by the account-wide block";

  it("shows the chip on the finding page, and keeps the finding open", async () => {
    renderApp(`/findings/${ID}`, {
      [`GET ${path}`]: findingDetail({
        finding_id: ID,
        mitigated_by_account_block: true,
      }),
    });

    expect(await screen.findByText(CHIP)).toBeInTheDocument();
    expect(screen.getByText("Open")).toBeInTheDocument();
  });

  it("shows the chip on a row of the Findings list", async () => {
    renderApp("/findings?lane=open", {
      "GET /api/findings": [
        finding({ finding_id: ID, mitigated_by_account_block: true }),
        finding({ finding_id: "F-OTHER", title: "Another finding" }),
      ],
    });

    await screen.findByRole("link", { name: "Another finding" });

    expect(screen.getAllByText(CHIP)).toHaveLength(1);
  });

  it("shows no chip when the finding is not mitigated", async () => {
    renderApp(`/findings/${ID}`, { [`GET ${path}`]: findingDetail({ finding_id: ID }) });

    await screen.findByRole("heading", { level: 1 });

    expect(screen.queryByText(CHIP)).not.toBeInTheDocument();
  });
});

describe("Fix page text", () => {
  async function openFix(overrides = {}) {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      [`GET ${path}`]: findingDetail({ finding_id: ID }),
      [`POST ${path}/fix`]: fix({ finding_id: ID, ...overrides }),
    });
    await user.click(await screen.findByRole("button", { name: "Generate fix" }));
    await screen.findByText("Why it matters");
  }

  it("says to run a scan to verify, with no API path", async () => {
    await openFix();

    expect(screen.getByText(/Run a scan to verify\./)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("POST /api/scans");
  });

  it("shows a cost line only when the guardrail has one", async () => {
    await openFix({
      guardrails: [
        guardrail({ status: "active", cost: "The pricing page lists $0.003 per item." }),
        guardrail({
          id: "g2",
          title: "A guardrail with no known cost",
          status: "active",
          cost: null,
        }),
      ],
    });

    const priced = screen.getByRole("article", {
      name: "Block public access for the whole account",
    });
    const unpriced = screen.getByRole("article", {
      name: "A guardrail with no known cost",
    });

    expect(within(priced).getByText("Cost")).toBeInTheDocument();
    expect(priced).toHaveTextContent("The pricing page lists $0.003 per item.");
    expect(within(unpriced).queryByText("Cost")).not.toBeInTheDocument();
    expect(unpriced).not.toHaveTextContent("Check pricing");
  });

  it("wraps a long command instead of cutting it off, and keeps the Copy button above it", async () => {
    const command = `aws s3control put-public-access-block --account-id ${"A".repeat(200)}\n`;
    await openFix({
      patches: [
        {
          format: "cli",
          title: "A long command",
          content: command,
          files: [],
          needs_input: false,
          inputs_needed: [],
          instructions_only: false,
        },
      ],
    });

    const block = screen.getByRole("button", { name: "Copy A long command" })
      .parentElement?.parentElement as HTMLElement;
    const code = block.querySelector("pre") as HTMLElement;

    expect(code).toHaveClass("whitespace-pre-wrap");
    expect(code).not.toHaveClass("overflow-x-auto");
    expect(code.className).toContain("overflow-wrap:anywhere");
    expect(code.textContent).toBe(command);
    expect(
      code.contains(screen.getByRole("button", { name: "Copy A long command" })),
    ).toBe(false);
  });
});
