import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { scoreSentence } from "../format";
import { finding, findingDetail, fix, scan } from "../test/factories";
import { callsTo } from "../test/mockApi";
import { never, renderApp } from "../test/render";

const ID = "F-PRW-pw-aaaaaaaa";
const path = `/api/findings/${ID}`;
const OWN = "F-OWN-1";

const STEPS = {
  check_id: "iam_password_policy_minimum_length_14",
  summary: "The account password policy allows short passwords.",
  steps: [
    {
      text: "See the password policy the account has now.",
      command: "aws iam get-account-password-policy",
    },
    { text: "Set the minimum password length to 14 or more.", command: null },
  ],
  before_you_apply: [
    "Tell your users first.",
    "The policy does not apply to the root user.",
  ],
  docs_url:
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
  verified_on: "2026-10-09",
};

const REMEDIATION =
  "Apply **least privilege** and enable **MFA**:\n- Use `customer-managed` policies\n- Review often";
const RISK = "**Weak passwords** make guessing easier, risking:\n- Account takeover";

const imported = findingDetail({
  finding_id: ID,
  rule_id: "PRW-iam_password_policy_minimum_length_14",
  source: "prowler",
  title: "Password policy is weak",
  severity: "HIGH",
  risk_score: 70,
  last_scan_id: null,
  resource: null,
  score_basis: "severity only",
  score_breakdown: {
    base: 70,
    base_source: "scanner",
    adjustments: 0,
    capped: false,
    basis: "severity only",
  },
  evidence: {
    items: [
      {
        fact: "Risk described by the scanner",
        value: RISK,
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
  finding_id: ID,
  patches: [],
  guidance: [REMEDIATION, "Reference: https://example.com/check"],
  pre_checks: STEPS.before_you_apply,
  not_checked: [],
  cloudshield_steps: STEPS,
  generated_by: "template",
  model: null,
  rollback: "No rollback steps are generated for an imported finding.",
  verify: "Run the full scan to verify.",
  explanation: {
    why_it_matters: RISK,
    what_changes: "",
    what_could_break: "",
    cited: ["e1"],
    skipped_reason: "CloudShield did not collect this evidence.",
  },
});

const routes = { [`GET ${path}`]: imported, [`POST ${path}/fix`]: importedFix };

async function openFix(extra: Record<string, unknown> = {}) {
  const user = renderApp(`/findings/${ID}?tab=fix`, { ...routes, ...extra });
  await user.click(await screen.findByRole("button", { name: "Generate fix" }));
  await screen.findByText("What to do");
  return user;
}

describe("Fix page: imported text is formatted", () => {
  it("shows the scanner's guidance with bold, code and a list, and no raw marks", async () => {
    await openFix();

    const card = screen
      .getByRole("heading", { name: "What the scanner recommends" })
      .closest("section") as HTMLElement;

    expect(card.querySelectorAll("strong")).toHaveLength(2);
    expect(card.querySelector("code")).toHaveTextContent("customer-managed");
    expect(within(card).getByText("Review often").closest("li")).not.toBeNull();
    expect(card.textContent).not.toContain("**");
    expect(card.textContent).not.toContain("`");
    expect(
      within(card).getByRole("link", { name: "https://example.com/check" }),
    ).toBeInTheDocument();
  });

  it("shows the scanner's risk with a Reported chip, formatted the same way", async () => {
    await openFix();

    const risk = screen.getByRole("region", { name: "Risk reported by the scanner" });

    expect(risk.querySelector("strong")).toHaveTextContent("Weak passwords");
    expect(within(risk).getByText("Account takeover").closest("li")).not.toBeNull();
    expect(risk.querySelector('[data-certainty="reported"]')).not.toBeNull();
    expect(risk.textContent).not.toContain("**");
  });

  it("shows a reported evidence text the same way on the Evidence tab, and an object as it was", async () => {
    renderApp(`/findings/${ID}?tab=evidence`, routes);

    const panel = await screen.findByRole("tabpanel");

    expect(panel.querySelector("strong")).toHaveTextContent("Weak passwords");
    expect(panel.textContent).not.toContain("**");
    expect(panel.querySelector("pre")).toHaveTextContent('"type": "Account"');
  });

  it("leaves the guidance of our own findings as plain text", async () => {
    const own = findingDetail({ finding_id: OWN });
    const user = renderApp(`/findings/${OWN}?tab=fix`, {
      [`GET /api/findings/${OWN}`]: own,
      [`POST /api/findings/${OWN}/fix`]: fix({
        guidance: [
          'Replace Action "*" with the actions needed, and Resource "*" with ARNs.',
        ],
      }),
    });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    expect(
      await screen.findByText(
        'Replace Action "*" with the actions needed, and Resource "*" with ARNs.',
      ),
    ).toBeInTheDocument();
  });
});

describe("Fix page: What to do", () => {
  it("shows the section with its label, summary, steps and documentation link", async () => {
    await openFix();

    const section = screen.getByRole("region", { name: "What to do" });

    expect(
      within(section).getByText(
        "Steps written by CloudShield. Check them against the AWS documentation before you act.",
      ),
    ).toBeInTheDocument();
    expect(within(section).getByText(STEPS.summary)).toBeInTheDocument();
    const items = within(section).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    const link = within(section).getByRole("link", { name: "AWS documentation" });
    expect(link).toHaveAttribute("href", STEPS.docs_url);
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(section).toHaveTextContent("read on 2026-10-09");
  });

  it("shows a command in a code block with a copy button that really copies", async () => {
    const user = await openFix();
    const writeText = vi.spyOn(navigator.clipboard, "writeText");

    const section = screen.getByRole("region", { name: "What to do" });
    expect(section.querySelector("code")).toHaveTextContent(
      "aws iam get-account-password-policy",
    );
    await user.click(
      within(section).getByRole("button", { name: /Copy command for step 1/ }),
    );

    expect(writeText).toHaveBeenCalledWith("aws iam get-account-password-policy");
  });

  it("puts the section before the scanner's own guidance", async () => {
    await openFix();

    const todo = screen.getByRole("region", { name: "What to do" });
    const guidance = screen.getByRole("heading", { name: "What the scanner recommends" });

    expect(
      todo.compareDocumentPosition(guidance) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("is left out when the check has no entry, and the generic guidance stays", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      ...routes,
      [`POST ${path}/fix`]: { ...importedFix, cloudshield_steps: null },
    });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    await screen.findByRole("heading", { name: "What the scanner recommends" });
    expect(screen.queryByRole("region", { name: "What to do" })).not.toBeInTheDocument();
  });

  it("uses the steps' before-you-apply items as the checklist", async () => {
    await openFix();

    const card = screen
      .getByRole("heading", { name: "Before you apply it" })
      .closest("section") as HTMLElement;

    expect(within(card).getAllByRole("checkbox")).toHaveLength(2);
    expect(within(card).getByText("Tell your users first.")).toBeInTheDocument();
  });

  it("is not shown for our own findings", async () => {
    const own = findingDetail({ finding_id: OWN });
    const user = renderApp(`/findings/${OWN}?tab=fix`, {
      [`GET /api/findings/${OWN}`]: own,
      [`POST /api/findings/${OWN}/fix`]: fix(),
    });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    await screen.findByText("Why it matters");
    expect(screen.queryByRole("region", { name: "What to do" })).not.toBeInTheDocument();
  });
});

describe("Fix page: each caveat once, and no blast radius", () => {
  it("says the evidence comes from an external scanner once", async () => {
    await openFix();

    expect(screen.getAllByText(/This comes from an external scanner/)).toHaveLength(1);
    expect(screen.queryAllByText(/did not collect this evidence/i)).toHaveLength(1);
  });

  it("does not repeat unknown or not-collected lines for an imported finding", async () => {
    await openFix();

    const panel = screen.getByRole("tabpanel");

    expect(within(panel).queryByText(/^unknown$/i)).not.toBeInTheDocument();
    expect(within(panel).queryByText(/not collected/i)).not.toBeInTheDocument();
    expect(
      within(panel).queryByRole("heading", { name: "Rollback" }),
    ).not.toBeInTheDocument();
  });

  it("has no blast radius on the screen, imported or our own", async () => {
    await openFix();
    expect(document.body.textContent?.toLowerCase()).not.toContain("blast");
  });

  it("lists what CloudShield did not check for our own finding", async () => {
    const own = findingDetail({ finding_id: OWN });
    const user = renderApp(`/findings/${OWN}?tab=fix`, {
      [`GET /api/findings/${OWN}`]: own,
      [`POST /api/findings/${OWN}/fix`]: fix({ not_checked: ["Static website hosting"] }),
    });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    const card = (
      await screen.findByRole("heading", { name: "CloudShield did not check" })
    ).closest("section") as HTMLElement;
    expect(within(card).getByText("Static website hosting")).toBeInTheDocument();
    expect(document.body.textContent?.toLowerCase()).not.toContain("blast");
  });

  it("names the second step of the stepper Check before you apply", async () => {
    renderApp(`/findings/${ID}`, routes);

    const list = await screen.findByRole("list", { name: "Progress" });

    expect(within(list).getByText("Check before you apply")).toBeInTheDocument();
    expect(list.textContent?.toLowerCase()).not.toContain("blast");
  });
});

describe("Fix page: plain words", () => {
  it("is a closed fold-out that lists only the terms in the finding's own text", async () => {
    await openFix();

    const words = screen
      .getByText(/Plain words \(\d+\)/)
      .closest("details") as HTMLDetailsElement;

    expect(words.open).toBe(false);
    const terms = Array.from(words.querySelectorAll("dt")).map((dt) => dt.textContent);
    expect(terms).toEqual(expect.arrayContaining(["Least privilege", "MFA"]));
    expect(terms).not.toContain("Network ACL");
    expect(terms).not.toContain("Lateral movement");
    expect(words.querySelectorAll("dd").length).toBe(terms.length);
  });

  it("opens with a click or tap on its heading, and shows each meaning in words", async () => {
    const user = await openFix();
    const summary = screen.getByText(/Plain words \(\d+\)/);

    await user.click(summary);

    const words = summary.closest("details") as HTMLDetailsElement;
    expect(words.open).toBe(true);
    expect(within(words).getByText(/only the permissions it needs/i)).toBeInTheDocument();
    expect(summary.tagName).toBe("SUMMARY");
  });

  it("is left out when no hard word is used", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      ...routes,
      [`GET ${path}`]: { ...imported, evidence: { items: [] } },
      [`POST ${path}/fix`]: {
        ...importedFix,
        guidance: ["Do the simple thing."],
        cloudshield_steps: null,
        explanation: { ...importedFix.explanation, why_it_matters: "" },
      },
    });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    await screen.findByText("Do the simple thing.");
    expect(screen.queryByText(/Plain words/)).not.toBeInTheDocument();
  });

  it("also finds the terms that CloudShield's own steps use", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      ...routes,
      [`GET ${path}`]: { ...imported, evidence: { items: [] } },
      [`POST ${path}/fix`]: {
        ...importedFix,
        guidance: ["Plain advice."],
        explanation: { ...importedFix.explanation, why_it_matters: "" },
        cloudshield_steps: {
          ...STEPS,
          steps: [{ text: "Network ACLs are stateless.", command: null }],
        },
      },
    });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    await screen.findByText("What to do");
    const terms = Array.from(document.querySelectorAll("details dt")).map(
      (d) => d.textContent,
    );
    expect(terms).toEqual(expect.arrayContaining(["Network ACL", "Stateless"]));
  });
});

describe("Fix page: verify an imported finding with a full scan", () => {
  const AVAILABLE = { available: true, version: "5", reason: null, hint: null };

  function verifyRoutes(after: unknown, run = scan({ id: 9, extended_status: "ok" })) {
    let reads = 0;
    return {
      "GET /api/extended/status": AVAILABLE,
      [`GET ${path}`]: () => (++reads === 1 ? imported : after),
      "POST /api/scans": scan({ id: 9, status: "queued" }),
      "GET /api/scans/9": run,
      "GET /api/findings": [finding({ finding_id: ID, status: "RESOLVED" }), finding()],
    };
  }

  async function runVerify(routesToUse: Record<string, unknown>) {
    const user = renderApp(`/findings/${ID}?tab=fix`, { ...routes, ...routesToUse });
    const button = await screen.findByRole("button", { name: "Run full scan to verify" });
    await waitFor(() => expect(button).toBeEnabled());
    await user.click(button);
    return user;
  }

  it("shows the button with the manual alternative", async () => {
    renderApp(`/findings/${ID}?tab=fix`, {
      ...routes,
      "GET /api/extended/status": AVAILABLE,
    });

    const panel = await screen.findByRole("region", { name: "Verify with a full scan" });

    expect(
      within(panel).getByRole("button", { name: "Run full scan to verify" }),
    ).toBeInTheDocument();
    expect(panel).toHaveTextContent("python -m cloudshield.imports prowler <file>");
  });

  it("is disabled with the reason and hint when the full scan cannot run", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      ...routes,
      "GET /api/extended/status": {
        available: false,
        version: null,
        reason: "Prowler was not found.",
        hint: "Set PROWLER_PYTHON.",
      },
    });

    const button = await screen.findByRole("button", { name: "Run full scan to verify" });
    const note = await screen.findByRole("note");

    expect(button).toBeDisabled();
    expect(note).toHaveTextContent("Prowler was not found.");
    expect(note).toHaveTextContent("Set PROWLER_PYTHON.");
    await user.click(button);
    expect(callsTo("POST", "/api/scans")).toHaveLength(0);
  });

  it("starts the scan with the extended checks on", async () => {
    await runVerify(verifyRoutes(imported));

    await waitFor(() => expect(callsTo("POST", "/api/scans")).toHaveLength(1));
    expect(callsTo("POST", "/api/scans")[0].body).toEqual({ extended: true });
  });

  it("says Resolved only after the finding has been fetched again and is resolved", async () => {
    await runVerify(verifyRoutes({ ...imported, status: "RESOLVED" }));

    expect(await screen.findByText("Resolved.")).toBeInTheDocument();
    expect(callsTo("GET", path).length).toBeGreaterThanOrEqual(2);
  });

  it("does not celebrate while the finding is still being fetched again", async () => {
    let reads = 0;
    await runVerify({
      ...verifyRoutes(imported),
      [`GET ${path}`]: () => (++reads === 1 ? imported : never()),
    });

    await waitFor(() => expect(reads).toBe(2));

    expect(screen.queryByText("Resolved.")).not.toBeInTheDocument();
    expect(screen.queryByText(/Still open/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Not rechecked/)).not.toBeInTheDocument();
  });

  it("says Still open when the check ran and the finding is still there", async () => {
    await runVerify(verifyRoutes({ ...imported, not_rechecked: false }));

    expect(await screen.findByText(/Still open\./)).toBeInTheDocument();
    expect(screen.queryByText("Resolved.")).not.toBeInTheDocument();
  });

  it("says Not rechecked when the finding was not in that scan's results", async () => {
    await runVerify(verifyRoutes({ ...imported, not_rechecked: true }));

    expect(
      await screen.findByText(/Not rechecked\. This check did not run in that scan\./),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Still open/)).not.toBeInTheDocument();
    expect(screen.queryByText("Resolved.")).not.toBeInTheDocument();
  });

  it("says Not rechecked, with the reason, when the extended checks failed", async () => {
    const failed = scan({
      id: 9,
      extended_status: "failed",
      extended_message: "Prowler stopped with exit code 1.",
    });
    await runVerify(verifyRoutes(imported, failed));

    const note = await screen.findByText(/Not rechecked\./);

    expect(note).toHaveTextContent("Prowler stopped with exit code 1.");
    expect(screen.queryByText("Resolved.")).not.toBeInTheDocument();
  });

  it("shows the progress of the scan and never a percentage", async () => {
    const running = scan({
      id: 9,
      status: "running",
      progress: "Running extended checks",
    });
    await runVerify(verifyRoutes(imported, running));

    expect(
      await screen.findAllByText(/Scan 9 running: Running extended checks/),
    ).not.toHaveLength(0);
    expect(screen.queryByText(/\d\s?%/)).not.toBeInTheDocument();
  });

  it("is not shown for our own findings, which keep the plain rescan", async () => {
    const own = findingDetail({ finding_id: OWN });
    const user = renderApp(`/findings/${OWN}?tab=fix`, {
      [`GET /api/findings/${OWN}`]: own,
      [`POST /api/findings/${OWN}/fix`]: fix(),
    });

    await user.click(await screen.findByRole("button", { name: "Generate fix" }));

    await screen.findByRole("region", { name: "Verify" });
    expect(
      screen.queryByRole("region", { name: "Verify with a full scan" }),
    ).not.toBeInTheDocument();
  });
});

describe("Score: how it was made", () => {
  function sentence(overrides: Parameters<typeof finding>[0]) {
    return scoreSentence(finding(overrides));
  }

  it("says an imported score with no scan data came from the scanner's rating alone", () => {
    expect(
      sentence({
        source: "prowler",
        severity: "HIGH",
        risk_score: 70,
        score_breakdown: {
          base: 70,
          base_source: "scanner",
          adjustments: 0,
          capped: false,
          basis: "severity only",
        },
      }),
    ).toBe(
      "70 = 70 from the scanner's HIGH rating + 0 from CloudShield context. No scan data for this resource.",
    );
  });

  it("says an imported score that our own scan raised, without the no-data line", () => {
    expect(
      sentence({
        source: "prowler",
        severity: "HIGH",
        risk_score: 85,
        score_breakdown: {
          base: 70,
          base_source: "scanner",
          adjustments: 15,
          capped: false,
          basis: "context adjusted",
        },
      }),
    ).toBe("85 = 70 from the scanner's HIGH rating + 15 from CloudShield context.");
  });

  it("says our own score came from the rule rating plus context", () => {
    expect(sentence({ risk_score: 95 })).toBe(
      "95 = 70 from the HIGH rule rating + 25 from CloudShield context.",
    );
  });

  it("says when a score was capped at 100", () => {
    expect(
      sentence({
        severity: "CRITICAL",
        risk_score: 100,
        score_breakdown: {
          base: 90,
          base_source: "cloudshield",
          adjustments: 25,
          capped: true,
          basis: "context adjusted",
        },
      }),
    ).toBe(
      "100 = 90 from the CRITICAL rule rating + 25 from CloudShield context. Capped at 100.",
    );
  });

  it("says nothing for a finding with no score", () => {
    expect(sentence({ risk_score: null, score_breakdown: null })).toBeNull();
  });

  it("shows the sentence on the finding page and on the Risk tab", async () => {
    renderApp(`/findings/${ID}?tab=risk`, routes);

    await screen.findByRole("tabpanel");
    const expected =
      "70 = 70 from the scanner's HIGH rating + 0 from CloudShield context. No scan data for this resource.";

    expect(screen.getByTestId("score-how-header")).toHaveTextContent(expected);
    expect(screen.getByTestId("score-how")).toHaveTextContent(expected);
  });
});
