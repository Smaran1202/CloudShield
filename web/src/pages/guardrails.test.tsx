import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { finding, findingDetail, fix, guardrail, scan } from "../test/factories";
import { fail } from "../test/mockApi";
import { renderApp } from "../test/render";

const ID = "F-OWN-GUARD";
const path = `/api/findings/${ID}`;
const own = findingDetail({ finding_id: ID, rule_id: "CIS-S3-001" });

const account = guardrail({ status: "active" });
const org = guardrail({
  id: "s3-organization-block-public-access",
  title: "Block public access across the organization",
  kind: "organization_policy",
  scope: "organization",
  status: "needs_org_admin",
  patches: [
    {
      format: "cli",
      title: "Block public access across the organization (AWS CLI)",
      content: "aws organizations create-policy --type S3_POLICY\n",
      files: [{ name: "s3-block-public-access-policy.json", content: "{}\n" }],
      needs_input: false,
      inputs_needed: [],
      instructions_only: false,
    },
  ],
});
const pipeline = guardrail({
  id: "pipeline-s3-versioning",
  title: "Reject buckets without versioning in your pipeline",
  kind: "pipeline_check",
  scope: "resource",
  status: "unknown",
  patches: [
    {
      format: "github_actions",
      title: "Check bucket versioning with Checkov (GitHub Actions)",
      content: "name: CloudShield check S3 versioning\n",
      files: [],
      needs_input: false,
      inputs_needed: [],
      instructions_only: false,
    },
  ],
});

// `ready` waits for something that only appears once the fix has loaded.
async function openFix(
  guardrails = [account, org, pipeline],
  detail = own,
  ready = () => screen.findByText("Why it matters"),
) {
  const routes = {
    [`GET ${path}`]: detail,
    [`POST ${path}/fix`]: fix({ finding_id: ID, guardrails }),
  };
  const user = renderApp(`/findings/${ID}?tab=fix`, routes);
  await user.click(await screen.findByRole("button", { name: "Generate fix" }));
  await ready();
  return user;
}

function card(title: string): HTMLElement {
  return screen.getByRole("article", { name: title });
}

type User = Awaited<ReturnType<typeof openFix>>;

// A row is one line. Its details and patches open with its button.
async function expand(user: User, title: string) {
  await user.click(within(card(title)).getByRole("button", { name: new RegExp(title) }));
}

// The guardrails CloudShield cannot read are in one fold.
async function openCannotCheck(user: User) {
  await user.click(
    screen.getByRole("button", { name: /guardrails? CloudShield cannot check/ }),
  );
}

describe("Fix tab: Prevent it coming back", () => {
  it("shows the section under the fix with the promise that nothing is changed", async () => {
    const user = await openFix();

    const section = screen.getByRole("region", { name: "Prevent it coming back" });

    expect(
      within(section).getByRole("heading", { name: "Prevent it coming back" }),
    ).toBeInTheDocument();
    expect(section).toHaveTextContent(
      "Apply the fix first, then a guardrail stops it returning. CloudShield never changes your account.",
    );
    // One guardrail CloudShield can read is a row. The two it cannot read are in one fold.
    expect(within(section).getAllByRole("article")).toHaveLength(1);
    await openCannotCheck(user);
    expect(within(section).getAllByRole("article")).toHaveLength(3);
  });

  it("groups the guardrails CloudShield cannot check under one fold with their count", async () => {
    await openFix();

    const fold = screen.getByRole("button", {
      name: "2 guardrails CloudShield cannot check",
    });

    expect(fold).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByRole("article", { name: account.title })).toBeVisible();
    expect(screen.queryByRole("article", { name: org.title })).not.toBeInTheDocument();
  });

  it("says guardrail, not guardrails, for one", async () => {
    await openFix([account, pipeline]);

    expect(
      screen.getByRole("button", { name: "1 guardrail CloudShield cannot check" }),
    ).toBeInTheDocument();
  });

  it("has no fold when every guardrail can be read", async () => {
    await openFix([
      account,
      guardrail({ id: "g2", title: "Another one", status: "not_active" }),
    ]);

    expect(screen.getAllByRole("article")).toHaveLength(2);
    expect(
      screen.queryByRole("button", { name: /cannot check/ }),
    ).not.toBeInTheDocument();
  });

  it("shows one compact row for each guardrail: title, status chip and kind, and no details", async () => {
    await openFix();

    const row = card(account.title);

    expect(
      within(row).getByRole("button", { name: new RegExp(account.title) }),
    ).toHaveAttribute("aria-expanded", "false");
    expect(row.querySelector('[data-status="active"]')).not.toBeNull();
    expect(row).toHaveTextContent("Account setting");
    expect(within(row).queryByText("What this affects")).not.toBeVisible();
    expect(within(row).queryByRole("link", { name: "AWS documentation" })).toBeNull();
  });

  it("opens a row and a fold with the keyboard", async () => {
    const user = await openFix();
    const fold = screen.getByRole("button", { name: /cannot check/ });

    fold.focus();
    await user.keyboard("{Enter}");
    expect(fold).toHaveAttribute("aria-expanded", "true");
    const row = within(card(org.title)).getByRole("button", {
      name: new RegExp(org.title),
    });
    row.focus();
    await user.keyboard(" ");

    expect(row).toHaveAttribute("aria-expanded", "true");
    expect(within(card(org.title)).getByText("What this affects")).toBeVisible();
  });

  it("shows title, kind, scope, effects, cost and an AWS link once a row is opened", async () => {
    const user = await openFix();
    await expand(user, "Block public access for the whole account");

    const shown = card("Block public access for the whole account");

    expect(shown).toHaveTextContent("Account setting");
    expect(shown).toHaveTextContent("Whole account");
    expect(shown).toHaveTextContent("What this affects");
    expect(shown).toHaveTextContent("Applies to every bucket in the account.");
    expect(shown).toHaveTextContent("Cost");
    expect(shown).toHaveTextContent("Check pricing.");
    expect(
      within(shown).getByRole("link", { name: "AWS documentation" }),
    ).toHaveAttribute("href", account.docs_url);
  });

  it("shows each status as an icon and a label", async () => {
    const user = await openFix();
    await openCannotCheck(user);

    const chips = [
      [card(account.title), "active", "Active"],
      [card(org.title), "needs_org_admin", "Needs organization admin"],
      [card(pipeline.title), "unknown", "Unknown"],
    ] as const;

    for (const [shown, status, label] of chips) {
      const chip = shown.querySelector(`[data-status="${status}"]`) as HTMLElement;
      expect(chip).toHaveTextContent(label);
      expect(chip.querySelector("svg[data-icon]")).not.toBeNull();
    }
  });

  it("shows a not active status", async () => {
    await openFix([guardrail({ status: "not_active" })]);

    const chip = screen.getByText("Not active");

    expect(chip.closest("[data-status]")).toHaveAttribute("data-status", "not_active");
  });

  it("shows the patches with tabs and a Copy button for each guardrail", async () => {
    const user = await openFix();
    await expand(user, account.title);
    const panel = within(card(account.title)).getByRole("region", {
      name: `Patches for ${account.title}`,
    });

    expect(
      within(panel)
        .getAllByRole("tab")
        .map((t) => t.textContent),
    ).toEqual(["terraform", "cli"]);
    await user.click(within(panel).getByRole("tab", { name: "cli" }));

    expect(panel).toHaveTextContent("Needs your input before you use it");
    expect(panel).toHaveTextContent("Your 12-digit AWS account id");
    expect(
      within(panel).getByRole("button", {
        name: "Copy Block public access for the whole account (AWS CLI)",
      }),
    ).toBeInTheDocument();
  });

  it("shows a pipeline file and its extra files as copyable text", async () => {
    const user = await openFix();
    await openCannotCheck(user);

    const shown = card(pipeline.title);
    const orgCard = card(org.title);

    expect(shown).toHaveTextContent("name: CloudShield check S3 versioning");
    expect(orgCard).toHaveTextContent("s3-block-public-access-policy.json");
  });

  it("shows no section when a finding has no guardrails", async () => {
    await openFix([]);

    expect(screen.queryByText("Prevent it coming back")).not.toBeInTheDocument();
  });

  it("shows no section for an imported finding, even if guardrails were sent", async () => {
    const imported = findingDetail({
      finding_id: ID,
      rule_id: "PRW-s3_bucket_kms_encryption",
      source: "prowler",
    });

    // Only an imported finding has this region, so the fix really has loaded.
    await openFix([account], imported, () =>
      screen.findByRole("region", { name: "Risk reported by the scanner" }),
    );

    expect(screen.queryByText("Prevent it coming back")).not.toBeInTheDocument();
  });
});

describe("Overview: guardrail line", () => {
  const base = { "GET /api/scans": [scan()], "GET /api/findings": [finding()] };

  it("counts active and unknown guardrails", async () => {
    renderApp("/", {
      ...base,
      "GET /api/guardrails": [account, org, pipeline, guardrail({ status: "unknown" })],
    });

    expect(await screen.findByTestId("guardrail-line")).toHaveTextContent(
      "Guardrails: 1 active, 2 unknown.",
    );
  });

  it("says none are active when none were verified", async () => {
    renderApp("/", { ...base, "GET /api/guardrails": [pipeline] });

    expect(await screen.findByTestId("guardrail-line")).toHaveTextContent(
      "Guardrails: 0 active, 1 unknown.",
    );
  });

  it("says so when the guardrails cannot be read", async () => {
    renderApp("/", { ...base, "GET /api/guardrails": fail(500, "database is locked") });

    expect(await screen.findByTestId("guardrail-line")).toHaveTextContent(
      "Guardrails: could not be read.",
    );
  });
});
