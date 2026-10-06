import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { formatDate } from "../format";
import { certaintySummary } from "./Overview";
import { callsTo, fail } from "../test/mockApi";
import { finding, scan, summary } from "../test/factories";
import { never, renderApp } from "../test/render";

const ARN = "arn:aws:iam::123456789012:policy/deploy";

function row(id: string, score: number | null, overrides = {}) {
  return finding({
    finding_id: `F-${id}`,
    risk_score: score,
    title: `Finding ${id}`,
    resource_id: `res-${id}`,
    ...overrides,
  });
}

const rows = [
  row("A", 95, { title: "Open SSH to the world", rule_id: "CIS-SG-001" }),
  row("B", 85, { title: "Public bucket", rule_id: "CIS-S3-001" }),
  row("C", 70, { title: "Wildcard policy", rule_id: "CIS-IAM-001", resource_id: ARN }),
  row("D", 59),
  row("E", 40),
  row("I", null, { severity: "INFO", title: "Default encryption" }),
  row("R1", 90, {
    status: "RESOLVED",
    resolved_at: "2026-10-02T10:00:00Z",
    title: "Old fix",
  }),
  row("R2", 75, {
    status: "RESOLVED",
    resolved_at: "2026-10-04T10:00:00Z",
    title: "Newest fix",
  }),
];

const results = {
  "GET /api/scans": [scan()],
  "GET /api/findings": rows,
  "GET /api/risk/summary": summary({ environment_score: 99.8 }),
};

function lane(name: string): HTMLElement {
  return screen.getByRole("region", { name });
}

function tile(name: string): HTMLElement {
  return within(lane("Fix now")).getByRole("link", { name }).closest("li") as HTMLElement;
}

describe("Overview: before a scan", () => {
  it("shows a skeleton shaped like the board, and says it is loading, while the scans are fetched", async () => {
    renderApp("/", { "GET /api/scans": never });

    expect(screen.getByText("Loading scans...")).toBeInTheDocument();
    expect(document.querySelectorAll(".skeleton").length).toBeGreaterThan(3);
    await screen.findByText(/API online/);
  });

  it("shows the backend's message when the scans cannot be loaded, and can retry", async () => {
    let attempts = 0;
    const user = renderApp("/", {
      "GET /api/scans": () => (++attempts === 1 ? fail(500, "database is locked") : []),
    });

    expect(await screen.findByRole("alert")).toHaveTextContent("database is locked");
    await user.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByText("No scan yet. Run a scan.")).toBeInTheDocument();
  });

  it("says there is no scan yet, with no numbers and no lanes", async () => {
    renderApp("/", { "GET /api/scans": [] });

    expect(await screen.findByText("No scan yet. Run a scan.")).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Fix now" })).not.toBeInTheDocument();
    expect(screen.queryByText(/fixed\./)).not.toBeInTheDocument();
    expect(screen.queryByText(/to go\./)).not.toBeInTheDocument();
    expect(callsTo("GET", "/api/findings")).toHaveLength(0);
    expect(callsTo("GET", "/api/risk/summary")).toHaveLength(0);
  });

  it("still says no scan yet when the only scan failed, and shows why", async () => {
    const failed = scan({
      status: "failed",
      failure_message: "ProfileNotFound: The config profile (nope) could not be found",
      finished_at: null,
    });
    renderApp("/", { "GET /api/scans": [failed] });

    expect(await screen.findByText("No scan yet. Run a scan.")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("ProfileNotFound");
  });
});

describe("Overview: the hero", () => {
  it("counts the fixed and the open findings in the headline", async () => {
    renderApp("/", results);

    const headline = await screen.findByRole("heading", { level: 1 });
    expect(within(headline).getByText("2 fixed.")).toBeInTheDocument();
    expect(within(headline).getByText("6 to go.")).toBeInTheDocument();
  });

  it("says to start with the highest-risk open finding", async () => {
    renderApp("/", results);

    const sentence = (await screen.findByText(/Start with/)).closest("p") as HTMLElement;
    expect(sentence).toHaveTextContent("Start with Open SSH to the world.");
    expect(within(sentence).getByRole("link")).toHaveAttribute("href", "/findings/F-A");
  });

  it("is two columns on a wide screen: the headline on the left, the Fix next card on the right", async () => {
    renderApp("/", results);

    const hero = await screen.findByTestId("hero");

    expect(hero).toHaveClass("min-[1100px]:grid-cols-[1.4fr_1fr]");
    expect(hero.children).toHaveLength(2);
    expect(
      within(hero.children[0] as HTMLElement).getByRole("heading", { level: 1 }),
    ).toBeVisible();
    expect(hero.children[1]).toBe(screen.getByRole("region", { name: "Fix next" }));
  });

  it("shows the Fix next card for the highest-risk open finding, with a 140px lane-coloured score", async () => {
    renderApp("/", results);

    const card = await screen.findByRole("region", { name: "Fix next" });
    const score = card.querySelector('[data-lane="now"]') as HTMLElement;
    expect(score).toHaveTextContent("95");
    expect(score).toHaveClass("h-[140px]");
    expect(score).toHaveClass("w-[140px]");
    expect(score).toHaveClass("bg-red");
    expect(within(card).getByText("Open SSH to the world")).toBeInTheDocument();
    expect(within(card).getByText("res-A")).toHaveAttribute("title", "res-A");
  });

  it("summarises how much of the evidence is verified, from the real evidence items", async () => {
    renderApp("/", results);

    const card = await screen.findByRole("region", { name: "Fix next" });

    expect(card).toHaveTextContent("1 verified, 1 heuristic, 1 unknown");
  });

  it("gives the Fix next card a primary Open fix button that goes to the Fix tab", async () => {
    renderApp("/", results);

    const card = await screen.findByRole("region", { name: "Fix next" });
    const button = within(card).getByRole("link", { name: /Open fix/ });

    expect(button).toHaveAttribute("href", "/findings/F-A?tab=fix");
    expect(button).toHaveClass("bg-ink");
    expect(button).toHaveClass("min-h-12");
  });

  it("leaves the Fix next card out, and the hero single-column, when nothing scored is open", async () => {
    renderApp("/", {
      ...results,
      "GET /api/findings": [row("I", null, { severity: "INFO" })],
    });

    expect(
      await screen.findByText("Only informational findings are open."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Fix next" })).not.toBeInTheDocument();
    expect(screen.getByTestId("hero")).not.toHaveClass(
      "min-[1100px]:grid-cols-[1.4fr_1fr]",
    );
  });

  it("explains the lane thresholds and that CloudShield never changes the account", async () => {
    renderApp("/", results);

    const text = await screen.findByText(/Fix now is a risk score of 80 or more/);
    expect(text).toHaveTextContent("Next is 60 to 79");
    expect(text).toHaveTextContent("Later is below 60");
    expect(text).toHaveTextContent("never changes your AWS account");
  });

  it("says nothing is open when every finding is fixed", async () => {
    renderApp("/", {
      ...results,
      "GET /api/findings": [row("R", 80, { status: "RESOLVED" })],
    });

    expect(await screen.findByText("Nothing is open.")).toBeInTheDocument();
    expect(screen.getByText("0 to go.")).toBeInTheDocument();
  });
});

describe("certaintySummary", () => {
  const item = (certainty: "verified" | "heuristic" | "unknown") => ({
    fact: "x",
    value: null,
    source: "s",
    certainty,
  });

  it("counts each kind of evidence, leaving out the kinds that are not there", () => {
    expect(
      certaintySummary([
        item("verified"),
        item("verified"),
        item("verified"),
        item("unknown"),
      ]),
    ).toBe("3 verified, 1 unknown");
    expect(certaintySummary([item("heuristic")])).toBe("1 heuristic");
  });

  it("says so when there is no evidence", () => {
    expect(certaintySummary([])).toBe("No evidence stored yet");
  });
});

describe("Overview: the lanes", () => {
  it("places open findings in the lanes by score, highest first", async () => {
    renderApp("/", results);

    await screen.findByRole("region", { name: "Fix now" });
    const now = within(lane("Fix now")).getAllByRole("link");
    const next = within(lane("Next")).getAllByRole("link");
    const later = within(lane("Later")).getAllByRole("link");
    expect(now.map((l) => l.getAttribute("href"))).toEqual([
      "/findings/F-A",
      "/findings/F-B",
    ]);
    expect(next.map((l) => l.getAttribute("href"))).toEqual(["/findings/F-C"]);
    expect(later.map((l) => l.getAttribute("href"))).toContain("/findings/F-D");
  });

  it("gives each lane its natural height, so no coloured area is left empty", async () => {
    renderApp("/", results);

    await screen.findByRole("region", { name: "Fix now" });

    for (const name of ["Fix now", "Next", "Later"])
      expect(lane(name)).toHaveClass("self-start");
    expect(lane("Fix now").parentElement).toHaveClass("items-start");
  });

  it("shows each lane's name, count and hint", async () => {
    renderApp("/", results);

    await screen.findByRole("region", { name: "Fix now" });
    expect(
      within(lane("Fix now")).getByRole("heading", { name: "Fix now" }),
    ).toBeInTheDocument();
    expect(within(lane("Fix now")).getByText("2")).toBeInTheDocument();
    expect(
      within(lane("Fix now")).getByText("Risk score 80 or more"),
    ).toBeInTheDocument();
    expect(within(lane("Next")).getByText("1")).toBeInTheDocument();
    expect(within(lane("Later")).getByText("3")).toBeInTheDocument();
  });

  it("shows an honest message in a lane that is empty", async () => {
    renderApp("/", { ...results, "GET /api/findings": [row("A", 95)] });

    await screen.findByRole("region", { name: "Next" });
    expect(
      within(lane("Next")).getByText("Nothing is open between 60 and 79."),
    ).toBeInTheDocument();
    expect(
      within(lane("Later")).getByText("Nothing scored below 60 is open."),
    ).toBeInTheDocument();
  });

  it("shows the findings with no score as one dashed summary row in Later, not as tiles", async () => {
    renderApp("/", results);

    await screen.findByRole("region", { name: "Later" });
    const summaryRow = within(lane("Later")).getByText(
      /1 informational finding with no risk score/,
    );
    expect(summaryRow.closest("li")).toHaveClass("border-dashed");
    expect(
      within(lane("Later")).queryByRole("link", { name: /Default encryption/ }),
    ).toBeNull();
    expect(within(lane("Later")).getByRole("link", { name: "See them" })).toHaveAttribute(
      "href",
      "/findings?lane=later",
    );
  });

  it("makes the Fix now score 88px and the other scores 64px, with 24px padding", async () => {
    renderApp("/", results);

    await screen.findByRole("region", { name: "Fix now" });

    expect(
      tile("Open SSH to the world").querySelector(".text-score-lane"),
    ).toHaveTextContent("95");
    const next = within(lane("Next"))
      .getByRole("link", { name: "Wildcard policy" })
      .closest("li");
    expect(next?.querySelector(".text-score-tile")).toHaveTextContent("70");
    expect(tile("Open SSH to the world")).toHaveClass("p-6");
  });

  it("shows a tile with the score, rule tag, severity chip, title, resource and an Open fix footer", async () => {
    renderApp("/", results);

    await screen.findByRole("region", { name: "Fix now" });
    const t = tile("Open SSH to the world");

    expect(within(t).getByText("CIS-SG-001")).toBeInTheDocument();
    expect(within(t).getByText("HIGH")).toBeInTheDocument();
    expect(within(t).getByRole("heading", { level: 3 })).toHaveClass("line-clamp-3");
    expect(within(t).getByText("res-A")).toHaveAttribute("title", "res-A");
    expect(within(t).getByText("Open fix")).toBeInTheDocument();
    expect(t.querySelector('svg[data-icon="arrow"]')).not.toBeNull();
  });

  it("shows a real arrow icon on the tile, and no arrow or other glyph typed as text", async () => {
    renderApp("/", results);

    await screen.findByRole("region", { name: "Fix now" });

    expect(document.body.textContent).not.toMatch(/[\u2190-\u21ff\u00e2]/);
  });

  it("shortens an ARN on the tile and keeps the full value in the title", async () => {
    renderApp("/", results);

    const short = await screen.findByText("...:policy/deploy");

    expect(short).toHaveAttribute("title", ARN);
  });

  it("copies the resource id from a button on the tile, and shows it was copied", async () => {
    const user = renderApp("/", results);
    await screen.findByRole("region", { name: "Fix now" });
    const writeText = vi.spyOn(navigator.clipboard, "writeText");

    const button = within(tile("Open SSH to the world")).getByRole("button", {
      name: "Copy res-A",
    });
    await user.click(button);

    expect(writeText).toHaveBeenCalledWith("res-A");
    await waitFor(() =>
      expect(button.querySelector('svg[data-icon="check"]')).not.toBeNull(),
    );
    expect(button).toHaveClass("h-11");
    expect(button).toHaveClass("w-11");
    expect(button).toHaveClass("copy-reveal");
  });

  it("says plainly when the clipboard refuses the copy", async () => {
    const user = renderApp("/", results);
    await screen.findByRole("region", { name: "Fix now" });
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("denied"));

    await user.click(
      within(tile("Open SSH to the world")).getByRole("button", { name: "Copy res-A" }),
    );

    expect(
      await within(tile("Open SSH to the world")).findByRole("alert"),
    ).toHaveTextContent("Copy failed");
  });
});

describe("Overview: below the lanes", () => {
  it("shows the most recently resolved finding in the Done strip, with an unambiguous date", async () => {
    renderApp("/", results);

    const strip = await screen.findByRole("region", { name: "Done" });
    expect(within(strip).getByText("Fixed: Newest fix")).toBeInTheDocument();
    expect(strip).toHaveTextContent(formatDate("2026-10-04T10:00:00Z"));
    expect(strip).toHaveTextContent(/\d{1,2} [A-Z][a-z]{2} 2026/);
    expect(strip.querySelector("svg.check")).not.toBeNull();
  });

  it("hides the Done strip when nothing is resolved", async () => {
    renderApp("/", { ...results, "GET /api/findings": [row("A", 95)] });

    await screen.findByRole("region", { name: "Fix now" });
    expect(screen.queryByRole("region", { name: "Done" })).not.toBeInTheDocument();
  });

  it("shows a proportional progress bar, how many are resolved, and the latest one", async () => {
    renderApp("/", results);

    const card = (await screen.findByRole("heading", { name: "Progress" })).closest(
      "section",
    ) as HTMLElement;
    const bar = within(card).getByRole("img", { name: "2 of 8 resolved" });
    expect((bar.firstElementChild as HTMLElement).style.width).toBe("25%");
    expect(within(card).getByText("2 of 8 resolved")).toBeInTheDocument();
    expect(card).toHaveTextContent("Latest: Newest fix");
    expect(card).toHaveTextContent(formatDate("2026-10-04T10:00:00Z"));
  });

  it("says nothing is resolved yet, with an empty bar", async () => {
    renderApp("/", { ...results, "GET /api/findings": [row("A", 95)] });

    const card = (await screen.findByRole("heading", { name: "Progress" })).closest(
      "section",
    ) as HTMLElement;

    expect(within(card).getByText("Nothing has been resolved yet.")).toBeInTheDocument();
    const bar = within(card).getByRole("img", { name: "0 of 1 resolved" });
    expect((bar.firstElementChild as HTMLElement).style.width).toBe("0%");
  });

  it("puts the progress card and the findings per scan card side by side", async () => {
    const scans = [scan({ id: 2, finding_count: 4 }), scan({ id: 1, finding_count: 9 })];
    renderApp("/", { ...results, "GET /api/scans": scans });

    const progress = (await screen.findByRole("heading", { name: "Progress" })).closest(
      "section",
    );
    const chart = screen
      .getByRole("heading", { name: "Findings per scan" })
      .closest("section");

    expect(progress?.parentElement).toBe(chart?.parentElement);
    expect(progress?.parentElement).toHaveClass("min-[900px]:grid-cols-2");
  });

  it("shows the combined score only as a small figure with its tooltip", async () => {
    renderApp("/", results);

    const label = await screen.findByText("Combined environment score");
    const fact = label.closest("div") as HTMLElement;

    expect(fact).toHaveTextContent("99.8");
    expect(fact.querySelector("dd")).toHaveClass("text-label");
    expect(screen.getByRole("tooltip")).toHaveTextContent("climbs towards 100");
    expect(screen.getByRole("tooltip")).toHaveTextContent("the lanes decide the order");
  });

  it("says when the combined score cannot be loaded, and still shows the board", async () => {
    renderApp("/", {
      ...results,
      "GET /api/risk/summary": fail(500, "summary exploded"),
    });

    expect(await screen.findByText(/summary exploded/)).toBeInTheDocument();
    expect(await screen.findByRole("region", { name: "Fix now" })).toBeInTheDocument();
  });

  it("shows the backend's message when the findings cannot be loaded", async () => {
    renderApp("/", { ...results, "GET /api/findings": fail(500, "findings exploded") });

    expect(await screen.findByRole("alert")).toHaveTextContent("findings exploded");
  });

  it("has no unlabelled trend line, and does not ask for the trend", async () => {
    renderApp("/", results);

    await screen.findByRole("region", { name: "Fix now" });

    expect(
      screen.queryByRole("img", { name: /Combined environment score by scan/ }),
    ).toBeNull();
    expect(callsTo("GET", "/api/risk/trend")).toHaveLength(0);
  });

  it("shows the facts of the last scan: id, when it finished, how long, resources, errors", async () => {
    const now = new Date("2026-10-04T10:00:00Z").getTime();
    vi.spyOn(Date, "now").mockReturnValue(now);
    const last = scan({ id: 3, error_count: 2, resource_count: 11 });
    renderApp("/", { ...results, "GET /api/scans": [last] });

    const facts = (await screen.findByText("Last scan")).closest("dl") as HTMLElement;

    expect(facts).toHaveTextContent("Scan 3");
    expect(facts).toHaveTextContent("3 days ago");
    expect(facts).toHaveTextContent("42s");
    expect(within(facts).getByText("11")).toBeInTheDocument();
    expect(within(facts).getByText("2")).toBeInTheDocument();
    expect(within(facts).getByText("3 days ago")).toHaveAttribute(
      "title",
      formatDate(last.finished_at),
    );
  });
});

describe("Overview: findings per scan", () => {
  function scansWith(count: number) {
    return Array.from({ length: count }, (_, i) =>
      scan({ id: count - i, finding_count: (count - i) * 2 }),
    );
  }

  function chart(): HTMLElement {
    return screen.getByRole("list", { name: "Findings per scan" });
  }

  it("is hidden with one scan", async () => {
    renderApp("/", { ...results, "GET /api/scans": scansWith(1) });

    await screen.findByRole("region", { name: "Fix now" });

    expect(
      screen.queryByRole("heading", { name: "Findings per scan" }),
    ).not.toBeInTheDocument();
  });

  it("shows one labelled bar per scan, with the value on the bar and the scan number below, for two scans", async () => {
    renderApp("/", { ...results, "GET /api/scans": scansWith(2) });

    await screen.findByRole("heading", { name: "Findings per scan" });
    const bars = within(chart()).getAllByRole("listitem");

    expect(bars).toHaveLength(2);
    expect(bars[0]).toHaveTextContent("2");
    expect(bars[0]).toHaveTextContent("#1");
    expect(bars[1]).toHaveTextContent("4");
    expect(bars[1]).toHaveTextContent("#2");
  });

  it("shows only the last eight scans, oldest on the left", async () => {
    renderApp("/", { ...results, "GET /api/scans": scansWith(12) });

    await screen.findByRole("heading", { name: "Findings per scan" });
    const labels = within(chart())
      .getAllByRole("listitem")
      .map((item) => item.textContent?.match(/#\d+/)?.[0]);

    expect(labels).toEqual(["#5", "#6", "#7", "#8", "#9", "#10", "#11", "#12"]);
  });

  it("draws bars in proportion to the finding counts", async () => {
    const scans = [scan({ id: 2, finding_count: 10 }), scan({ id: 1, finding_count: 5 })];
    renderApp("/", { ...results, "GET /api/scans": scans });

    await screen.findByRole("heading", { name: "Findings per scan" });
    const heights = within(chart())
      .getAllByRole("listitem")
      .map((item) =>
        parseInt((item.querySelector(".bg-ink") as HTMLElement).style.height, 10),
      );

    expect(heights).toEqual([64, 128]);
  });

  it("leaves out scans that did not complete, which have no finding count to show", async () => {
    const scans = [
      scan({ id: 3, status: "failed", finding_count: 0, failure_message: "boom" }),
      scan({ id: 2 }),
      scan({ id: 1 }),
    ];
    renderApp("/", { ...results, "GET /api/scans": scans });

    await screen.findByRole("heading", { name: "Findings per scan" });

    expect(within(chart()).getAllByRole("listitem")).toHaveLength(2);
  });
});

describe("Overview: running a scan", () => {
  it("runs a scan from the header, shows the real progress, then refreshes the board", async () => {
    let listCalls = 0;
    let checks = 0;
    const user = renderApp("/", {
      "GET /api/scans": () => (++listCalls === 1 ? [] : [scan({ id: 5 })]),
      "POST /api/scans": scan({ id: 5, status: "queued", progress: "Queued" }),
      "GET /api/scans/5": () =>
        ++checks < 3
          ? scan({ id: 5, status: "running", progress: "Scanning AWS" })
          : scan({ id: 5 }),
      "GET /api/findings": rows,
      "GET /api/risk/summary": summary(),
    });

    await user.click(await screen.findByRole("button", { name: "Run scan" }));

    expect(await screen.findByText(/Scan 5 running: Scanning AWS/)).toBeInTheDocument();
    expect(await screen.findByText("Scan 5 completed.")).toBeInTheDocument();
    expect(await screen.findByRole("region", { name: "Fix now" })).toBeInTheDocument();
    expect(callsTo("POST", "/api/scans")).toHaveLength(1);
  });

  it("shows a spinner in the button and a bar that has no percentage while the scan runs", async () => {
    const user = renderApp("/", {
      "POST /api/scans": scan({ id: 7, status: "running", progress: "Scanning AWS" }),
      "GET /api/scans/7": scan({ id: 7, status: "running", progress: "Scanning AWS" }),
    });

    await user.click(await screen.findByRole("button", { name: "Run scan" }));

    const button = await screen.findByRole("button", { name: "Scanning..." });
    expect(button).toBeDisabled();
    expect(button.querySelector(".spinner")).not.toBeNull();
    expect(document.querySelector(".scan-bar")).not.toBeNull();
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    expect(screen.queryByText(/\d\s?%/)).not.toBeInTheDocument();
  });

  it("announces the backend's progress text in a polite live region", async () => {
    const user = renderApp("/", {
      "POST /api/scans": scan({ id: 7, status: "running", progress: "Scanning AWS" }),
      "GET /api/scans/7": scan({ id: 7, status: "running", progress: "Running rules" }),
    });

    await user.click(await screen.findByRole("button", { name: "Run scan" }));

    const live = document.querySelector('[aria-live="polite"]') as HTMLElement;
    await waitFor(() => expect(live).toHaveTextContent("Scan 7 running: Running rules"));
  });

  it("shows the backend's real failure message when a scan fails", async () => {
    const user = renderApp("/", {
      "POST /api/scans": scan({ id: 6, status: "queued" }),
      "GET /api/scans/6": scan({
        id: 6,
        status: "failed",
        failure_message:
          "RuntimeError: No AWS credentials found. Set AWS_PROFILE on the server.",
      }),
    });

    await user.click(await screen.findByRole("button", { name: "Run scan" }));

    const alert = await screen.findByText(/Scan 6 failed:/);
    expect(alert).toHaveTextContent(
      "No AWS credentials found. Set AWS_PROFILE on the server.",
    );
    expect(document.querySelector(".scan-bar")).toBeNull();
  });

  it("shows the backend's message when a scan is already running (409)", async () => {
    const user = renderApp("/", {
      "POST /api/scans": fail(409, "A scan is already running."),
    });

    await user.click(await screen.findByRole("button", { name: "Run scan" }));

    expect(await screen.findByText("A scan is already running.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run scan" })).toBeEnabled();
  });

  it("follows a scan that is already running when the page opens", async () => {
    let checks = 0;
    renderApp("/", {
      "GET /api/scans": [scan({ id: 4, status: "running", progress: "Scanning AWS" })],
      "GET /api/scans/4": () =>
        ++checks < 2
          ? scan({ id: 4, status: "running", progress: "Scanning AWS" })
          : scan({ id: 4 }),
    });

    expect(await screen.findByText(/Scan 4 running/)).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByText("Scan 4 completed.")).toBeInTheDocument(),
    );
    expect(callsTo("POST", "/api/scans")).toHaveLength(0);
  });

  it("flashes the scan chip green for a moment after a scan completes", async () => {
    const user = renderApp("/", {
      "GET /api/scans": [scan({ id: 3 })],
      "POST /api/scans": scan({ id: 4, status: "queued" }),
      "GET /api/scans/4": scan({ id: 4 }),
      "GET /api/findings": rows,
      "GET /api/risk/summary": summary(),
    });

    await user.click(await screen.findByRole("button", { name: "Run scan" }));

    const chip = await screen.findByRole("link", { name: /Scan 3 completed/ });
    await waitFor(() => expect(chip).toHaveAttribute("data-flash", "true"));
    expect(chip).toHaveClass("chip-flash");
    await waitFor(() => expect(chip).toHaveAttribute("data-flash", "false"), {
      timeout: 3000,
    });
  });
});
