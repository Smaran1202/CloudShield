import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { scan } from "../test/factories";
import { callsTo, fail } from "../test/mockApi";
import { never, renderApp } from "../test/render";

const AVAILABLE = {
  available: true,
  version: "Prowler 5.44.0",
  reason: null,
  hint: null,
};
const BLOCKED = {
  available: false,
  version: null,
  reason: "This computer's security policy blocked Prowler from starting.",
  hint: "Use PROWLER_PYTHON, Docker or WSL.",
};
const STAGE = "Running extended checks (this can take several minutes)";

async function openMenu(routes: Record<string, unknown> = {}) {
  const user = renderApp("/scans", routes);
  await user.click(await screen.findByRole("button", { name: "More ways to scan" }));
  return user;
}

describe("Run scan: the split button", () => {
  it("has the main button and a second button that opens a menu of choices", async () => {
    await openMenu({ "GET /api/extended/status": AVAILABLE });

    const menu = screen.getByRole("menu", { name: "Ways to scan" });

    expect(within(menu).getByRole("menuitem", { name: /^Run scan/ })).toBeEnabled();
    expect(
      within(menu).getByRole("menuitem", {
        name: /Run full scan \(adds extended checks\)/,
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "More ways to scan" })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
  });

  it("keeps the menu closed until it is asked for, and does not ask the API until then", async () => {
    renderApp("/scans");

    await screen.findByRole("button", { name: "Run scan" });

    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(callsTo("GET", "/api/extended/status")).toHaveLength(0);
  });

  it("starts a plain scan from the main button, with no extended option", async () => {
    const user = renderApp("/scans", {
      "POST /api/scans": scan({ id: 3, status: "queued" }),
      "GET /api/scans/3": scan({ id: 3 }),
    });

    await user.click(await screen.findByRole("button", { name: "Run scan" }));

    await screen.findByText("Scan 3 completed.");
    expect(callsTo("POST", "/api/scans")[0].body).toBeNull();
  });

  it("starts a plain scan from the first menu choice", async () => {
    const user = await openMenu({
      "GET /api/extended/status": AVAILABLE,
      "POST /api/scans": scan({ id: 3, status: "queued" }),
      "GET /api/scans/3": scan({ id: 3 }),
    });

    await user.click(screen.getByRole("menuitem", { name: /^Run scan/ }));

    await screen.findByText("Scan 3 completed.");
    expect(callsTo("POST", "/api/scans")[0].body).toBeNull();
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("starts a full scan with the extended option set", async () => {
    const user = await openMenu({
      "GET /api/extended/status": AVAILABLE,
      "POST /api/scans": scan({ id: 4, status: "queued" }),
      "GET /api/scans/4": scan({ id: 4 }),
    });
    const full = await screen.findByRole("menuitem", { name: /Run full scan/ });
    await waitFor(() => expect(full).toBeEnabled());

    await user.click(full);

    await screen.findByText("Scan 4 completed.");
    expect(callsTo("POST", "/api/scans")[0].body).toEqual({ extended: true });
  });

  it("disables the full scan and says why and what to do when it cannot run here", async () => {
    const user = await openMenu({
      "GET /api/extended/status": BLOCKED,
      "POST /api/scans": scan({ id: 4 }),
    });

    const full = await screen.findByRole("menuitem", { name: /Run full scan/ });
    const note = await screen.findByRole("note");

    expect(full).toBeDisabled();
    expect(note).toHaveTextContent("security policy blocked Prowler");
    expect(note).toHaveTextContent("Use PROWLER_PYTHON, Docker or WSL.");
    await user.click(full);
    expect(callsTo("POST", "/api/scans")).toHaveLength(0);
    expect(screen.getByRole("menuitem", { name: /^Run scan/ })).toBeEnabled();
  });

  it("keeps the full scan disabled while it checks, and when the check itself fails", async () => {
    await openMenu({ "GET /api/extended/status": never });

    expect(
      await screen.findByText(/Checking whether it can run here/),
    ).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: /Run full scan/ })).toBeDisabled();
  });

  it("shows the API's message when the status cannot be read", async () => {
    await openMenu({ "GET /api/extended/status": fail(500, "status exploded") });

    expect(await screen.findByRole("note")).toHaveTextContent(
      "Could not check: status exploded",
    );
    expect(screen.getByRole("menuitem", { name: /Run full scan/ })).toBeDisabled();
  });

  it("closes the menu with Escape", async () => {
    const user = await openMenu({ "GET /api/extended/status": AVAILABLE });

    await user.keyboard("{Escape}");

    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("closes the menu when the page is clicked elsewhere", async () => {
    const user = await openMenu({ "GET /api/extended/status": AVAILABLE });

    await user.click(screen.getByRole("navigation", { name: "Main" }));

    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("disables both buttons while a scan runs", async () => {
    const user = renderApp("/scans", {
      "POST /api/scans": scan({
        id: 5,
        status: "running",
        progress: "Reading resources",
      }),
      "GET /api/scans/5": scan({
        id: 5,
        status: "running",
        progress: "Reading resources",
      }),
    });

    await user.click(await screen.findByRole("button", { name: "Run scan" }));

    const running = await screen.findByRole("button", { name: "Scanning..." });
    expect(running).toBeDisabled();
    expect(screen.getByRole("button", { name: "More ways to scan" })).toBeDisabled();
  });
});

describe("Run scan: progress and result of the extended checks", () => {
  function steps(...progress: string[]) {
    let calls = 0;
    return () => {
      const text = progress[Math.min(calls++, progress.length - 1)];
      return scan({ id: 8, status: "running", progress: text });
    };
  }

  async function runFull(routes: Record<string, unknown>) {
    const user = renderApp("/scans", {
      "GET /api/extended/status": AVAILABLE,
      "POST /api/scans": scan({ id: 8, status: "queued", progress: "Queued" }),
      ...routes,
    });
    await user.click(await screen.findByRole("button", { name: "More ways to scan" }));
    const full = await screen.findByRole("menuitem", { name: /Run full scan/ });
    await waitFor(() => expect(full).toBeEnabled());
    await user.click(full);
    return user;
  }

  it("shows each stage in words, with a spinner and a bar that has no percentage", async () => {
    await runFull({ "GET /api/scans/8": steps("Reading resources", STAGE) });

    expect(
      await screen.findByText(new RegExp(STAGE.replace(/[()]/g, "\\$&"))),
    ).toBeInTheDocument();
    const button = screen.getByRole("button", { name: "Scanning..." });
    expect(button.querySelector(".spinner")).not.toBeNull();
    expect(document.querySelector(".scan-bar")).not.toBeNull();
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    expect(screen.queryByText(/\d\s?%/)).not.toBeInTheDocument();
  });

  it("says the extended stage can take several minutes", async () => {
    await runFull({ "GET /api/scans/8": steps(STAGE) });

    expect(await screen.findByText(/this can take several minutes/)).toBeInTheDocument();
  });

  it("shows the counts when the extended checks worked", async () => {
    await runFull({
      "GET /api/scans/8": scan({
        id: 8,
        extended_status: "ok",
        extended_message: "Extended checks: 48 imported, 4 resolved, 67 passed",
      }),
    });

    expect(await screen.findByText("Scan 8 completed.")).toBeInTheDocument();
    expect(
      screen.getByText("Extended checks: 48 imported, 4 resolved, 67 passed"),
    ).toBeInTheDocument();
  });

  it("shows the failure and its hint, and still says the scan completed", async () => {
    await runFull({
      "GET /api/scans/8": scan({
        id: 8,
        extended_status: "failed",
        extended_message: "Prowler stopped with exit code 1.",
        extended_hint: "See docs/extended-checks.md.",
      }),
    });

    expect(await screen.findByText("Scan 8 completed.")).toBeInTheDocument();
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(
      "Extended checks failed: Prowler stopped with exit code 1.",
    );
    expect(alert).toHaveTextContent("See docs/extended-checks.md.");
  });

  it("shows an unavailable runner as unavailable, with the way to fix it", async () => {
    await runFull({
      "GET /api/scans/8": scan({
        id: 8,
        extended_status: "unavailable",
        extended_message: "Prowler was not found.",
        extended_hint: "Set PROWLER_PYTHON.",
      }),
    });

    const alert = await screen.findByRole("alert");

    expect(alert).toHaveTextContent(
      "Extended checks unavailable: Prowler was not found.",
    );
    expect(alert).toHaveTextContent("Set PROWLER_PYTHON.");
  });

  it("shows the permissions hint next to results that were still imported", async () => {
    await runFull({
      "GET /api/scans/8": scan({
        id: 8,
        extended_status: "ok",
        extended_message:
          "Extended checks: 3 imported, 0 resolved, 1 passed. Prowler reported errors.",
        extended_hint: "attach SecurityAudit and ViewOnlyAccess to the scanner user.",
      }),
    });

    expect(await screen.findByText(/Prowler reported errors/)).toBeInTheDocument();
    expect(screen.getByText(/SecurityAudit and ViewOnlyAccess/)).toBeInTheDocument();
  });

  it("says nothing about extended checks after a plain scan", async () => {
    const user = renderApp("/scans", {
      "POST /api/scans": scan({ id: 9, status: "queued" }),
      "GET /api/scans/9": scan({ id: 9 }),
    });

    await user.click(await screen.findByRole("button", { name: "Run scan" }));

    await screen.findByText("Scan 9 completed.");
    expect(screen.queryByText(/Extended checks/)).not.toBeInTheDocument();
  });
});

describe("Scans page: extended checks", () => {
  it("shows the extended status of each scan and its message", async () => {
    renderApp("/scans", {
      "GET /api/scans": [
        scan({
          id: 3,
          extended_status: "ok",
          extended_message: "Extended checks: 2 imported, 0 resolved, 1 passed",
        }),
        scan({
          id: 2,
          extended_status: "failed",
          extended_message: "Prowler was stopped.",
          extended_hint: "Run fewer services.",
        }),
        scan({ id: 1 }),
      ],
    });

    await screen.findByRole("table", { name: "Scans" });
    const [, three, two, one] = screen.getAllByRole("row").slice(0, 4);

    expect(within(three).getByText("Extended: ok")).toBeInTheDocument();
    expect(within(two).getByText("Extended: failed")).toBeInTheDocument();
    expect(within(one).queryByText(/Extended:/)).not.toBeInTheDocument();
    expect(
      screen.getByText("Extended checks: 2 imported, 0 resolved, 1 passed"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Extended checks failed: Prowler was stopped/),
    ).toBeInTheDocument();
    expect(screen.getByText("Run fewer services.")).toBeInTheDocument();
  });

  it("does not turn an extended failure into a failed scan alert", async () => {
    renderApp("/scans", {
      "GET /api/scans": [
        scan({
          extended_status: "failed",
          extended_message: "Boom.",
          extended_hint: "Try later.",
        }),
      ],
    });

    await screen.findByRole("table", { name: "Scans" });

    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getAllByText("completed").length).toBeGreaterThan(0);
  });
});
