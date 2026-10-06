import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { formatDate } from "../format";
import { scan } from "../test/factories";
import { fail } from "../test/mockApi";
import { never, renderApp } from "../test/render";
import { SCANS_GRID } from "./Scans";

const oneError = {
  service: "iam",
  region: null,
  resource: "arn:aws:iam::1:policy/p",
  message: "An error occurred (AccessDenied) when calling ListEntitiesForPolicy",
};

describe("Scans", () => {
  it("shows loading while scans are fetched", async () => {
    renderApp("/scans", { "GET /api/scans": never });

    expect(screen.getByText("Loading scans...")).toBeInTheDocument();
    await screen.findByText(/API online/);
  });

  it("shows the backend's message when scans cannot be loaded", async () => {
    renderApp("/scans", { "GET /api/scans": fail(500, "database is locked") });

    expect(await screen.findByRole("alert")).toHaveTextContent("database is locked");
  });

  it("says there are no scans yet", async () => {
    renderApp("/scans", { "GET /api/scans": [] });

    expect(await screen.findByText("No scans yet.")).toBeInTheDocument();
  });

  it("shows a table with the columns Scan, Started, Duration, Regions, Resources, Findings, Errors and Status", async () => {
    renderApp("/scans", { "GET /api/scans": [scan({ id: 2 }), scan({ id: 1 })] });

    await screen.findByRole("table", { name: "Scans" });
    const header = screen.getByTestId("scans-header");

    expect(
      within(header)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual([
      "Scan",
      "Status",
      "Started",
      "Duration",
      "Regions",
      "Resources",
      "Findings",
      "Errors",
    ]);
    expect(header.className).toContain(SCANS_GRID);
    for (const r of screen.getAllByRole("row").slice(1))
      expect(r.className).toContain(SCANS_GRID);
  });

  it("shows each scan's status and counts in one row", async () => {
    renderApp("/scans", {
      "GET /api/scans/1": scan({ id: 1, status: "running" }),
      "GET /api/scans": [
        scan({ id: 2, resource_count: 9, finding_count: 4 }),
        scan({ id: 1, status: "running" }),
      ],
    });

    await screen.findByRole("table", { name: "Scans" });
    const [, first, second] = screen.getAllByRole("row");
    const cells = within(first).getAllByRole("cell");

    expect(cells[0]).toHaveTextContent("2");
    expect(cells[1]).toHaveTextContent("completed");
    expect(cells[3]).toHaveTextContent("42s");
    expect(cells[4]).toHaveTextContent("ap-southeast-2");
    expect(cells[5]).toHaveTextContent("9");
    expect(cells[6]).toHaveTextContent("4");
    expect(within(second).getAllByRole("cell")[1]).toHaveTextContent("running");
  });

  it("shows the start as an unambiguous date with a relative time under it", async () => {
    renderApp("/scans", {
      "GET /api/scans": [scan({ started_at: "2026-10-05T04:42:00Z" })],
    });

    await screen.findByRole("table", { name: "Scans" });
    const started = within(screen.getAllByRole("row")[1]).getAllByRole("cell")[2];

    expect(started).toHaveTextContent(formatDate("2026-10-05T04:42:00Z"));
    expect(started.textContent).toMatch(/\d{1,2} Oct 2026/);
    expect(started.textContent).toMatch(/ago|just now|yesterday/);
  });

  it("shows the progress text of a scan that is queued or running", async () => {
    renderApp("/scans", {
      "GET /api/scans/4": scan({ id: 4, status: "running", progress: "Scanning AWS" }),
      "GET /api/scans": [scan({ id: 4, status: "running", progress: "Scanning AWS" })],
    });

    await screen.findByRole("table", { name: "Scans" });
    const status = within(screen.getAllByRole("row")[1]).getAllByRole("cell")[1];

    expect(status).toHaveTextContent("running");
    expect(status).toHaveTextContent("Scanning AWS");
    expect(screen.getByTestId("latest-scan")).toHaveTextContent("Scanning AWS");
  });

  it("shows the combined score only inside the opened details, with its tooltip", async () => {
    const user = renderApp("/scans", {
      "GET /api/scans": [scan({ id: 3, error_count: 1, errors: [oneError] })],
    });

    await screen.findByRole("table", { name: "Scans" });
    expect(screen.queryByText("Combined score")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Details of scan 3/ }));

    expect(screen.getByText("Combined score")).toBeInTheDocument();
    expect(screen.getByText("97.5")).toBeInTheDocument();
    expect(screen.getByRole("tooltip")).toHaveTextContent("the lanes decide the order");
  });

  it("opens a failed scan by default and can close it", async () => {
    const user = renderApp("/scans", {
      "GET /api/scans": [
        scan({
          status: "failed",
          failure_message: "RuntimeError: boom",
          finished_at: null,
        }),
      ],
    });

    const button = await screen.findByRole("button", { name: /Details of scan 1/ });

    expect(button).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("alert")).toHaveTextContent("Failed: RuntimeError: boom");
    await user.click(button);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("has no environment score column", async () => {
    renderApp("/scans", { "GET /api/scans": [scan()] });

    await screen.findByRole("table", { name: "Scans" });

    expect(screen.queryByText(/environment score/i)).not.toBeInTheDocument();
    expect(screen.queryByText("97.5")).not.toBeInTheDocument();
  });

  it("summarises the latest scan in a strip above the table", async () => {
    renderApp("/scans", {
      "GET /api/scans": [scan({ id: 5, resource_count: 9 }), scan({ id: 4 })],
    });

    const strip = await screen.findByTestId("latest-scan");

    expect(strip).toHaveTextContent("Latest: Scan 5");
    expect(strip).toHaveTextContent("completed");
    expect(strip).toHaveTextContent("Took 42s");
    expect(strip).toHaveTextContent("9 resources, 0 errors");
  });

  it("shows the real failure message of a failed scan", async () => {
    renderApp("/scans", {
      "GET /api/scans": [
        scan({
          status: "failed",
          failure_message: "RuntimeError: No AWS credentials found.",
          finished_at: null,
        }),
      ],
    });

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Failed: RuntimeError: No AWS credentials found.",
    );
    expect(screen.getAllByText("failed").length).toBeGreaterThan(0);
  });

  it("keeps the scanner errors folded until the error count is clicked, then lists them", async () => {
    const user = renderApp("/scans", {
      "GET /api/scans": [
        scan({
          id: 3,
          error_count: 1,
          errors: [
            {
              service: "iam",
              region: null,
              resource: "arn:aws:iam::1:policy/p",
              message:
                "An error occurred (AccessDenied) when calling ListEntitiesForPolicy",
            },
          ],
        }),
      ],
    });
    const button = await screen.findByRole("button", {
      name: "Details of scan 3: 1 error",
    });

    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByText(/AccessDenied/)).not.toBeInTheDocument();

    await user.click(button);

    expect(button).toHaveAttribute("aria-expanded", "true");
    const list = screen.getByRole("list", { name: "Errors in scan 3" });
    expect(within(list).getByText(/AccessDenied/)).toBeInTheDocument();
    expect(within(list).getByText(/iam, arn:aws:iam::1:policy\/p/)).toBeInTheDocument();

    await user.click(button);

    expect(screen.queryByText(/AccessDenied/)).not.toBeInTheDocument();
  });

  it("shows a plain 0 and no button for a scan without errors", async () => {
    renderApp("/scans", { "GET /api/scans": [scan()] });

    await screen.findByRole("table", { name: "Scans" });

    expect(screen.queryByRole("button", { name: /error/ })).not.toBeInTheDocument();
    expect(
      within(screen.getAllByRole("row")[1]).getAllByRole("cell")[7],
    ).toHaveTextContent("0");
  });
});
