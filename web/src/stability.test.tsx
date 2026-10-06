import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { callsTo, fail } from "./test/mockApi";
import { finding, resource, scan, summary, trend } from "./test/factories";
import { renderApp } from "./test/render";

// Animations play when an element first appears. These tests check that a refetch keeps the
// elements that are already on the page, so nothing replays and nothing blinks.

const first = finding({ finding_id: "F-1", title: "First finding", risk_score: 95 });
const second = finding({ finding_id: "F-2", title: "Second finding", risk_score: 70 });
const third = finding({ finding_id: "F-3", title: "Third finding", risk_score: 85 });

function scansAfterRun(): () => unknown {
  let calls = 0;
  return () => (++calls === 1 ? [scan({ id: 1 })] : [scan({ id: 2 }), scan({ id: 1 })]);
}

describe("lists keep their elements when data is fetched again", () => {
  it("keeps the rows of the findings table, and adds the new one", async () => {
    let listCalls = 0;
    const user = renderApp("/findings", {
      "GET /api/scans": scansAfterRun(),
      "GET /api/findings": () =>
        ++listCalls === 1 ? [first, second] : [first, second, third],
      "POST /api/scans": scan({ id: 2, status: "queued" }),
      "GET /api/scans/2": scan({ id: 2 }),
    });
    const before = await screen.findByRole("link", { name: "First finding" });
    const rowBefore = before.closest("[role=row]");
    const secondBefore = screen
      .getByRole("link", { name: "Second finding" })
      .closest("[role=row]");

    await user.click(screen.getByRole("button", { name: "Run scan" }));

    expect(
      await screen.findByRole("link", { name: "Third finding" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "First finding" }).closest("[role=row]"),
    ).toBe(rowBefore);
    expect(
      screen.getByRole("link", { name: "Second finding" }).closest("[role=row]"),
    ).toBe(secondBefore);
    expect(callsTo("GET", "/api/findings")).toHaveLength(2);
  });

  it("keeps the tiles of the board when the scan ends, and adds the new one", async () => {
    let listCalls = 0;
    const user = renderApp("/", {
      "GET /api/scans": scansAfterRun(),
      "GET /api/findings": () =>
        ++listCalls === 1 ? [first, second] : [first, second, third],
      "GET /api/risk/summary": summary(),
      "GET /api/risk/trend": trend(),
      "POST /api/scans": scan({ id: 2, status: "queued" }),
      "GET /api/scans/2": scan({ id: 2 }),
    });
    await screen.findByRole("region", { name: "Fix now" });
    const tile = within(screen.getByRole("region", { name: "Fix now" })).getByRole(
      "link",
      {
        name: /First finding/,
      },
    );

    await user.click(screen.getByRole("button", { name: "Run scan" }));

    await waitFor(() =>
      expect(
        within(screen.getByRole("region", { name: "Fix now" })).getAllByRole("link"),
      ).toHaveLength(2),
    );
    const after = within(screen.getByRole("region", { name: "Fix now" })).getByRole(
      "link",
      {
        name: /First finding/,
      },
    );
    expect(after).toBe(tile);
  });

  it("does not show the loading text again while a list is fetched again", async () => {
    let listCalls = 0;
    const user = renderApp("/findings", {
      "GET /api/scans": scansAfterRun(),
      "GET /api/findings": () => (++listCalls === 1 ? [first] : [first, second]),
      "POST /api/scans": scan({ id: 2, status: "queued" }),
      "GET /api/scans/2": scan({ id: 2 }),
    });
    await screen.findByRole("link", { name: "First finding" });

    await user.click(screen.getByRole("button", { name: "Run scan" }));

    await waitFor(() => expect(callsTo("GET", "/api/findings")).toHaveLength(2));
    expect(screen.queryByText("Loading findings...")).not.toBeInTheDocument();
    expect(
      await screen.findByRole("link", { name: "Second finding" }),
    ).toBeInTheDocument();
  });

  it("keeps the old rows on screen, and says why, when the fetch after a scan fails", async () => {
    let listCalls = 0;
    const user = renderApp("/findings", {
      "GET /api/scans": scansAfterRun(),
      "GET /api/findings": () =>
        ++listCalls === 1 ? [first] : fail(500, "findings exploded"),
      "POST /api/scans": scan({ id: 2, status: "queued" }),
      "GET /api/scans/2": scan({ id: 2 }),
    });
    const row = (await screen.findByRole("link", { name: "First finding" })).closest(
      "[role=row]",
    );

    await user.click(screen.getByRole("button", { name: "Run scan" }));
    await waitFor(() => expect(callsTo("GET", "/api/findings")).toHaveLength(2));

    expect(await screen.findByRole("alert")).toHaveTextContent("findings exploded");
    expect(
      screen.getByRole("link", { name: "First finding" }).closest("[role=row]"),
    ).toBe(row);
  });

  it("keeps the resource rows when the scan ends", async () => {
    let listCalls = 0;
    const user = renderApp("/resources", {
      "GET /api/scans": scansAfterRun(),
      "GET /api/findings": [],
      "GET /api/resources": () =>
        ++listCalls === 1
          ? [resource()]
          : [resource(), resource({ resource_id: "other", name: "other" })],
      "POST /api/scans": scan({ id: 2, status: "queued" }),
      "GET /api/scans/2": scan({ id: 2 }),
    });
    const row = (await screen.findByRole("link", { name: "my-bucket" })).closest(
      "[role=row]",
    );

    await user.click(screen.getByRole("button", { name: "Run scan" }));

    expect(await screen.findByRole("link", { name: "other" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "my-bucket" }).closest("[role=row]")).toBe(
      row,
    );
  });
});
