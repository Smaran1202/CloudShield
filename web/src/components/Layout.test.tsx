import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { scan } from "../test/factories";
import { fail, networkDown } from "../test/mockApi";
import { never, renderApp } from "../test/render";

describe("Header: API status", () => {
  it("shows the API as online with its version from /api/health", async () => {
    renderApp("/scans");

    expect(await screen.findByText("API online v1.2.3")).toBeInTheDocument();
  });

  it("shows the API as offline when the health call fails", async () => {
    renderApp("/scans", { "GET /api/health": networkDown() });

    expect(await screen.findByText("API offline")).toBeInTheDocument();
    expect(screen.queryByText(/API online/)).not.toBeInTheDocument();
  });

  it("shows the API as offline when the health call answers with an error", async () => {
    renderApp("/scans", { "GET /api/health": fail(500, "down") });

    expect(await screen.findByText("API offline")).toBeInTheDocument();
  });

  it("says it is checking while the health call is pending", async () => {
    renderApp("/scans", { "GET /api/health": never });

    expect(screen.getByText("Checking API...")).toBeInTheDocument();
    await screen.findByText("No scans yet.");
  });
});

describe("Header: shell", () => {
  it("has the wordmark and a link to every page, marking the current one", async () => {
    renderApp("/findings", { "GET /api/findings": [] });

    const nav = await screen.findByRole("navigation", { name: "Main" });

    for (const name of ["Overview", "Findings", "Resources", "Scans"]) {
      expect(within(nav).getByRole("link", { name })).toBeInTheDocument();
    }
    expect(within(nav).getByRole("link", { name: "Findings" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(within(nav).getByRole("link", { name: "Overview" })).not.toHaveAttribute(
      "aria-current",
    );
    expect(screen.getByRole("link", { name: "cloudshield" })).toHaveAttribute(
      "href",
      "/",
    );
  });

  it("draws the active link with a 3px underline", async () => {
    renderApp("/scans");

    const nav = await screen.findByRole("navigation", { name: "Main" });

    expect(within(nav).getByRole("link", { name: "Scans" })).toHaveClass(
      "border-b-[3px]",
    );
    expect(within(nav).getByRole("link", { name: "Scans" })).toHaveClass("border-ink");
  });

  it("has no theme toggle: the design is light only", async () => {
    renderApp("/scans");

    await screen.findByText(/API online/);

    expect(screen.queryByRole("button", { name: /theme/i })).not.toBeInTheDocument();
    expect(document.documentElement).not.toHaveClass("dark");
  });

  it("has a Run scan button that is 48px high", async () => {
    renderApp("/scans");

    const button = await screen.findByRole("button", { name: "Run scan" });

    expect(button).toHaveClass("min-h-12");
    expect(button).toHaveClass("bg-ink");
    expect(button).toHaveClass("rounded-chip");
  });

  it("shows a page for addresses that do not exist", async () => {
    renderApp("/nowhere");

    expect(await screen.findByText("Page not found")).toBeInTheDocument();
  });
});

describe("Header: last scan chip", () => {
  it("says how the last scan ended and how many errors it had", async () => {
    renderApp("/scans", { "GET /api/scans": [scan({ id: 3, error_count: 2 })] });

    const chip = await screen.findByRole("link", { name: "Scan 3 completed, 2 errors" });

    expect(chip).toHaveAttribute("href", "/scans");
  });

  it("uses the singular for one error", async () => {
    renderApp("/scans", { "GET /api/scans": [scan({ id: 3, error_count: 1 })] });

    expect(
      await screen.findByRole("link", { name: "Scan 3 completed, 1 error" }),
    ).toBeInTheDocument();
  });

  it("says when the last scan failed or is still running", async () => {
    renderApp("/scans", {
      "GET /api/scans": [scan({ id: 4, status: "failed", failure_message: "boom" })],
    });

    expect(
      await screen.findByRole("link", { name: "Scan 4 failed" }),
    ).toBeInTheDocument();
  });

  it("is not shown before there is any scan", async () => {
    renderApp("/scans");

    await screen.findByText("No scans yet.");

    expect(screen.queryByRole("link", { name: /^Scan \d/ })).not.toBeInTheDocument();
  });

  it("is not made up when the scans cannot be loaded", async () => {
    renderApp("/scans", { "GET /api/scans": fail(500, "database is locked") });

    await screen.findByRole("alert");

    expect(screen.queryByRole("link", { name: /^Scan \d/ })).not.toBeInTheDocument();
  });
});

describe("Header: scan progress", () => {
  it("shows the sliding bar only while a scan runs", async () => {
    const user = renderApp("/scans", {
      "POST /api/scans": scan({ id: 8, status: "queued" }),
      "GET /api/scans/8": scan({ id: 8, status: "running", progress: "Scanning AWS" }),
    });
    await screen.findByRole("button", { name: "Run scan" });
    expect(document.querySelector(".scan-bar")).toBeNull();

    await user.click(screen.getByRole("button", { name: "Run scan" }));

    await waitFor(() => expect(document.querySelector(".scan-bar")).not.toBeNull());
    expect(document.querySelector(".scan-bar")).toHaveAttribute("aria-hidden", "true");
    expect(document.querySelector(".scan-bar")).toHaveClass("h-1");
  });

  it("keeps a polite live region ready, even when nothing is happening", async () => {
    renderApp("/scans");

    await screen.findByText(/API online/);

    expect(document.querySelector('[aria-live="polite"]')).not.toBeNull();
  });
});

describe("Header: layout", () => {
  it("is a full-width sticky bar with a bottom border, holding its content in the container", async () => {
    renderApp("/findings", { "GET /api/findings": [] });

    const header = await screen.findByRole("banner");

    expect(header).toHaveClass("sticky");
    expect(header).toHaveClass("top-0");
    expect(header).toHaveClass("border-b");
    expect(header.firstElementChild).toHaveClass("mx-auto");
    expect(header.firstElementChild).toHaveClass("max-w-[1440px]");
    expect(header.firstElementChild).toHaveClass("px-[clamp(20px,4vw,64px)]");
  });

  it("centres the page content in the same container as the header, on every page", async () => {
    for (const path of ["/", "/findings", "/resources", "/scans"]) {
      const { unmount } = renderApp(path, {
        "GET /api/findings": [],
        "GET /api/resources": [],
      }) as unknown as { unmount?: () => void };
      const main = await screen.findByRole("main");

      expect(main.parentElement).toHaveClass("mx-auto");
      expect(main.parentElement).toHaveClass("max-w-[1440px]");
      expect(main.parentElement).toHaveClass("px-[clamp(20px,4vw,64px)]");
      unmount?.();
      document.body.innerHTML = "";
    }
  });
});
