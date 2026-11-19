import { screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { scan } from "../test/factories";
import { fail, networkDown } from "../test/mockApi";
import { never, renderApp } from "../test/render";

describe("Header: API status", () => {
  it("shows the API as online with its version from /api/health", async () => {
    renderApp("/scans");

    expect(await screen.findByText("API online v1.2.3")).toBeInTheDocument();
  });

  it("does not draw the online state, but still tells screen readers", async () => {
    renderApp("/scans");

    const status = await screen.findByText("API online v1.2.3");

    expect(status).toHaveClass("sr-only");
    expect(status.querySelector("span")).not.toBeNull();
  });

  it("draws the offline state with a red dot and the words", async () => {
    renderApp("/scans", { "GET /api/health": networkDown() });

    const status = await screen.findByText("API offline");

    expect(status).not.toHaveClass("sr-only");
    expect(status.querySelector(".bg-red")).not.toBeNull();
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

  it("makes every item a 40px pill, with a light fill on hover and a darker one on press", async () => {
    renderApp("/scans");

    const nav = await screen.findByRole("navigation", { name: "Main" });
    const idle = within(nav).getByRole("link", { name: "Findings" });

    for (const name of ["rounded-full", "h-10", "px-4"]) expect(idle).toHaveClass(name);
    expect(idle).toHaveClass("hover:bg-pill-hover");
    expect(idle).toHaveClass("active:bg-pill-press");
  });

  it("draws the active item in white on the oval, with no fill of its own", async () => {
    renderApp("/scans");

    const nav = await screen.findByRole("navigation", { name: "Main" });
    const active = within(nav).getByRole("link", { name: "Scans" });

    expect(active).toHaveClass("text-white");
    expect(active).not.toHaveClass("hover:bg-pill-hover");
    expect(active).toHaveAttribute("aria-current", "page");
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

    expect(button).toHaveClass("min-h-10");
    expect(button).toHaveClass("bg-ink");
    expect(button).toHaveClass("rounded-l-chip");
  });

  it("shows a page for addresses that do not exist", async () => {
    renderApp("/nowhere");

    expect(await screen.findByText("Page not found")).toBeInTheDocument();
  });
});

describe("Header: the navigation oval", () => {
  const LEFT: Record<string, number> = {
    Overview: 0,
    Findings: 100,
    Resources: 200,
    Scans: 300,
  };
  const left = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetLeft");

  // jsdom has no layout, so each link gets a position from its text.
  function placeLinks() {
    Object.defineProperty(HTMLElement.prototype, "offsetLeft", {
      configurable: true,
      get() {
        return LEFT[(this as HTMLElement).textContent ?? ""] ?? 0;
      },
    });
  }

  afterEach(() => {
    if (left) Object.defineProperty(HTMLElement.prototype, "offsetLeft", left);
  });

  it("is one shared element, behind the active item, and hidden from assistive technology", async () => {
    placeLinks();
    renderApp("/findings", { "GET /api/findings": [] });

    const nav = await screen.findByRole("navigation", { name: "Main" });
    const oval = within(nav).getByTestId("nav-oval");

    expect(nav.querySelectorAll(".nav-oval")).toHaveLength(1);
    expect(oval).toHaveAttribute("aria-hidden", "true");
    expect(oval).toHaveClass("rounded-full", "h-10", "bg-ink");
    expect(oval.style.transform).toBe("translate(100px, 0px)");
  });

  it("moves the same element to the new item and keeps aria-current on the active link", async () => {
    placeLinks();
    const user = renderApp("/findings", { "GET /api/findings": [] });
    const nav = await screen.findByRole("navigation", { name: "Main" });
    const oval = within(nav).getByTestId("nav-oval");

    await user.click(within(nav).getByRole("link", { name: "Scans" }));

    await waitFor(() => expect(oval.style.transform).toBe("translate(300px, 0px)"));
    expect(within(nav).getByTestId("nav-oval")).toBe(oval);
    expect(within(nav).getByRole("link", { name: "Scans" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(within(nav).getByRole("link", { name: "Findings" })).not.toHaveAttribute(
      "aria-current",
    );
  });

  it("is hidden on a page that is not in the navigation", async () => {
    renderApp("/nowhere");

    const nav = await screen.findByRole("navigation", { name: "Main" });

    expect(within(nav).getByTestId("nav-oval")).not.toBeVisible();
  });

  it("keeps every item a real link that can be reached with the keyboard", async () => {
    const user = renderApp("/scans");
    const nav = await screen.findByRole("navigation", { name: "Main" });

    await user.tab();
    await user.tab();

    expect(nav.contains(document.activeElement)).toBe(true);
    expect(document.activeElement?.tagName).toBe("A");
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

describe("Demo data label", () => {
  const label = "Demo data: a made-up account. Nothing here is from a real AWS account.";

  it("is shown when the newest scan carries a data label", async () => {
    renderApp("/scans", { "GET /api/scans": [scan({ id: 2, data_label: label })] });

    expect(await screen.findByRole("note")).toHaveTextContent(label);
  });

  it("is not shown for a scan without one", async () => {
    renderApp("/scans", { "GET /api/scans": [scan({ id: 2 })] });

    await screen.findByRole("link", { name: /^Scan 2/ });

    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });

  it("goes away when a newer scan has no label", async () => {
    renderApp("/scans", {
      "GET /api/scans": [scan({ id: 3 }), scan({ id: 2, data_label: label })],
    });

    await screen.findByRole("link", { name: /^Scan 3/ });

    expect(screen.queryByRole("note")).not.toBeInTheDocument();
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

  it("is one row on a wide screen with the status, scan chip and Run scan on the right", async () => {
    renderApp("/findings", { "GET /api/findings": [] });

    const header = await screen.findByRole("banner");
    const right = header.firstElementChild?.lastElementChild as HTMLElement;

    expect(right).toHaveClass("min-[1100px]:ml-auto", "min-[1100px]:justify-end");
    expect(right).toHaveClass("w-full", "justify-between");
    expect(within(right).getByRole("button", { name: "Run scan" })).toBeVisible();
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
