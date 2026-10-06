import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { formatDate } from "../format";
import { finding, resource, scan } from "../test/factories";
import { fail } from "../test/mockApi";
import { never, renderApp } from "../test/render";
import { RESOURCES_GRID } from "./Resources";

const bucket = resource();
const group = resource({
  resource_id: "sg-0abc123",
  resource_type: "Security Group",
  region: "ap-southeast-2",
  name: "web",
  attributes: { vpc_id: "vpc-1", inbound: [{ IpProtocol: "tcp" }] },
});
const policy = resource({
  resource_id: "arn:aws:iam::123456789012:policy/deploy",
  resource_type: "IAM Policy",
  region: null,
  name: "deploy",
  attributes: { arn: "arn:aws:iam::123456789012:policy/deploy" },
});

const listRoutes = {
  "GET /api/scans": [scan({ id: 1, finished_at: "2026-10-01T10:00:42Z" })],
  "GET /api/resources": [bucket, group, policy],
  "GET /api/findings": [
    finding({ resource_id: "sg-0abc123", risk_score: 95 }),
    finding({ finding_id: "F-2", resource_id: "sg-0abc123", risk_score: 40 }),
    finding({
      finding_id: "F-3",
      resource_id: "sg-0abc123",
      status: "RESOLVED",
      risk_score: 99,
    }),
    finding({ finding_id: "F-4", resource_id: "my-bucket", risk_score: 65 }),
  ],
};

describe("Resources", () => {
  it("shows loading while resources are fetched", async () => {
    renderApp("/resources", { "GET /api/resources": never, "GET /api/findings": [] });

    expect(screen.getByText("Loading resources...")).toBeInTheDocument();
    await screen.findByText(/API online/);
  });

  it("shows the backend's message when resources cannot be loaded", async () => {
    renderApp("/resources", {
      "GET /api/resources": fail(500, "boom"),
      "GET /api/findings": [],
    });

    expect(await screen.findByRole("alert")).toHaveTextContent("boom");
  });

  it("says there are no resources yet", async () => {
    renderApp("/resources", { "GET /api/resources": [], "GET /api/findings": [] });

    expect(await screen.findByText("No resources yet.")).toBeInTheDocument();
  });

  it("has the columns Name, Type, Region, Findings, Highest risk and Last seen", async () => {
    renderApp("/resources", listRoutes);

    await screen.findByRole("table", { name: "Resources" });
    const headers = within(screen.getByTestId("resources-header")).getAllByRole(
      "columnheader",
    );

    expect(headers.map((h) => h.textContent)).toEqual([
      "Name",
      "Type",
      "Region",
      "Findings",
      "Highest risk",
      "Last seen",
    ]);
    expect(screen.getByTestId("resources-header").className).toContain(RESOURCES_GRID);
    for (const r of screen.getAllByRole("row").slice(1)) {
      expect(r.className).toContain(RESOURCES_GRID);
    }
  });

  it("shows type chips with counts, and filters by the chip pressed", async () => {
    const user = renderApp("/resources", listRoutes);
    await screen.findByText("Showing 3 of 3 resources");
    const chips = within(screen.getByRole("group", { name: "Resource type" }));

    expect(chips.getByRole("button", { name: /^All\s*3$/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(
      chips.getByRole("button", { name: /^Security Group\s*1$/ }),
    ).toBeInTheDocument();

    await user.click(chips.getByRole("button", { name: /^Security Group/ }));

    expect(screen.getByText("Showing 1 of 3 resources")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "web" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "my-bucket" })).not.toBeInTheDocument();
    expect(chips.getByRole("button", { name: /^Security Group/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("shows the open findings count with the worst lane dot, and the highest open risk", async () => {
    renderApp("/resources", listRoutes);

    const web = (await screen.findByRole("link", { name: "web" })).closest(
      "[role=row]",
    ) as HTMLElement;
    const cells = within(web).getAllByRole("cell");

    expect(cells[3]).toHaveTextContent("2");
    expect(cells[3]).toHaveTextContent("Fix now");
    expect(cells[3].querySelector(".bg-red")).not.toBeNull();
    expect(cells[4]).toHaveTextContent("95");
    const bucketRow = screen
      .getByRole("link", { name: "my-bucket" })
      .closest("[role=row]") as HTMLElement;
    expect(within(bucketRow).getAllByRole("cell")[4]).toHaveTextContent("65");
    expect(within(bucketRow).getAllByRole("cell")[3]).toHaveTextContent("Next");
  });

  it("shows a dash for the highest risk when the resource has no open scored finding", async () => {
    renderApp("/resources", listRoutes);

    const row = (await screen.findByRole("link", { name: "deploy" })).closest(
      "[role=row]",
    ) as HTMLElement;
    const cells = within(row).getAllByRole("cell");

    expect(cells[3]).toHaveTextContent("-");
    expect(cells[4]).toHaveTextContent("-");
  });

  it("shows the type with an icon and the last seen time of the scan that saw it", async () => {
    renderApp("/resources", listRoutes);

    const row = (await screen.findByRole("link", { name: "web" })).closest(
      "[role=row]",
    ) as HTMLElement;
    const cells = within(row).getAllByRole("cell");

    expect(cells[1].querySelector("svg[data-icon]")).not.toBeNull();
    expect(cells[1]).toHaveTextContent("Security Group");
    expect(cells[5]).toHaveAttribute("title", formatDate("2026-10-01T10:00:42Z"));
    expect(cells[5].textContent).toMatch(/ago|just now/);
  });

  it("says when nothing matches the search", async () => {
    const user = renderApp("/resources", listRoutes);
    await screen.findByRole("table");

    await user.type(screen.getByLabelText("Search"), "zzz");

    expect(
      await screen.findByText("No resources match these filters"),
    ).toBeInTheDocument();
  });

  it("shows global resources as global", async () => {
    renderApp("/resources", { ...listRoutes, "GET /api/resources": [policy] });

    expect(await screen.findByText("global")).toBeInTheDocument();
  });

  it("shortens a long id and keeps the full value in the title", async () => {
    renderApp("/resources", { ...listRoutes, "GET /api/resources": [policy] });

    const short = await screen.findByText("...:policy/deploy");

    expect(short).toHaveAttribute("title", "arn:aws:iam::123456789012:policy/deploy");
  });
});

describe("Resource detail", () => {
  const routes = {
    "GET /api/resources": [bucket, group, policy],
    "GET /api/findings": [finding({ resource_id: "sg-0abc123" })],
  };

  it("shows loading", async () => {
    renderApp("/resources/sg-0abc123", { ...routes, "GET /api/resources": never });

    expect(screen.getByText("Loading resource...")).toBeInTheDocument();
    await screen.findByText(/API online/);
  });

  it("shows the backend's message when it cannot be loaded", async () => {
    renderApp("/resources/sg-0abc123", {
      ...routes,
      "GET /api/findings": fail(500, "nope"),
    });

    expect(await screen.findByRole("alert")).toHaveTextContent("nope");
  });

  it("shows the stored attributes and the findings on the resource", async () => {
    renderApp("/resources/sg-0abc123", routes);

    expect(await screen.findByRole("heading", { name: "web" })).toBeInTheDocument();
    expect(screen.getByText("vpc_id")).toBeInTheDocument();
    expect(screen.getByText("vpc-1")).toBeInTheDocument();
    expect(
      screen.getByText(/A missing attribute means a call failed/),
    ).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /Security group allows SSH/ });
    expect(link).toHaveAttribute("href", "/findings/F-CIS-SG-001-aaaaaaaa");
  });

  it("opens a resource whose id contains slashes and colons", async () => {
    const id = encodeURIComponent("arn:aws:iam::123456789012:policy/deploy");
    renderApp(`/resources/${id}`, { ...routes, "GET /api/findings": [] });

    expect(await screen.findByRole("heading", { name: "deploy" })).toBeInTheDocument();
    expect(screen.getByText("No findings.")).toBeInTheDocument();
  });

  it("says when the resource is not stored", async () => {
    renderApp("/resources/gone", routes);

    expect(
      await screen.findByText("This resource is not in the stored data"),
    ).toBeInTheDocument();
  });

  it("links from the list to the detail page", async () => {
    renderApp("/resources", routes);

    const row = (await screen.findByRole("link", { name: "web" })).closest(
      "[role=row]",
    ) as HTMLElement;

    expect(within(row).getByRole("link", { name: "web" })).toHaveAttribute(
      "href",
      "/resources/sg-0abc123",
    );
  });
});
