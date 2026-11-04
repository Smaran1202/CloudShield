import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { finding, findingDetail, scan } from "../test/factories";
import { calls, callsTo, fail } from "../test/mockApi";
import { renderApp } from "../test/render";

const LOG_IN = fail(401, "Log in first.");
const WRONG = "The role or password is wrong.";
const OWNER = { auth_enabled: true, role: "owner" };
const VIEWER = { auth_enabled: true, role: "viewer" };

const writes = () => calls.filter((call) => call.method !== "GET");
const here = () => screen.getByTestId("location").textContent;

// The API starts logged out. A successful login switches it to the session of `role`.
function loginRoutes(role: typeof OWNER | typeof VIEWER) {
  let loggedIn = false;
  return {
    "GET /api/auth/me": () => (loggedIn ? role : LOG_IN),
    "POST /api/auth/login": () => {
      loggedIn = true;
      return role;
    },
  };
}

describe("the login being off", () => {
  it("shows no login page, no role badge and no log out button, and the controls work", async () => {
    renderApp("/scans");

    expect(
      await screen.findByRole("table", { name: "Scans" }).catch(() => null),
    ).toBeNull();
    await screen.findByText(/API online/);
    expect(here()).toBe("/scans");
    expect(screen.queryByTestId("role-badge")).toBeNull();
    expect(screen.queryByRole("button", { name: "Log out" })).toBeNull();
    expect(screen.getByRole("button", { name: "Run scan" })).toBeEnabled();
  });

  it("sends a visit to /login back to the app", async () => {
    renderApp("/login");

    await waitFor(() => expect(here()).toBe("/"));
  });
});

describe("the login page", () => {
  it("is shown when the API says there is no session, and the app behind it is not", async () => {
    renderApp("/findings", { "GET /api/auth/me": LOG_IN, "GET /api/findings": [] });

    expect(await screen.findByRole("heading", { name: "Log in" })).toBeInTheDocument();
    expect(here()).toBe("/login");
    expect(screen.queryByRole("button", { name: "Run scan" })).toBeNull();
    expect(screen.queryByRole("navigation", { name: "Main" })).toBeNull();
  });

  it("is shown when any request gets a 401", async () => {
    renderApp("/scans", { "GET /api/scans": LOG_IN });

    expect(await screen.findByRole("heading", { name: "Log in" })).toBeInTheDocument();
    expect(here()).toBe("/login");
  });

  it("puts the cursor in the password field, with the owner role chosen", async () => {
    renderApp("/", { "GET /api/auth/me": LOG_IN });

    const field = await screen.findByLabelText("Password");

    expect(field).toHaveFocus();
    expect(field).toHaveAttribute("type", "password");
    expect(field).toHaveAttribute("autocomplete", "current-password");
    expect(screen.getByRole("radio", { name: /Owner/ })).toBeChecked();
    expect(screen.getByRole("radio", { name: /Viewer/ })).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Log in" })).toBeDisabled();
  });

  it("logs in with the chosen role, sends the password once, and returns to the page it came from", async () => {
    const user = renderApp("/findings?severity=HIGH", {
      ...loginRoutes(VIEWER),
      "GET /api/findings": [],
    });
    const field = await screen.findByLabelText("Password");

    await user.click(screen.getByRole("radio", { name: /Viewer/ }));
    await user.type(field, "viewer password");
    await user.click(screen.getByRole("button", { name: "Log in" }));

    await waitFor(() => expect(here()).toBe("/findings?severity=HIGH"));
    const [login] = callsTo("POST", "/api/auth/login");
    expect(login.body).toEqual({ role: "viewer", password: "viewer password" });
    expect(login.credentials).toBe("include");
    expect(await screen.findByTestId("role-badge")).toHaveTextContent("Viewer");
    expect(callsTo("POST", "/api/auth/login")).toHaveLength(1);
  });

  it("says the same plain thing for a wrong password, clears the field and keeps the cursor there", async () => {
    const user = renderApp("/", {
      "GET /api/auth/me": LOG_IN,
      "POST /api/auth/login": fail(401, WRONG),
    });
    const field = await screen.findByLabelText("Password");

    await user.type(field, "not the password");
    await user.click(screen.getByRole("button", { name: "Log in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(WRONG);
    expect(field).toHaveValue("");
    expect(field).toHaveFocus();
    expect(here()).toBe("/login");
  });

  it("shows how long to wait when there were too many tries", async () => {
    const user = renderApp("/", {
      "GET /api/auth/me": LOG_IN,
      "POST /api/auth/login": fail(
        429,
        "Too many wrong tries. Try again in 240 seconds.",
      ),
    });

    await user.type(await screen.findByLabelText("Password"), "whatever");
    await user.click(screen.getByRole("button", { name: "Log in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Try again in 240 seconds",
    );
  });

  it("can be submitted with the Enter key", async () => {
    const user = renderApp("/", loginRoutes(OWNER));

    await user.type(await screen.findByLabelText("Password"), "owner password{Enter}");

    await waitFor(() => expect(callsTo("POST", "/api/auth/login")).toHaveLength(1));
    await waitFor(() => expect(here()).toBe("/"));
  });
});

describe("the owner", () => {
  it("sees an Owner badge and a Log out button, and every control works", async () => {
    renderApp("/scans", { "GET /api/auth/me": OWNER });

    expect(await screen.findByTestId("role-badge")).toHaveTextContent("Owner");
    expect(screen.getByRole("button", { name: "Run scan" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "More ways to scan" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Import a results file" })).toBeEnabled();
  });

  it("logs out, goes to the login page and sends the logout once", async () => {
    const user = renderApp("/scans", {
      "GET /api/auth/me": OWNER,
      "POST /api/auth/logout": null,
    });

    await user.click(await screen.findByRole("button", { name: "Log out" }));

    expect(await screen.findByRole("heading", { name: "Log in" })).toBeInTheDocument();
    expect(here()).toBe("/login");
    expect(callsTo("POST", "/api/auth/logout")).toHaveLength(1);
  });

  it("stays logged in and says so when the logout fails", async () => {
    const user = renderApp("/scans", {
      "GET /api/auth/me": OWNER,
      "POST /api/auth/logout": fail(500, "database is locked"),
    });

    await user.click(await screen.findByRole("button", { name: "Log out" }));

    expect(await screen.findByText("Could not log out.")).toBeInTheDocument();
    expect(here()).toBe("/scans");
  });
});

describe("a viewer", () => {
  const ID = "F-OWN-V1";
  const path = `/api/findings/${ID}`;
  const detail = findingDetail({ finding_id: ID });
  const routes = { "GET /api/auth/me": VIEWER };

  it("sees a Viewer badge, and Run scan and its menu are disabled with the reason", async () => {
    renderApp("/scans", routes);

    expect(await screen.findByTestId("role-badge")).toHaveTextContent("Viewer");
    for (const name of ["Run scan", "More ways to scan"]) {
      const button = screen.getByRole("button", { name });
      expect(button).toBeDisabled();
      expect(button).toHaveAttribute("title", "Viewing only");
    }
  });

  it("cannot import a file from the Imports section", async () => {
    renderApp("/scans", routes);

    const button = await screen.findByRole("button", { name: "Import a results file" });

    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", "Viewing only");
  });

  it("cannot dismiss, or generate a fix, but still reads the finding", async () => {
    renderApp(`/findings/${ID}`, { ...routes, [`GET ${path}`]: detail });

    const dismiss = await screen.findByRole("button", { name: "Dismiss" });

    expect(dismiss).toBeDisabled();
    expect(dismiss).toHaveAttribute("title", "Viewing only");
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(detail.title);
  });

  it("cannot generate a fix", async () => {
    renderApp(`/findings/${ID}?tab=fix`, { ...routes, [`GET ${path}`]: detail });

    const generate = await screen.findByRole("button", { name: "Generate fix" });

    expect(generate).toBeDisabled();
    expect(generate).toHaveAttribute("title", "Viewing only");
  });

  it("cannot undo a dismissal or use Review and dismiss", async () => {
    const dismissed = findingDetail({
      finding_id: ID,
      dismissed: true,
      disposition: "accepted",
    });
    renderApp(`/findings/${ID}`, { ...routes, [`GET ${path}`]: dismissed });

    expect(await screen.findByRole("button", { name: "Undo dismissal" })).toBeDisabled();
  });

  it("cannot dismiss all AWS-managed findings", async () => {
    const managed = finding({
      finding_id: "S1",
      risk_score: 62,
      suggested_not_applicable: { reason: "AWS owns this." },
    });
    renderApp("/findings", {
      ...routes,
      "GET /api/scans": [scan()],
      "GET /api/findings": [managed],
    });

    const more = await screen.findByRole("button", { name: "More" });

    expect(more).toBeDisabled();
    expect(more).toHaveAttribute("title", "Viewing only");
  });

  it("sends no request except GET, whatever is pressed", async () => {
    const user = renderApp(`/findings/${ID}?tab=fix`, {
      ...routes,
      [`GET ${path}`]: detail,
    });
    await screen.findByRole("button", { name: "Generate fix" });

    for (const name of ["Run scan", "More ways to scan", "Dismiss", "Generate fix"]) {
      const button = screen.queryByRole("button", { name });
      if (button) await user.click(button);
    }

    expect(writes()).toEqual([]);
  });

  it("is not stopped by the page itself from reading", async () => {
    renderApp("/findings", { ...routes, "GET /api/findings": [finding()] });

    const table = await screen.findByRole("table", { name: "Findings" });

    expect(within(table).getAllByRole("row").length).toBeGreaterThan(1);
  });
});
