import { expect, test, type Page } from "@playwright/test";
import { OWNER_PASSWORD, VIEWER_PASSWORD } from "./credentials";

const WRONG = "The role or password is wrong.";

// Every request the page sends to the API that is not a GET. Only the login and the logout may
// be among them.
function recordWrites(page: Page): string[] {
  const writes: string[] = [];
  page.on("request", (request) => {
    const { pathname } = new URL(request.url());
    const method = request.method();
    if (pathname.startsWith("/api/") && method !== "GET" && method !== "OPTIONS") {
      writes.push(`${method} ${pathname}`);
    }
  });
  return writes;
}

const notAuth = (writes: string[]) =>
  writes.filter((write) => !/^POST \/api\/auth\/(login|logout)$/.test(write));

async function logIn(page: Page, role: "Owner" | "Viewer", password: string) {
  await page.getByRole("radio", { name: new RegExp(role) }).check();
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Log in" }).click();
}

test("without a session every page is the login page", async ({ page }) => {
  await page.goto("/findings");

  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Log in" })).toBeVisible();
  await expect(page.getByLabel("Password")).toBeFocused();
  await expect(page.getByRole("button", { name: "Run scan" })).toHaveCount(0);
});

test("a wrong password gives one plain message and stays on the login page", async ({
  page,
}) => {
  await page.goto("/login");

  await logIn(page, "Owner", "not the password");

  await expect(page.getByRole("alert")).toHaveText(WRONG);
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByLabel("Password")).toBeFocused();
});

test("a viewer can look, every action control is disabled, and nothing is written", async ({
  page,
}) => {
  const writes = recordWrites(page);
  await page.goto("/findings?lane=all");
  await expect(page).toHaveURL(/\/login$/);

  await logIn(page, "Viewer", VIEWER_PASSWORD);

  await expect(page).toHaveURL(/\/findings\?lane=all$/);
  await expect(page.getByTestId("role-badge")).toHaveText("Viewer");
  for (const name of ["Run scan", "More ways to scan"]) {
    const button = page.getByRole("button", { name });
    await expect(button).toBeDisabled();
    await expect(button).toHaveAttribute("title", "Viewing only");
  }

  await page.getByRole("table", { name: "Findings" }).getByRole("link").first().click();
  const dismiss = page.getByRole("button", { name: "Dismiss", exact: true });
  await expect(dismiss).toBeDisabled();
  await expect(dismiss).toHaveAttribute("title", "Viewing only");
  await page.getByRole("tab", { name: "Fix", exact: true }).click();
  const generate = page.getByRole("button", { name: "Generate fix" });
  await expect(generate).toBeDisabled();
  await expect(generate).toHaveAttribute("title", "Viewing only");

  await page.goto("/scans");
  await expect(
    page.getByRole("button", { name: "Import a results file" }),
  ).toBeDisabled();

  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/findings");
  await expect(page).toHaveURL(/\/login$/);
  expect(notAuth(writes)).toEqual([]);
});

test("the owner sees the same pages with the controls enabled, and presses none", async ({
  page,
}) => {
  const writes = recordWrites(page);
  await page.goto("/login");

  await logIn(page, "Owner", OWNER_PASSWORD);

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByTestId("role-badge")).toHaveText("Owner");
  await expect(page.getByRole("button", { name: "Run scan" })).toBeEnabled();
  await expect(page.getByRole("button", { name: "More ways to scan" })).toBeEnabled();
  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  expect(notAuth(writes)).toEqual([]);
});
