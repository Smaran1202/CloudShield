import {
  expect,
  test as base,
  type APIRequestContext,
  type Page,
} from "@playwright/test";
import type { FindingOut } from "../src/api";

export { expect };

export const API = "http://127.0.0.1:8000";

// Every test runs with this guard. The browser may only read: any request to the API other than
// GET is stopped and fails the test with its URL. Console errors, page errors and failed or
// error responses fail the test too.
export const test = base.extend<{ readOnlyGuard: void }>({
  readOnlyGuard: [
    async ({ page }, use) => {
      const problems: string[] = [];

      await page.route(/\/api\//, async (route) => {
        const request = route.request();
        if (!new URL(request.url()).pathname.startsWith("/api/")) {
          await route.continue();
        } else if (request.method() !== "GET") {
          problems.push(`Blocked ${request.method()} ${request.url()}`);
          await route.abort();
        } else {
          await route.continue();
        }
      });
      page.on("console", (message) => {
        if (message.type() === "error") problems.push(`Console error: ${message.text()}`);
      });
      page.on("pageerror", (error) => problems.push(`Page error: ${error.message}`));
      page.on("requestfailed", (request) => {
        const why = request.failure()?.errorText ?? "unknown";
        problems.push(`Request failed: ${request.method()} ${request.url()} (${why})`);
      });
      page.on("response", (response) => {
        if (response.status() >= 400) {
          problems.push(`HTTP ${response.status()}: ${response.url()}`);
        }
      });

      await use();
      expect(problems, "Problems seen while the test ran").toEqual([]);
    },
    { auto: true },
  ],
});

// Reads the API directly (GET only) so tests can adapt to whatever data exists.
export async function getJson<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(`${API}${path}`);
  expect(response.ok(), `GET ${path} answered ${response.status()}`).toBeTruthy();
  return (await response.json()) as T;
}

// Written here on purpose, not imported from the app, so a mistake in the app's own rule shows.
export const isActive = (f: FindingOut) =>
  f.status === "OPEN" && !f.dismissed && !f.merged_into;

export const listedRows = (page: Page) =>
  page
    .getByRole("table", { name: "Findings" })
    .locator('[role="row"]:not([data-testid="findings-header"])');

export const showing = (page: Page, n: number) =>
  expect(page.getByText(/Showing \d+ of \d+ findings/)).toContainText(`Showing ${n} of`);

export function trailingNumber(text: string): number {
  const match = /(\d+)\s*$/.exec(text);
  if (!match) throw new Error(`No number at the end of "${text}"`);
  return Number(match[1]);
}
