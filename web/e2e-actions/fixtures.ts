import {
  expect,
  test as base,
  type APIRequestContext,
  type Page,
} from "@playwright/test";
import type { FindingOut, ScanOut } from "../src/api";

export { expect };

const port = process.env.E2E_ACTIONS_API_PORT;
// The test API, read directly (GET only) by the tests, and as the browser reaches it.
export const API = `http://127.0.0.1:${port}`;
const BROWSER_API_ORIGIN = `http://localhost:${port}`;

interface Guard {
  // A test that expects the API to refuse something says so, so that the refusal (and the
  // console line the browser writes for it) is not counted as a problem.
  allowStatus: (status: number) => void;
}

// These tests write, so the guard works the other way round from the read-only suite: the
// page may only talk to the test API. A request to any other API fails the test. Console
// errors, page errors, failed requests and error responses fail it too, unless allowed.
export const test = base.extend<{ guard: Guard }>({
  guard: [
    async ({ page }, use) => {
      const problems: string[] = [];
      const allowed = new Set<number>();

      await page.route(/\/api\//, async (route) => {
        const request = route.request();
        const url = new URL(request.url());
        if (!url.pathname.startsWith("/api/") || url.origin === BROWSER_API_ORIGIN) {
          await route.continue();
          return;
        }
        problems.push(`Blocked ${request.method()} ${request.url()}: not the test API`);
        await route.abort();
      });
      page.on("console", (message) => {
        if (message.type() !== "error") return;
        const status = /status of (\d{3})/.exec(message.text())?.[1];
        if (status && allowed.has(Number(status))) return;
        problems.push(`Console error: ${message.text()}`);
      });
      page.on("pageerror", (error) => problems.push(`Page error: ${error.message}`));
      page.on("requestfailed", (request) => {
        const why = request.failure()?.errorText ?? "unknown";
        problems.push(`Request failed: ${request.method()} ${request.url()} (${why})`);
      });
      page.on("response", (response) => {
        if (response.status() >= 400 && !allowed.has(response.status())) {
          problems.push(`HTTP ${response.status()}: ${response.url()}`);
        }
      });

      await use({ allowStatus: (status) => allowed.add(status) });
      expect(problems, "Problems seen while the test ran").toEqual([]);
    },
    { auto: true },
  ],
});

export async function getJson<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(`${API}${path}`);
  expect(response.ok(), `GET ${path} answered ${response.status()}`).toBeTruthy();
  return (await response.json()) as T;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// Waits for the newest scan to end. `after` is the id of the newest scan before the run was
// started (null when there was none), so an earlier scan is never taken for the new one.
export async function waitForScan(
  request: APIRequestContext,
  after: number | null,
  minutes: number,
): Promise<ScanOut> {
  const deadline = Date.now() + minutes * 60_000;
  while (Date.now() < deadline) {
    const [latest] = await getJson<ScanOut[]>(request, "/api/scans");
    const ended = latest?.status === "completed" || latest?.status === "failed";
    if (latest && ended && (after === null || latest.id > after)) return latest;
    await sleep(3000);
  }
  throw new Error(`The scan did not end within ${minutes} minutes.`);
}

export const isActive = (f: FindingOut) =>
  f.status === "OPEN" && !f.dismissed && !f.merged_into;

export const findingPath = (finding: FindingOut) =>
  `/findings/${encodeURIComponent(finding.finding_id)}`;

export const headline = (page: Page) => page.getByRole("heading", { level: 1 });
