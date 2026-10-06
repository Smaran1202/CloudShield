import { vi } from "vitest";

// The tests replace fetch with a table of answers. Nothing here talks to a real API, and
// none of this data is shown outside the tests.

export interface Call {
  method: string;
  path: string;
  search: string;
}

type Answer = unknown;
type Handler = Answer | ((call: Call) => Answer);

class FailWith {
  constructor(
    public status: number,
    public body: unknown,
  ) {}
}

class NetworkDown {}

export const fail = (status: number, detail: string) => new FailWith(status, { detail });
export const networkDown = () => new NetworkDown();

export let calls: Call[] = [];
let unmocked: string[] = [];

export function resetApiMock() {
  calls = [];
  unmocked = [];
  vi.unstubAllGlobals();
}

export function assertNoUnmockedRequests() {
  if (unmocked.length > 0)
    throw new Error(`Requests with no mock: ${unmocked.join(", ")}`);
}

export function callsTo(method: string, path: string): Call[] {
  return calls.filter((c) => c.method === method && c.path === path);
}

function respond(answer: Answer): Response {
  if (answer instanceof FailWith) {
    return new Response(JSON.stringify(answer.body), {
      status: answer.status,
      headers: { "Content-Type": "application/json" },
    });
  }
  return new Response(JSON.stringify(answer), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

// Keys look like "GET /api/scans". Anything not listed is recorded and fails the test.
export function mockApi(routes: Record<string, Handler>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const method = (init?.method ?? "GET").toUpperCase();
      const call = { method, path: url.pathname, search: url.search };
      calls.push(call);
      const key = `${method} ${url.pathname}`;
      if (!(key in routes)) {
        unmocked.push(key);
        return respond(new FailWith(500, { detail: `No mock for ${key}` }));
      }
      const handler = routes[key];
      const answer = await (typeof handler === "function"
        ? (handler as (c: Call) => Answer)(call)
        : handler);
      if (answer instanceof NetworkDown) throw new TypeError("Failed to fetch");
      return respond(answer);
    }),
  );
}
