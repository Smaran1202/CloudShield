import { describe, expect, it, vi } from "vitest";
import { api, ApiError, messageFromDetail } from "./api";

describe("messageFromDetail", () => {
  it("uses FastAPI's detail text", () => {
    expect(messageFromDetail({ detail: "A scan is already running." }, 409)).toBe(
      "A scan is already running.",
    );
  });

  it("joins the messages of a validation error", () => {
    const body = {
      detail: [{ msg: "Field required" }, { msg: "Input should be a string" }],
    };

    expect(messageFromDetail(body, 422)).toBe("Field required; Input should be a string");
  });

  it("falls back to the HTTP status when there is no usable detail", () => {
    expect(messageFromDetail(null, 502)).toBe("The API answered with HTTP 502.");
    expect(messageFromDetail({ detail: "" }, 500)).toBe(
      "The API answered with HTTP 500.",
    );
  });
});

describe("api", () => {
  it("throws an ApiError with the backend's message and status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ detail: "Scan not found." }), { status: 404 }),
      ),
    );

    const error = await api.scan(9).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).message).toBe("Scan not found.");
    expect((error as ApiError).status).toBe(404);
  });

  it("explains that the API cannot be reached when the request fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));

    const error = await api.health().catch((e: unknown) => e);

    expect((error as ApiError).message).toBe(
      "Cannot reach the API at http://localhost:8000. Is it running?",
    );
    expect((error as ApiError).status).toBeNull();
  });

  it("copes with an error body that is not JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("<html>bad gateway</html>", { status: 502 })),
    );

    const error = await api.scans().catch((e: unknown) => e);

    expect((error as ApiError).message).toBe("The API answered with HTTP 502.");
  });

  it("encodes ids in paths and sends the refresh flag", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await api.finding("F-1/odd id");
    await api.generateFix("F-2", true);

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "http://localhost:8000/api/findings/F-1%2Fodd%20id",
      undefined,
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "http://localhost:8000/api/findings/F-2/fix?refresh=true",
      { method: "POST" },
    );
  });

  it("starts a scan with a POST and no body, so the server's own settings are used", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await api.startScan();

    expect(fetchMock).toHaveBeenCalledWith("http://localhost:8000/api/scans", {
      method: "POST",
    });
  });
});
