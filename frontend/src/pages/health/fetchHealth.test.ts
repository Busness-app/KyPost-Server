import { describe, expect, it, vi, afterEach } from "vitest";
import { HttpError } from "../../api/client";
import { fetchHealth } from "./fetchHealth";

// /api/health answers 503 with the health report as its body. getJSON throws on
// any non-2xx, so the page's catch blanked the whole view exactly when the
// server had something to report — "System Unhealthy" rendered identically to
// "could not reach the server".

vi.mock("../../api/client", async () => {
  const actual = await vi.importActual<typeof import("../../api/client")>("../../api/client");
  return { ...actual, getJSON: vi.fn() };
});

const { getJSON } = await import("../../api/client");
const mockGetJSON = vi.mocked(getJSON);

afterEach(() => {
  mockGetJSON.mockReset();
});

describe("fetchHealth", () => {
  it("returns the body of a healthy response", async () => {
    mockGetJSON.mockResolvedValue({ healthy: true });
    await expect(fetchHealth()).resolves.toEqual({ healthy: true });
  });

  it("returns the report carried by a 503 instead of throwing", async () => {
    const body = { healthy: false, daemonStale: true, failureReason: ["daemon last reported 9m0s ago"] };
    mockGetJSON.mockRejectedValue(new HttpError("request failed: 503", 503, body));

    await expect(fetchHealth()).resolves.toEqual(body);
  });

  it("rethrows a 503 that is not a health report", async () => {
    // A reverse proxy's own 503 carries an HTML error page, not our JSON.
    mockGetJSON.mockRejectedValue(new HttpError("request failed: 503", 503, "<html>502 Bad Gateway</html>"));

    await expect(fetchHealth()).rejects.toBeInstanceOf(HttpError);
  });

  it("rethrows everything that is not a 503", async () => {
    mockGetJSON.mockRejectedValue(new HttpError("request failed: 401", 401, { error: "unauthorized" }));
    await expect(fetchHealth()).rejects.toBeInstanceOf(HttpError);

    mockGetJSON.mockRejectedValue(new TypeError("network error"));
    await expect(fetchHealth()).rejects.toBeInstanceOf(TypeError);
  });
});
