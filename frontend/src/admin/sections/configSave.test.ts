import { beforeEach, describe, expect, it, vi } from "vitest";
import { saveConfigPatch } from "./configSave";

const getJSON = vi.fn();
const putJSON = vi.fn();

vi.mock("../../api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  putJSON: (url: string, body: unknown) => putJSON(url, body)
}));

beforeEach(() => {
  getJSON.mockReset();
  putJSON.mockReset();
  putJSON.mockResolvedValue({ ok: true });
});

describe("saveConfigPatch", () => {
  it("sends the whole config, not just the patch", async () => {
    getJSON.mockResolvedValue({
      timezone: "UTC",
      logLevel: "info",
      labels: { allowlist: ["Work"], keywordMappings: {} },
      rateLimits: { perMinute: 10, perHour: 100 }
    });

    await saveConfigPatch({ timezone: "Europe/London" });

    // Pin the endpoint too — destructuring only `body` out of the call would
    // still pass if the PUT went to the wrong URL.
    const [url, body] = putJSON.mock.calls[0];
    expect(url).toBe("/api/config");
    expect(body).toMatchObject({
      timezone: "Europe/London",
      logLevel: "info",
      labels: { allowlist: ["Work"] },
      rateLimits: { perMinute: 10, perHour: 100 }
    });
  });

  it("reads fresh before writing, so a panel cannot save a stale sibling's fields", async () => {
    getJSON.mockResolvedValue({ timezone: "UTC", labels: { allowlist: ["Later"], keywordMappings: {} } });

    await saveConfigPatch({ timezone: "Europe/London" });

    expect(getJSON).toHaveBeenCalledWith("/api/config");
    const [url, body] = putJSON.mock.calls[0];
    expect(url).toBe("/api/config");
    expect(body.labels.allowlist).toEqual(["Later"]);
  });
});
