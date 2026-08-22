import { describe, expect, it } from "vitest";
import { normalizeConfig } from "./config";

// The config response crosses a trust boundary: a mixed-version deployment or a
// hand-edited config document can send a field with the wrong shape entirely.
// normalizeConfig used to assert the shape (`as Record<string, any>`) rather
// than check it, so a wrong type was handed out under the right TypeScript
// name and the failure surfaced later, at whatever first called `.map()` on it.
describe("normalizeConfig rejects wrongly-typed fields instead of passing them through", () => {
  it("returns an array for allowlist even when the server sends a string", () => {
    const cfg = normalizeConfig({ labels: { allowlist: "work,personal" } });
    expect(Array.isArray(cfg.labels.allowlist)).toBe(true);
    expect(cfg.labels.allowlist).toEqual([]);
  });

  it("drops non-string members of allowlist", () => {
    const cfg = normalizeConfig({ labels: { allowlist: ["work", 7, null, "personal"] } });
    expect(cfg.labels.allowlist).toEqual(["work", "personal"]);
  });

  it("falls back to defaults when a nested object arrives as a scalar or array", () => {
    const cfg = normalizeConfig({ scan: "90", rateLimits: [10, 20], labels: "none", classifier: 3 });
    expect(cfg.scan.intervalSeconds).toBe(90);
    expect(cfg.rateLimits).toEqual({ perMinute: 10, perHour: 20 });
    expect(cfg.labels).toEqual({ allowlist: [], keywordMappings: {} });
    expect(cfg.classifier.baseUrl).toBe("");
  });

  it("keeps numbers numeric rather than adopting a numeric string", () => {
    const cfg = normalizeConfig({ scan: { intervalSeconds: "120" }, rateLimits: { perMinute: NaN } });
    expect(cfg.scan.intervalSeconds).toBe(90);
    expect(cfg.rateLimits.perMinute).toBe(10);
  });

  it("keeps strings stringy", () => {
    const cfg = normalizeConfig({ timezone: 5, logLevel: { level: "debug" } });
    expect(cfg.timezone).toBe("UTC");
    expect(cfg.logLevel).toBe("info");
  });

  it("still passes a well-formed document through unchanged", () => {
    const cfg = normalizeConfig({
      timezone: "Europe/Berlin",
      logLevel: "debug",
      scan: { intervalSeconds: 30 },
      rateLimits: { perMinute: 5, perHour: 50 },
      labels: { allowlist: ["work"], keywordMappings: { work: ["invoice"] } },
      classifier: { baseUrl: "http://ollama:11434", classifyPath: "/api/generate", apiKeySet: true }
    });
    expect(cfg).toEqual({
      timezone: "Europe/Berlin",
      logLevel: "debug",
      scan: { intervalSeconds: 30 },
      rateLimits: { perMinute: 5, perHour: 50 },
      labels: { allowlist: ["work"], keywordMappings: { work: ["invoice"] } },
      classifier: { baseUrl: "http://ollama:11434", apiKey: "", classifyPath: "/api/generate", apiKeySet: true }
    });
  });
});
