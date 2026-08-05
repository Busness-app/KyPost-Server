import { describe, expect, it } from "vitest";
import {
  collectNotificationKeywordOptions,
  normalizePrefs,
  shouldWarnAboutSleepState
} from "./notifications";
import { normalizeConfig } from "../../api/config";

// normalizePrefs reads a per-account settings blob the server may have written
// under an older schema. The stakes are asymmetric: reading a missing field as
// "on" opts an account into putting sender and subject on a lock screen it
// never agreed to, while reading it as "off" only costs a setting the user can
// turn back on.
describe("normalizePrefs", () => {
  it("requires an explicit true for contentPreview, so an older settings file reads as private", () => {
    expect(normalizePrefs({ mode: "all" }).contentPreview).toBe(false);
  });

  it("does not accept a truthy non-true as opting in", () => {
    for (const value of ["true", 1, {}, [], "yes"]) {
      expect(normalizePrefs({ contentPreview: value }).contentPreview).toBe(false);
    }
  });

  it("keeps an explicit true", () => {
    expect(normalizePrefs({ contentPreview: true }).contentPreview).toBe(true);
  });

  it("falls back to none for an unknown or missing mode rather than notifying for everything", () => {
    expect(normalizePrefs({ mode: "everything" }).mode).toBe("none");
    expect(normalizePrefs({}).mode).toBe("none");
    expect(normalizePrefs(null).mode).toBe("none");
    expect(normalizePrefs(undefined).mode).toBe("none");
  });

  it("passes through the two real modes", () => {
    expect(normalizePrefs({ mode: "all" }).mode).toBe("all");
    expect(normalizePrefs({ mode: "keywords" }).mode).toBe("keywords");
  });

  it("coerces keyword entries to strings and tolerates a non-array", () => {
    expect(normalizePrefs({ keywords: ["Work", 7] }).keywords).toEqual(["Work", "7"]);
    expect(normalizePrefs({ keywords: "Work" }).keywords).toEqual([]);
  });
});

describe("collectNotificationKeywordOptions", () => {
  const cfg = normalizeConfig({
    labels: {
      allowlist: ["Primary", "Work"],
      keywordMappings: { Work: ["boss"], Receipts: ["invoice"] }
    }
  });

  it("merges the allowlist, mapping values, and IMAP labels without duplicates", () => {
    expect(collectNotificationKeywordOptions(cfg, ["Work", "Archive"], [])).toEqual([
      "Primary",
      "Work",
      "boss",
      "invoice",
      "Archive"
    ]);
  });

  it("keeps a selected keyword that no longer appears anywhere else", () => {
    // Otherwise the option disappears while the preference behind it survives
    // on the server, leaving no way to switch it off.
    expect(collectNotificationKeywordOptions(cfg, [], ["Retired"])).toContain("Retired");
  });

  it("survives a config with no labels at all", () => {
    expect(collectNotificationKeywordOptions(normalizeConfig({}), [], [])).toEqual([]);
  });
});

describe("shouldWarnAboutSleepState", () => {
  const mobile = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Mobile Safari/537.36";
  const desktop = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36";

  it("warns only when switching away from none on a mobile browser", () => {
    expect(shouldWarnAboutSleepState("none", "all", mobile)).toBe(true);
    expect(shouldWarnAboutSleepState("none", "keywords", mobile)).toBe(true);
  });

  it("stays quiet on desktop", () => {
    expect(shouldWarnAboutSleepState("none", "all", desktop)).toBe(false);
  });

  it("stays quiet when notifications were already on, or are being turned off", () => {
    expect(shouldWarnAboutSleepState("all", "keywords", mobile)).toBe(false);
    expect(shouldWarnAboutSleepState("all", "none", mobile)).toBe(false);
    expect(shouldWarnAboutSleepState("none", "none", mobile)).toBe(false);
  });
});
