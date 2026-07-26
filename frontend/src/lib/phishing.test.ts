import { describe, expect, it } from "vitest";
import { PHISHING_KEYWORD, isFlaggedPhishing } from "./phishing";

describe("isFlaggedPhishing", () => {
  it("recognizes the keyword the server sets", () => {
    expect(isFlaggedPhishing({ keywords: ["Primary", PHISHING_KEYWORD] })).toBe(true);
  });

  // IMAP keywords are case-insensitive, so a server is free to hand back a
  // different case than the one the poller set. Comparing case-sensitively
  // would silently drop the banner on exactly the mail it exists for.
  it.each([["$phishing"], ["$PHISHING"], ["$PhIsHiNg"]])("matches %s case-insensitively", (keyword) => {
    expect(isFlaggedPhishing({ keywords: [keyword] })).toBe(true);
  });

  it("tolerates surrounding whitespace", () => {
    expect(isFlaggedPhishing({ keywords: ["  $Phishing  "] })).toBe(true);
  });

  it("does not flag ordinary mail", () => {
    expect(isFlaggedPhishing({ keywords: ["Primary", "Receipts"] })).toBe(false);
  });

  it("does not flag on a partial match", () => {
    expect(isFlaggedPhishing({ keywords: ["$PhishingReport", "NotPhishing"] })).toBe(false);
  });

  it.each([
    ["absent keywords", {}],
    ["empty keywords", { keywords: [] }],
  ])("treats %s as clean", (_label, email) => {
    expect(isFlaggedPhishing(email)).toBe(false);
  });
});
