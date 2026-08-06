import { describe, expect, it } from "vitest";
import { labelsToText, textToLabels, mappingToText, textToMapping, resolveConfigTab } from "./settings";

// These parse operator-typed textarea content into the label allowlist and the
// label->keyword mapping the classifier is bound to. A silent parse failure
// here does not error — it just drops a label, and the classifier is then
// constrained to an allowlist the operator did not write.
describe("textToLabels", () => {
  it("splits on newlines and drops blanks and duplicates", () => {
    expect(textToLabels("Primary\n\nWork\nPrimary\n  \n")).toEqual(["Primary", "Work"]);
  });

  it("handles CRLF, so a file pasted from Windows does not produce labels with a trailing \\r", () => {
    expect(textToLabels("Primary\r\nWork")).toEqual(["Primary", "Work"]);
  });

  it("round-trips through labelsToText", () => {
    const labels = ["Primary", "Work", "Receipts"];
    expect(textToLabels(labelsToText(labels))).toEqual(labels);
  });
});

describe("textToMapping", () => {
  it("parses label: value, value lines", () => {
    expect(textToMapping("Work: boss, project\nReceipts: invoice")).toEqual({
      Work: ["boss", "project"],
      Receipts: ["invoice"]
    });
  });

  it("keeps colons that appear inside values, splitting only on the first", () => {
    expect(textToMapping("Links: https://example.com")).toEqual({
      Links: ["https://example.com"]
    });
  });

  it("skips lines with no colon, an empty label, or no values rather than half-parsing them", () => {
    expect(textToMapping("nocolon\n: orphan\nEmpty:\nWork: boss")).toEqual({ Work: ["boss"] });
  });

  it("round-trips through mappingToText", () => {
    const mapping = { Work: ["boss", "project"], Receipts: ["invoice"] };
    expect(textToMapping(mappingToText(mapping))).toEqual(mapping);
  });
});

// The tab now comes from the URL, so it is attacker-and-typo-reachable. A value
// this function passes through is a value that must have a panel to render.
describe("resolveConfigTab", () => {
  it("defaults by role when no tab is asked for", () => {
    expect(resolveConfigTab(null, true)).toBe("application");
    expect(resolveConfigTab(null, false)).toBe("email");
    expect(resolveConfigTab("", false)).toBe("email");
  });

  it("opens a tab the user is allowed to see", () => {
    expect(resolveConfigTab("notifications", false)).toBe("notifications");
    expect(resolveConfigTab("carddav", false)).toBe("carddav");
    expect(resolveConfigTab("wkd", true)).toBe("wkd");
  });

  it("falls back instead of rendering a tab strip with no panel under it", () => {
    expect(resolveConfigTab("nope", true)).toBe("application");
    expect(resolveConfigTab("nope", false)).toBe("email");
  });

  it("falls back for an admin-only tab requested by a non-admin", () => {
    // Reachable by pasting a colleague's URL, not only by typing nonsense.
    for (const tab of ["application", "labels", "llm", "wkd"]) {
      expect(resolveConfigTab(tab, false)).toBe("email");
    }
  });

  it("keeps notifications available to non-admins — it is a per-account preference", () => {
    expect(resolveConfigTab("notifications", false)).toBe("notifications");
    expect(resolveConfigTab("notifications", true)).toBe("notifications");
  });
});
