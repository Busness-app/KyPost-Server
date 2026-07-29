import { describe, expect, it } from "vitest";
import { labelsToText, textToLabels, mappingToText, textToMapping } from "./settings";

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
