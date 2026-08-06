import { beforeEach, describe, expect, it, vi } from "vitest";
import { loadLabelPrefs, saveLabelPrefsPatch } from "./labelPrefs";

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

describe("saveLabelPrefsPatch", () => {
  it("sends the whole label block, not just the patch", async () => {
    // The endpoint replaces the account's entire label document. The auto-apply
    // toggle and the label list are separate controls writing to it, so a
    // caller sending only its own field would blank the other's.
    getJSON.mockResolvedValue({
      autoApplyEnabled: true,
      seeded: true,
      allowlist: ["Primary", "Promotions"],
      keywordMappings: { Primary: ["Primary", "Important"] }
    });

    await saveLabelPrefsPatch({ autoApplyEnabled: false });

    const [url, body] = putJSON.mock.calls[0];
    expect(url).toBe("/api/labels/preferences");
    expect(body).toMatchObject({
      autoApplyEnabled: false,
      allowlist: ["Primary", "Promotions"],
      keywordMappings: { Primary: ["Primary", "Important"] }
    });
  });

  it("reads fresh before writing, so one tab cannot save the other's stale copy", async () => {
    getJSON.mockResolvedValue({ autoApplyEnabled: true, seeded: true, allowlist: ["Later"], keywordMappings: {} });

    await saveLabelPrefsPatch({ autoApplyEnabled: false });

    expect(getJSON).toHaveBeenCalledWith("/api/labels/preferences");
    const [, body] = putJSON.mock.calls[0];
    expect(body.allowlist).toEqual(["Later"]);
  });

  it("saves an empty allowlist when that is what was asked for", async () => {
    // Deliberately clearing every label must reach the server as an empty
    // list, not be mistaken for "no change".
    getJSON.mockResolvedValue({ autoApplyEnabled: true, seeded: true, allowlist: ["Primary"], keywordMappings: {} });

    await saveLabelPrefsPatch({ allowlist: [], keywordMappings: {} });

    const [, body] = putJSON.mock.calls[0];
    expect(body.allowlist).toEqual([]);
  });
});

describe("loadLabelPrefs", () => {
  it("fills in fields an older server omits", async () => {
    getJSON.mockResolvedValue({ autoApplyEnabled: false });

    const prefs = await loadLabelPrefs();

    expect(prefs.allowlist).toEqual([]);
    expect(prefs.keywordMappings).toEqual({});
    expect(prefs.autoApplyEnabled).toBe(false);
  });
});
