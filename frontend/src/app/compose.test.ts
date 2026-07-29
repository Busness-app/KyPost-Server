import { describe, expect, it, vi } from "vitest";
import { formatBytes, keylessRecipientsFrom409, readFileAsAttachment } from "./compose";
import { HttpError } from "../api/client";

describe("readFileAsAttachment", () => {
  it("strips the data-URL prefix so the API receives raw base64", async () => {
    const file = new File(["hello"], "note.txt", { type: "text/plain" });
    const att = await readFileAsAttachment(file);
    expect(att.name).toBe("note.txt");
    expect(att.mimeType).toBe("text/plain");
    expect(att.size).toBe(5);
    // "hello" -> aGVsbG8=, with no "data:text/plain;base64," in front of it.
    expect(att.dataBase64).toBe("aGVsbG8=");
    expect(att.dataBase64).not.toContain("data:");
  });

  it("falls back to a generic mime type when the browser reports none", async () => {
    const file = new File(["x"], "blob.bin", { type: "" });
    await expect(readFileAsAttachment(file)).resolves.toMatchObject({
      mimeType: "application/octet-stream"
    });
  });
});

describe("keylessRecipientsFrom409", () => {
  it("pulls the recipient list out of a 409", () => {
    const err = new HttpError("conflict", 409, { keylessRecipients: ["a@x.test", "b@x.test"] });
    expect(keylessRecipientsFrom409(err)).toEqual(["a@x.test", "b@x.test"]);
  });

  it("returns null for a different status, so the caller uses the generic message", () => {
    expect(keylessRecipientsFrom409(new HttpError("boom", 500, {}))).toBeNull();
  });

  it("returns null for a non-HttpError and for an empty list", () => {
    expect(keylessRecipientsFrom409(new Error("nope"))).toBeNull();
    expect(keylessRecipientsFrom409(new HttpError("conflict", 409, { keylessRecipients: [] }))).toBeNull();
  });

  it("drops non-string entries rather than passing them through to the UI", () => {
    const err = new HttpError("conflict", 409, { keylessRecipients: ["a@x.test", 42, null] });
    expect(keylessRecipientsFrom409(err)).toEqual(["a@x.test"]);
  });
});

describe("formatBytes", () => {
  it("scales across the unit boundaries", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
  });
});
