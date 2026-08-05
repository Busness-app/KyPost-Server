import { describe, expect, it, vi } from "vitest";
import {
  MAX_ATTACHMENT_BYTES,
  combineWarnings,
  deliverSealedPickupLinks,
  formatBytes,
  keylessRecipientsFrom409,
  keyChangedRecipientsFrom409,
  readFileAsAttachment,
  secureLinkWarning
} from "./compose";
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

describe("attachment budget", () => {
  // The backend derives maxMailAttachmentBytes from its 25 MiB request cap:
  // (25 MiB - 1 MiB overhead) * 3/4, because attachments travel base64-encoded
  // inside the JSON body. If this drifts, the UI accepts a set of attachments
  // the server refuses, and the error names a limit the user did not exceed.
  it("matches the backend's derived cap exactly", () => {
    expect(MAX_ATTACHMENT_BYTES).toBe(18874368);
  });

  // And the encoded form must fit the request cap it was derived from.
  it("base64-expands to within the 25 MiB request cap", () => {
    const encoded = Math.ceil((MAX_ATTACHMENT_BYTES * 4) / 3);
    expect(encoded + 1024 * 1024).toBeLessThanOrEqual(25 * 1024 * 1024);
  });
});

// --- partial delivery of a client-side encrypted send -----------------------
//
// A browser-side encrypted send is several deliveries: one POST carrying the
// ciphertext for every recipient with a key, then one sealed pickup link per
// recipient without one. The keyed POST goes first and cannot be taken back.
//
// The compose window used to `await sendSealedPickupLink(...)` in a bare loop,
// so the first link that failed threw out of the send entirely: the remaining
// recipients were never attempted, and the error the user saw ("send failed")
// invited a retry that would deliver the keyed copy a second time. These cover
// the two properties that fixes it — every recipient is attempted, and what
// failed is reported rather than thrown.

describe("deliverSealedPickupLinks", () => {
  it("reports no failures when every link is sent", async () => {
    const sent: string[] = [];
    const failed = await deliverSealedPickupLinks(["a@example.com", "b@example.com"], async (addr) => {
      sent.push(addr);
    });

    expect(sent).toEqual(["a@example.com", "b@example.com"]);
    expect(failed).toEqual([]);
  });

  it("still attempts the remaining recipients after one fails", async () => {
    const attempted: string[] = [];
    const failed = await deliverSealedPickupLinks(
      ["a@example.com", "b@example.com", "c@example.com"],
      async (addr) => {
        attempted.push(addr);
        if (addr === "a@example.com") throw new Error("smtp rejected");
      }
    );

    expect(attempted).toEqual(["a@example.com", "b@example.com", "c@example.com"]);
    expect(failed).toEqual(["a@example.com"]);
  });

  it("does not throw when every link fails, so the delivered copy is not retried", async () => {
    const failed = await deliverSealedPickupLinks(["a@example.com", "b@example.com"], async () => {
      throw new Error("offline");
    });

    expect(failed).toEqual(["a@example.com", "b@example.com"]);
  });
});

describe("combineWarnings", () => {
  it("drops empty parts and joins the rest", () => {
    expect(combineWarnings("", "")).toBe("");
    expect(combineWarnings("saved to Sent failed", "")).toBe("saved to Sent failed");
    expect(combineWarnings("", "1 of 2 secure links could not be sent")).toBe(
      "1 of 2 secure links could not be sent"
    );
    expect(combineWarnings("a", "b")).toBe("a; b");
  });
});

describe("secureLinkWarning", () => {
  it("is empty when nothing failed", () => {
    expect(secureLinkWarning([], 3)).toBe("");
  });

  it("names the recipients who got nothing", () => {
    // Wording matches the server's partialDeliveryWarning, and names the
    // addresses because the user's only recovery is to contact them directly.
    expect(secureLinkWarning(["a@example.com"], 2)).toBe(
      "1 of 2 secure links could not be sent: a@example.com"
    );
  });
});

describe("keyChangedRecipientsFrom409", () => {
  // A broken TOFU pin is not a missing key, and must never be offered the
  // pickup fallback: the fallback mails the message plaintext in the clear,
  // which is the worst response to "the key published for this address just
  // changed". The server now refuses these sends outright with a distinct
  // body; the UI has to say why, or the user reads "no PGP key" and reaches
  // for the very checkbox that downgrades them.
  it("extracts the changed-key recipients from the 409 body", () => {
    const err = new HttpError("conflict", 409, {
      error: "the PGP key on file for some recipients no longer matches",
      keyChangedRecipients: ["bob@x.test"],
      pickupFallbackAvailable: false,
    });
    expect(keyChangedRecipientsFrom409(err)).toEqual(["bob@x.test"]);
  });

  it("returns null for the keyless 409, which is a different situation", () => {
    const err = new HttpError("conflict", 409, { keylessRecipients: ["a@x.test"] });
    expect(keyChangedRecipientsFrom409(err)).toBeNull();
  });

  it("returns null for anything that is not a 409", () => {
    expect(keyChangedRecipientsFrom409(new Error("boom"))).toBeNull();
  });
});
