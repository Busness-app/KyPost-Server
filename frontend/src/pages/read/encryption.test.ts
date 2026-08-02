import { describe, expect, it } from "vitest";

import { encryptionLabel, encryptionState } from "./encryption";
import type { DecryptedView, InboxEmail } from "./types";

const base: InboxEmail = {
  messageId: "1",
  sender: "alice@example.com",
  subject: "Quarterly numbers",
  status: "unread",
  atUtc: "2026-01-01T00:00:00Z"
};

const decrypted: DecryptedView = {
  body: "revenue fell 40%",
  signed: false,
  verified: false,
  signerFingerprint: "",
  error: ""
};

describe("encryptionState", () => {
  it("marks nothing on ordinary mail", () => {
    expect(encryptionState({ ...base, body: "hello" })).toBe("none");
  });

  // The case the column exists for. A server-custody account decrypts on the
  // server, so the row arrives encrypted AND readable — and used to carry no
  // marking at all, meaning an encrypted message and a cleartext one looked
  // identical in the list.
  it("marks a server-decrypted message as encrypted", () => {
    expect(encryptionState({ ...base, pgpEncrypted: true, body: "revenue fell 40%" })).toBe("encrypted");
  });

  // pgpEncrypted with no body and no error is the client-protected wire shape:
  // the server cannot decrypt for this account and does not pretend to.
  it("marks an undecryptable-yet message as locked", () => {
    expect(encryptionState({ ...base, pgpEncrypted: true })).toBe("locked");
  });

  it("marks a message this browser has decrypted as encrypted", () => {
    expect(encryptionState({ ...base, pgpEncrypted: true }, decrypted)).toBe("encrypted");
  });

  it("marks a server-side decrypt failure as failed", () => {
    expect(encryptionState({ ...base, pgpEncrypted: true, pgpDecryptError: "no matching key" })).toBe("failed");
  });

  // A client-protected account's failure never reaches the server, so the
  // local view is the only place the verdict exists.
  it("marks a local decrypt failure as failed", () => {
    const failed = { ...decrypted, body: "", error: "wrong passphrase" };
    expect(encryptionState({ ...base, pgpEncrypted: true }, failed)).toBe("failed");
  });

  // Guards the ordering inside the function: a failure with a body present
  // must not be reported as merely encrypted.
  it("prefers failed over encrypted when a body and an error are both present", () => {
    expect(encryptionState({ ...base, pgpEncrypted: true, body: "stale", pgpDecryptError: "bad packet" })).toBe("failed");
  });

  // pgpDecryptError on a message that is not flagged encrypted is not this
  // column's business — nothing about it is encrypted to report.
  it("ignores a decrypt error on unencrypted mail", () => {
    expect(encryptionState({ ...base, pgpDecryptError: "stale field" })).toBe("none");
  });
});

describe("encryptionLabel", () => {
  it("names the failure so the row is not silently unreadable", () => {
    expect(encryptionLabel("failed", "no matching key")).toBe("Could not decrypt: no matching key");
  });

  it("survives a failure with no error text", () => {
    expect(encryptionLabel("failed")).toBe("Could not decrypt: unknown error");
  });

  it("tells a locked row what to do about it", () => {
    expect(encryptionLabel("locked")).toContain("unlock");
  });

  it("says nothing for an unencrypted row", () => {
    expect(encryptionLabel("none")).toBe("");
  });
});
