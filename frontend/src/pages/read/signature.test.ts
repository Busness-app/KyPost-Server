import { describe, it, expect } from "vitest";

import { signatureState, signatureLabel } from "./signature";
import type { DecryptedView, InboxEmail } from "./types";

function email(over: Partial<InboxEmail> = {}): InboxEmail {
  return { messageId: "1", sender: "s@example.com", subject: "s", status: "unread", atUtc: "", ...over };
}

function view(over: Partial<DecryptedView> = {}): DecryptedView {
  return { body: "", signed: false, verified: false, signerFingerprint: "", error: "", ...over };
}

describe("signatureState", () => {
  it("is none for a message carrying no signature", () => {
    expect(signatureState(email(), undefined, false)).toBe("none");
  });

  // The regression that started this: signed AND unencrypted showed nothing at
  // all, because the whole badge block was nested inside pgpEncrypted.
  it("is not none for a signed but unencrypted message", () => {
    expect(signatureState(email({ pgpSigned: true }), undefined, false)).not.toBe("none");
  });

  it("is checking while the browser is still verifying", () => {
    expect(signatureState(email({ pgpSigned: true }), undefined, true)).toBe("checking");
  });

  it("is verified when the local check bound the signer to the sender", () => {
    const local = view({ signed: true, verified: true, signerFingerprint: "ABC" });
    expect(signatureState(email({ pgpSigned: true }), local, false)).toBe("verified");
  });

  it("is mismatched when a known key signed it but not the sender's", () => {
    const local = view({ signed: true, verified: false, signerFingerprint: "ABC" });
    expect(signatureState(email({ pgpSigned: true }), local, false)).toBe("mismatched");
  });

  // No fingerprint means nothing was checked against anything — an ordinary
  // first-time correspondent, not a forgery. Saying "does not match sender"
  // here accuses someone on the strength of our own missing key.
  it("is unchecked when no key was bound to the sender", () => {
    const local = view({ signed: true, verified: false, signerFingerprint: "" });
    expect(signatureState(email({ pgpSigned: true }), local, false)).toBe("unchecked");
  });

  it("is unchecked when the verification attempt errored", () => {
    const local = view({ signed: true, verified: false, signerFingerprint: "", error: "fetch failed" });
    expect(signatureState(email({ pgpSigned: true }), local, false)).toBe("unchecked");
  });

  // A server-decrypted (legacy) account's encrypted mail: the verdict is on the
  // message itself and there is no local view.
  it("falls back to the server's verdict when there is no local view", () => {
    expect(signatureState(email({ pgpSigned: true, pgpVerified: true }), undefined, false)).toBe("verified");
    expect(
      signatureState(email({ pgpSigned: true, pgpVerified: false, pgpSignerFingerprint: "ABC" }), undefined, false)
    ).toBe("mismatched");
  });
});

describe("signatureLabel", () => {
  it("uses copy that claims no more than was established", () => {
    expect(signatureLabel("verified")).toBe("signature verified");
    expect(signatureLabel("mismatched")).toBe("signature does not match sender");
    expect(signatureLabel("unchecked")).toBe("signature could not be checked — no key for this sender");
    expect(signatureLabel("checking")).toBe("checking signature…");
    expect(signatureLabel("none")).toBe("");
  });
});
