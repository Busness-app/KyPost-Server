import { describe, it, expect } from "vitest";

import { signatureState, signatureLabel } from "./signature";
import type { DecryptedView, InboxEmail } from "./types";

function email(over: Partial<InboxEmail> = {}): InboxEmail {
  return { messageId: "1", sender: "s@example.com", subject: "s", status: "unread", atUtc: "", ...over };
}

function view(over: Partial<DecryptedView> = {}): DecryptedView {
  return {
    body: "",
    signed: false,
    verified: false,
    signerFingerprint: "",
    error: "",
    bodyFromVerifiedPart: false,
    signerConflict: false,
    ...over
  };
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
    expect(signatureLabel("checking")).toBe("checking signature…");
    expect(signatureLabel("none")).toBe("");
  });

  // The old copy read "…— no key for this sender", which is false in the case
  // that matters most: an impostor signs with their own key, the server offers
  // only the real sender's key, and the check fails. A key for that sender
  // exists and is precisely why it failed.
  it("does not claim why the check failed", () => {
    expect(signatureLabel("unchecked")).toBe("signature could not be checked");
  });

  it("names a changed key rather than calling it unchecked", () => {
    expect(signatureLabel("conflicted")).toBe("this sender's key has changed");
  });
});

// A contact whose stored key no longer matches its TOFU pin is the one event
// TOFU exists to announce. The server withholds the key material, so the check
// cannot run — and rendering that as the generic "could not be checked" made a
// changed key indistinguishable from an unknown correspondent.
describe("a TOFU pin conflict is its own state", () => {
  it("outranks the generic unchecked state", () => {
    const local = view({ signed: true, verified: false, signerFingerprint: "", signerConflict: true });
    expect(signatureState(email({ pgpSigned: true }), local, false)).toBe("conflicted");
  });

  it("does not fire when the check simply had no bound key", () => {
    const local = view({ signed: true, verified: false, signerFingerprint: "", signerConflict: false });
    expect(signatureState(email({ pgpSigned: true }), local, false)).toBe("unchecked");
  });

  it("never overrides a successful verification", () => {
    const local = view({ signed: true, verified: true, signerFingerprint: "ABC", signerConflict: true });
    expect(signatureState(email({ pgpSigned: true }), local, false)).toBe("verified");
  });
});
