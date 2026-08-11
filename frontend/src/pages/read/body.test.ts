import { describe, it, expect } from "vitest";

import { displayBody } from "./body";
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
    ...over
  };
}

describe("displayBody", () => {
  it("prefers a locally decrypted body over the server's", () => {
    const local = view({ body: "plaintext", bodyMode: "plain", bodyFromVerifiedPart: true });
    expect(displayBody(email({ body: "envelope" }), local).body).toBe("plaintext");
  });

  it("falls back to the server's body when there is no local view", () => {
    expect(displayBody(email({ body: "server copy" })).body).toBe("server copy");
  });

  // The forgery this guards. A signed part that parses to nothing must not
  // borrow the server's render: that render covers the WHOLE message,
  // including parts the signature never touched, and it would appear under a
  // green "signature verified" badge.
  it("renders nothing rather than the server's copy when the VERIFIED part is empty", () => {
    const local = view({ body: "", bodyFromVerifiedPart: true, signed: true, verified: true });
    expect(displayBody(email({ body: "<p>attacker text</p>" }), local).body).toBe("");
  });

  // The deliberate failure path: the verify effect stores an empty body with an
  // empty error so the reader does not lose the message when the payload fetch
  // fails. That must still fall through.
  it("falls back to the server's copy when verification never produced a body", () => {
    const local = view({ body: "", bodyFromVerifiedPart: false, signed: true, verified: false });
    expect(displayBody(email({ body: "server copy" }), local).body).toBe("server copy");
  });

  it("falls back when the local view carries an error", () => {
    const local = view({ body: "stale", bodyFromVerifiedPart: true, error: "could not decrypt" });
    expect(displayBody(email({ body: "server copy" }), local).body).toBe("server copy");
  });

  it("keeps the verified part's own mode", () => {
    const local = view({ body: "<p>hi</p>", bodyMode: "html", bodyFromVerifiedPart: true });
    expect(displayBody(email({ body: "x", bodyMode: "plain" }), local).mode).toBe("html");
  });
});
