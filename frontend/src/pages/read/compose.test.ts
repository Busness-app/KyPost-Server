import { describe, expect, it } from "vitest";
import { buildReplyBody, buildForwardBody, buildReplyAllRecipients, ensureSubjectPrefix, escapeHtml } from "./compose";
import type { DecryptedView, InboxEmail } from "./types";

function email(over: Partial<InboxEmail> = {}): InboxEmail {
  return {
    messageId: "1",
    sender: "Alice <alice@example.com>",
    sentTo: "bob@example.com",
    cc: "",
    subject: "Hello",
    body: "hi",
    atUtc: "2026-01-01T00:00:00Z",
    ...over
  } as InboxEmail;
}

describe("quoting", () => {
  // The reason this module exists as its own file: quoting must run the same
  // blocking pipeline the read view does. A regression here fires a tracking
  // pixel the user explicitly declined, from the compose editor.
  const TRACKER = "https://tracker.example/pixel.png";

  it("strips images out of a quoted reply", () => {
    const out = buildReplyBody(email({ body: `<p>hi</p><img src="${TRACKER}">` }));
    expect(out).not.toContain(TRACKER);
    expect(out).toContain("[Image Blocked]");
  });

  it("strips images out of a quoted forward", () => {
    const out = buildForwardBody(email({ body: `<p>hi</p><img src="${TRACKER}">` }));
    expect(out).not.toContain(TRACKER);
    expect(out).toContain("[Image Blocked]");
  });

  it("escapes a plain-text body instead of letting it become markup", () => {
    const out = buildReplyBody(email({ body: "2 < 3 & 4 > 1" }));
    expect(out).toContain("2 &lt; 3 &amp; 4 &gt; 1");
  });

  it("escapes attacker-controlled headers into the quote block", () => {
    const out = buildReplyBody(email({ sender: '<img src=x onerror=alert(1)>', body: "hi" }));
    expect(out).not.toContain("<img src=x");
    expect(out).toContain("&lt;img src=x");
  });
});

describe("buildReplyAllRecipients", () => {
  it("puts the sender in To and everyone else in Cc", () => {
    const { to, cc } = buildReplyAllRecipients(
      email({ sender: "alice@example.com", sentTo: "bob@example.com", cc: "carol@example.com" })
    );
    expect(to).toBe("alice@example.com");
    expect(cc).toBe("bob@example.com, carol@example.com");
  });

  it("drops the sender and duplicates from Cc, case-insensitively", () => {
    const { cc } = buildReplyAllRecipients(
      email({ sender: "alice@example.com", sentTo: "ALICE@example.com, bob@example.com", cc: "Bob@example.com" })
    );
    expect(cc).toBe("bob@example.com");
  });
});

describe("ensureSubjectPrefix", () => {
  it("adds the prefix once and does not stack it", () => {
    expect(ensureSubjectPrefix("Hello", "Re:")).toBe("Re: Hello");
    expect(ensureSubjectPrefix("Re: Hello", "Re:")).toBe("Re: Hello");
    expect(ensureSubjectPrefix("re: Hello", "Re:")).toBe("re: Hello");
  });
});

describe("escapeHtml", () => {
  it("escapes every character that could break out of an attribute or element", () => {
    expect(escapeHtml(`<>&"'`)).toBe("&lt;&gt;&amp;&quot;&#39;");
  });
});

// Quoting a client-protected account's mail. The server sends the envelope for
// these — an armored blob or nothing — and an envelope's bodyMode says nothing
// about the plaintext inside. Reply/forward read email.bodyMode unconditionally
// and never looked at the decrypted view, so quoting an encrypted message quoted
// the ciphertext, and an HTML one was paired with the envelope's "plain".
describe("quoting a locally decrypted message", () => {
  function decryptedView(over: Partial<DecryptedView> = {}): DecryptedView {
    // bodyFromVerifiedPart defaults true here: every case in this describe is a
    // message this browser actually opened, which is what makes displayBody
    // prefer the local body over the envelope.
    return {
      body: "",
      signed: false,
      verified: false,
      signerFingerprint: "",
      error: "",
      bodyFromVerifiedPart: true,
      ...over
    };
  }

  it("quotes the decrypted body rather than the envelope", () => {
    const encrypted = email({ body: "-----BEGIN PGP MESSAGE-----\nwcBMA...\n-----END PGP MESSAGE-----", bodyMode: "plain" });
    const out = buildReplyBody(encrypted, decryptedView({ body: "the real plaintext", bodyMode: "plain" }));
    expect(out).toContain("the real plaintext");
    expect(out).not.toContain("BEGIN PGP MESSAGE");
  });

  it("uses the decrypted body's own render mode, not the envelope's", () => {
    // The envelope says "plain"; the decrypted part's Content-Type says html.
    // Taking the envelope's answer renders the markup as escaped source.
    const encrypted = email({ body: "-----BEGIN PGP MESSAGE-----", bodyMode: "plain" });
    const out = buildReplyBody(encrypted, decryptedView({ body: "<p>rich text</p>", bodyMode: "html" }));
    expect(out).toContain("<p>rich text</p>");
    expect(out).not.toContain("&lt;p&gt;");
  });

  it("still blocks remote content in a decrypted quote", () => {
    const out = buildForwardBody(
      email({ body: "-----BEGIN PGP MESSAGE-----" }),
      decryptedView({ body: `<p>hi</p><img src="https://tracker.example/pixel.png">`, bodyMode: "html" })
    );
    expect(out).not.toContain("tracker.example");
    expect(out).toContain("[Image Blocked]");
  });

  it("falls back to the server body when there is no decrypted view", () => {
    const out = buildReplyBody(email({ body: "plain server body" }), undefined);
    expect(out).toContain("plain server body");
  });

  it("ignores a decrypted view that only carries an error", () => {
    const out = buildReplyBody(email({ body: "server body" }), decryptedView({ error: "could not decrypt" }));
    expect(out).toContain("server body");
  });
});
