import { describe, expect, it } from "vitest";
import { buildReplyBody, buildForwardBody, buildReplyAllRecipients, ensureSubjectPrefix, escapeHtml } from "./compose";
import type { InboxEmail } from "./types";

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
