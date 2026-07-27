import { describe, expect, it } from "vitest";
import { processEmailHtml, sanitizeEmailHtml } from "./emailHtml";

// This is the function standing between a hostile email and the user's
// session. It had a careful doc comment explaining why it matters and zero
// assertions proving it works; these are those assertions.

describe("sanitizeEmailHtml", () => {
  it.each([
    ["inline script", "<script>alert(1)</script>", "alert"],
    ["img error handler", '<img src=x onerror="alert(1)">', "onerror"],
    ["javascript: href", '<a href="javascript:alert(1)">x</a>', "javascript:"],
    ["iframe", '<iframe src="https://evil.example"></iframe>', "<iframe"],
    ["object embed", '<object data="https://evil.example"></object>', "<object"],
    ["form action", '<form action="https://evil.example"><input name=a></form>', "<form"],
    ["svg onload", '<svg onload="alert(1)"></svg>', "onload"],
    ["body onload", '<body onload="alert(1)">hi</body>', "onload"],
    ["meta refresh", '<meta http-equiv="refresh" content="0;url=https://evil.example">', "<meta"],
    ["base tag", '<base href="https://evil.example/">', "<base"],
  ])("strips %s", (_label, input, forbidden) => {
    expect(sanitizeEmailHtml(input).toLowerCase()).not.toContain(forbidden.toLowerCase());
  });

  it("keeps ordinary formatting intact", () => {
    const out = sanitizeEmailHtml("<p>Hello <b>there</b> — <a href='https://ok.example'>link</a></p>");
    expect(out).toContain("<b>there</b>");
    expect(out).toContain("https://ok.example");
  });

  // blockRemoteContent is what the "Show Images" toggle actually relies on.
  // Every one of these fetches a remote URL eagerly on render, so treating
  // <img> as the only remote-content vector silently defeats the toggle and
  // its anti-tracking-pixel intent.
  describe("blockRemoteContent", () => {
    it.each([
      ["style element", "<style>p{background:url(https://tracker.example/a)}</style>", "tracker.example"],
      ["inline style background", '<p style="background-image:url(https://tracker.example/b)">x</p>', "tracker.example"],
      ["legacy background attribute", '<table background="https://tracker.example/c"><tr><td>x</td></tr></table>', "tracker.example"],
      ["svg image href", '<svg><image href="https://tracker.example/d"/></svg>', "tracker.example"],
      ["video poster", '<video poster="https://tracker.example/e"></video>', "tracker.example"],
      ["audio src", '<audio src="https://tracker.example/f"></audio>', "tracker.example"],
    ])("blocks %s", (_label, input, forbidden) => {
      expect(sanitizeEmailHtml(input, true)).not.toContain(forbidden);
    });

    it("permits the same remote content when images are allowed", () => {
      const out = sanitizeEmailHtml('<p style="background-image:url(https://cdn.example/x)">x</p>', false);
      expect(out).toContain("cdn.example");
    });
  });
});

describe("processEmailHtml", () => {
  it("replaces images with a placeholder when images are blocked", () => {
    const out = processEmailHtml('<p><img src="https://tracker.example/pixel.gif"></p>', false);
    expect(out).toContain("[Image Blocked]");
    expect(out).not.toContain("tracker.example");
  });

  it("keeps images when the user has opted in", () => {
    const out = processEmailHtml('<p><img src="https://cdn.example/photo.png"></p>', true);
    expect(out).toContain("cdn.example");
  });

  it("forces external links to open safely", () => {
    const out = processEmailHtml('<a href="https://ok.example">x</a>', true);
    expect(out).toContain('target="_blank"');
    expect(out).toContain("noopener");
  });

  it("unwraps a full HTML document to its body", () => {
    const out = processEmailHtml("<html><head><title>t</title></head><body><p>hi</p></body></html>", true);
    expect(out).toContain("<p>hi</p>");
    expect(out).not.toContain("<title>");
  });

  // Scripts must not survive the DOMParser round-trip processEmailHtml does
  // before sanitizing — the sanitize call has to be the last step.
  it("still strips script after its own DOM rewriting", () => {
    const out = processEmailHtml('<div><script>alert(1)</script><a href="https://ok.example">x</a></div>', true);
    expect(out).not.toContain("alert");
  });
});

// Every client registers itself as the system handler for kypost://, so an
// <a href="kypost://native-pair?srv=https://evil.example&pt=..."> in a message
// body is a request to hand the user's device to an attacker's server. This app
// deliberately navigates to kypost:// itself (NotificationsPage's "Pair Desktop
// App"), which is exactly why the allowlist is pinned here rather than left to
// DOMPurify's default: a dependency bump that widened that default would
// silently reopen a pairing-phishing hole.
describe("dangerous URI schemes in links", () => {
  it.each([
    ["the app's own pairing scheme", "kypost://native-pair?sub=x&srv=https://evil.example&pt=y"],
    ["the app's own scheme, uppercased", "KYPOST://native-pair?sub=x"],
    ["javascript", "javascript:alert(1)"],
    ["data html", "data:text/html,<script>alert(1)</script>"],
    ["file", "file:///etc/passwd"],
    ["android intent", "intent://scan/#Intent;scheme=zxing;end"],
    ["smb share", "smb://server/share"],
  ])("refuses %s", (_label, href) => {
    const out = processEmailHtml(`<p>Hi</p><a href="${href}">Confirm your account</a>`, true);
    // No live link survives at all: no anchor element, and no href attribute
    // for a browser to act on. The scheme may still appear inside the
    // user-facing "[Blocked link: ...]" marker, which is the point of it.
    expect(out).not.toContain("<a");
    expect(out).not.toContain("href");
    // The ordinary content around it is untouched.
    expect(out).toContain("<p>Hi</p>");
  });

  // A stripped href leaves a styled, clickable-looking anchor that silently
  // does nothing -- the failure mode Android rejected in favour of a toast.
  // Say so instead.
  it("tells the user a link was blocked rather than silently dropping it", () => {
    const out = processEmailHtml('<a href="kypost://native-pair?sub=x">Confirm your account</a>', true);
    expect(out).toContain("Blocked link");
    expect(out).toContain("kypost:");
    expect(out).not.toContain("<a");
  });

  it("leaves ordinary link schemes working", () => {
    const out = processEmailHtml(
      '<a href="https://ok.example/a">web</a><a href="mailto:a@b.example">mail</a><a href="tel:+15551234">call</a>',
      true,
    );
    expect(out).toContain("https://ok.example/a");
    expect(out).toContain("mailto:a@b.example");
    expect(out).toContain("tel:+15551234");
    expect(out).toContain('target="_blank"');
    expect(out).toContain("noopener");
    expect(out).not.toContain("Blocked link");
  });

  // Regression guard for the pinned regexp: relative URLs, fragments and cid:
  // (inline image references) must keep working, or ordinary mail breaks.
  it.each([
    ["a relative path", "/inbox/42"],
    ["a bare fragment", "#section-2"],
    ["a protocol-relative url", "//ok.example/a"],
  ])("keeps %s intact", (_label, href) => {
    const out = processEmailHtml(`<a href="${href}">x</a>`, true);
    expect(out).toContain(href);
    expect(out).not.toContain("Blocked link");
  });

  it("keeps cid: inline image references when images are shown", () => {
    const out = processEmailHtml('<img src="cid:logo@example">', true);
    expect(out).toContain("cid:logo@example");
  });
});

// Regression: the four quoting/printing call sites in ReadPage.tsx used to call
// sanitizeEmailHtml(body) with one argument and get the permissive branch, so a
// message whose images the user had deliberately NOT unblocked fired every
// tracking pixel the moment they pressed Reply. The default must fail closed.
describe("remote-content default", () => {
  it.each([
    ["inline style background", '<p style="background-image:url(https://tracker.example/b)">x</p>'],
    ["style element", "<style>p{background:url(https://tracker.example/a)}</style>"],
    ["legacy background attribute", '<table background="https://tracker.example/c"><tr><td>x</td></tr></table>'],
    ["video poster", '<video poster="https://tracker.example/e"></video>']
  ])("blocks %s when blockRemoteContent is omitted", (_label, input) => {
    expect(sanitizeEmailHtml(input)).not.toContain("tracker.example");
  });
});

// Regression for the pre-check/DOMPurify disagreement: processEmailHtml tested
// the raw href while DOMPurify strips \x00-\x20 first, so an obfuscated scheme
// slipped past the "[Blocked link]" replacement and then had its href stripped
// — leaving a dead anchor that still looked like a live link.
describe("obfuscated scheme handling", () => {
  it.each([
    ["embedded newline", "java\nscript:alert(1)"],
    ["embedded tab", "java\tscript:alert(1)"],
    ["leading control chars", "\x01javascript:alert(1)"],
    ["obfuscated kypost deep link", "kypost\n://native-pair?srv=https://evil.example"]
  ])("replaces an anchor with %s with a visible marker", (_label, href) => {
    const out = processEmailHtml(`<a href="${href}">Confirm your account</a>`, true);
    expect(out).toContain("[Blocked link:");
    expect(out).not.toContain("<a");
    expect(out.toLowerCase()).not.toContain("alert(1)");
  });

  it("names the refused scheme after normalizing it", () => {
    const out = processEmailHtml('<a href="java\nscript:alert(1)">x</a>', true);
    expect(out).toContain("[Blocked link: javascript:]");
  });

  it("still allows ordinary links with surrounding whitespace", () => {
    const out = processEmailHtml('<a href="  https://ok.example  ">x</a>', true);
    expect(out).toContain("ok.example");
    expect(out).toContain("<a");
  });
});

// run-4 finding LOW-1: isAllowedUri strips only [\x00-\x20] before testing,
// while DOMPurify's ATTR_WHITESPACE also strips U+00A0, U+1680, U+180E,
// U+2000-U+200A, U+2028, U+2029, U+202F, U+205F and U+3000. The two therefore
// disagree: this pre-check judges "java<U+00A0>script:" allowed and skips the
// [Blocked link] marker, then DOMPurify normalizes it to "javascript:",
// refuses it, and strips the href — producing exactly the dead-but-clickable-
// looking anchor the marker exists to prevent.
describe("isAllowedUri whitespace normalization matches DOMPurify", () => {
  const separators: Array<[string, string]> = [
    ["U+00A0", " "],
    ["U+1680", " "],
    ["U+2000", " "],
    ["U+2028", " "],
    ["U+2029", " "],
    ["U+202F", " "],
    ["U+205F", " "],
    ["U+3000", "　"],
  ];

  for (const [name, ch] of separators) {
    it(`marks a javascript: URL split by ${name} as blocked`, () => {
      const html = `<a href="java${ch}script:alert(1)">Confirm your account</a>`;
      const out = processEmailHtml(html, false);
      expect(out).toContain("[Blocked link:");
    });
  }
});
