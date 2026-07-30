import { describe, expect, it } from "vitest";
import { processEmailHtml, resolveBodyMode, sanitizeEmailHtml } from "./emailHtml";

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

    it("permits remote content when images are allowed", () => {
      const out = sanitizeEmailHtml('<table background="https://cdn.example/x"><tr><td>y</td></tr></table>', false);
      expect(out).toContain("cdn.example");
    });
  });

  // run-4 finding M6: CSS was coupled to the remote-content toggle, but they
  // are different concerns. Pressing "Show Remote Content" — which a user does
  // to see a newsletter's pictures — also handed the sender document-wide CSS
  // on the app's own origin, because the permissive branch dropped both the
  // style attribute and the <style> element from its FORBID lists and the CSP
  // allows style-src 'unsafe-inline'.
  //
  // Email CSS is not scoped to the message container, so the sender could
  // hide the "This message impersonates KyPost" banner with
  // .notice-error{display:none!important}, repaint the PGP badge from red to a
  // green "verified", or cover the whole viewport with a fixed-position
  // body::after overlay. None of that requires script, so nothing else in the
  // pipeline stops it. Roundcube prefixes email CSS selectors for exactly this
  // reason.
  //
  // Unblocking images must therefore never unblock CSS. The remote-content
  // entries (background attribute, svg/video/audio) stay coupled to the
  // toggle — those really are about fetching remote URLs.
  describe("sender CSS is forbidden regardless of the remote-content toggle", () => {
    it.each([[true], [false]])("strips the style attribute (blockRemoteContent=%s)", (block) => {
      const out = sanitizeEmailHtml('<p style="display:none">x</p>', block);
      expect(out).not.toContain("display:none");
      expect(out).not.toContain("style=");
    });

    it.each([[true], [false]])("strips <style> elements (blockRemoteContent=%s)", (block) => {
      // A leading <style> is hoisted into <head> and dropped anyway; the
      // payload needs a preceding element to survive, which is how it was
      // reproduced.
      const out = sanitizeEmailHtml("<p>x</p><style>.notice-error{display:none!important}</style>", block);
      expect(out).not.toContain("notice-error");
      expect(out).not.toContain("<style");
    });

    it("does not let an unblocked message hide the impersonation banner", () => {
      const out = sanitizeEmailHtml(
        '<p>hi</p><style>.notice-error,.security-badge-off{display:none!important}</style>' +
          '<div style="position:fixed;inset:0;background:#fff">overlay</div>',
        false
      );
      expect(out).not.toContain("display:none");
      expect(out).not.toContain("position:fixed");
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

describe("run-5 audit regressions", () => {
  it("strips class, id and open so mail cannot borrow the app stylesheet", () => {
    // The stylesheet is global: five rules are position:fixed inset:0 at
    // z-index up to 2600, guarded by :not([open]). A sender naming them gets a
    // full-viewport, click-intercepting overlay with no script and no remote
    // content.
    const out = processEmailHtml(
      '<div class="rules-help-backdrop" id="x" open><span class="security-badge security-badge-on">PGP signature verified</span></div>',
      false,
    );
    expect(out).not.toContain("rules-help-backdrop");
    expect(out).not.toContain("security-badge");
    expect(out).not.toContain("class=");
    expect(out).not.toContain(" id=");
    expect(out).not.toContain("open");
  });

  it("blocks schemes containing a digit", () => {
    // RFC 3986 allows digits after the first character of a scheme. The old
    // character class omitted them, so these read as "no scheme at all" and
    // fell through to the relative-URL allowance.
    for (const uri of ["ts3server://evil.example?password=x", "h323:evil", "sip2:x", "s3://x"]) {
      const out = processEmailHtml(`<a href="${uri}">click</a>`, false);
      expect(out).not.toContain(uri);
    }
  });

  it("still allows the schemes ordinary mail needs", () => {
    for (const uri of ["https://example.com/x", "mailto:a@b.c", "tel:+15551234", "/relative", "#frag"]) {
      const out = processEmailHtml(`<a href="${uri}">click</a>`, false);
      expect(out).toContain(uri);
    }
  });
});

// The pipeline AROUND the sanitizer, which is where the message actually got
// eaten. Every case below was reproduced against the previous implementation.
describe("processEmailHtml does not lose message content", () => {
  it("keeps everything after a stray closing div", () => {
    // The old code wrapped content in a <div> and returned that element's
    // innerHTML. The parser closed the wrapper here, so the rest of the
    // message became a sibling and was dropped — silently truncating any mail
    // with unbalanced div nesting, which marketing templates produce routinely.
    const out = processEmailHtml("<p>First half</p></div><p>Second half</p>", false);
    expect(out).toContain("First half");
    expect(out).toContain("Second half");
  });

  it("hardens links that follow a stray closing div", () => {
    // Same root cause, worse consequence: an anchor outside the wrapper never
    // reached the rel/target pass, and a disallowed scheme there never got its
    // [Blocked link] marker.
    const out = processEmailHtml('<p>hi</p></div><a href="https://ok.example">click</a>', false);
    expect(out).toContain("https://ok.example");
    expect(out).toContain('rel="noopener noreferrer"');
  });

  it("blocks a disallowed scheme that follows a stray closing div", () => {
    const out = processEmailHtml('<p>hi</p></div><a href="kypost://native-pair?srv=x">click</a>', false);
    expect(out).not.toContain("kypost://");
    expect(out).toContain("[Blocked link: kypost:]");
  });

  it("is not re-cut by a </body> inside an attribute", () => {
    // The old <body>...</body> regex could pick the wrong closing tag.
    const out = processEmailHtml('<body><p title="&lt;/body&gt;">Kept</p><p>Also kept</p></body>', false);
    expect(out).toContain("Kept");
    expect(out).toContain("Also kept");
  });

  it("extracts the body of a full HTML document", () => {
    const out = processEmailHtml("<html><head><title>t</title></head><body><p>Body text</p></body></html>", false);
    expect(out).toContain("Body text");
    expect(out).not.toContain("<title>");
  });
});

describe("resolveBodyMode", () => {
  it("trusts the server's answer over the shape of the bytes", () => {
    // The whole point. This body is plain text that happens to contain an
    // angle-bracketed address; the server said so, and that has to win.
    expect(resolveBodyMode("Contact <admin@example.com> today", "plain")).toBe("plain");
    // And markup the server called markup stays markup even if the fallback
    // heuristic would have been unsure.
    expect(resolveBodyMode("plain looking", "html")).toBe("html");
  });

  it("does not treat an angle-bracketed address as markup when it must guess", () => {
    // Regression: /<[^>]+>/ matched "<admin@example.com>", so a plain-text
    // body went through the markup pipeline, the parser read the address as an
    // unknown element, and it was deleted from the message with no marker.
    const body = "Please contact <admin@example.com> about the invoice.";
    expect(resolveBodyMode(body, undefined)).toBe("plain");
    // Prove the consequence the old path had, so nobody reintroduces it.
    expect(processEmailHtml(body, false)).not.toContain("admin@example.com");
  });

  it("does not treat comparison operators as markup when it must guess", () => {
    expect(resolveBodyMode("ship it if a < b and b > c", undefined)).toBe("plain");
  });

  it("still recognizes real markup when it must guess", () => {
    for (const body of ["<p>hi</p>", "<DIV>hi</DIV>", '<a href="https://x">x</a>', "<br>", "<table><tr><td>x"]) {
      expect(resolveBodyMode(body, undefined)).toBe("html");
    }
  });

  // The tag allowlist that replaced /<[^>]+>/ traded one set of false answers
  // for another. Both sets are pinned here so neither can come back.
  it("recognizes markup outside any hand-written tag list", () => {
    // Every one of these was classified "plain" by the 34-tag allowlist, so a
    // real HTML message rendered as escaped source.
    for (const body of [
      "<center>Hello</center>",
      "<dl><dt>term</dt><dd>definition</dd></dl>",
      "<code>x = 1</code>",
      "<small>fine print</small>",
      "<figure><figcaption>caption</figcaption></figure>",
      "<article>story</article>",
      "<sub>2</sub> and <sup>3</sup>",
      "<section><header>hi</header></section>"
    ]) {
      expect(resolveBodyMode(body, undefined), `expected html for ${body}`).toBe("html");
    }
  });

  // The residual ambiguity, pinned deliberately rather than left to be
  // rediscovered. Prose mentioning a real tag cannot be told from markup
  // without a Content-Type, so this errs toward "html" — and the point of the
  // test is that erring that way is CHEAP: a known element renders as itself
  // and the words around it survive.
  it("errs toward markup for prose mentioning a real tag, without eating the words", () => {
    const body = "Use <br> to break a line in HTML.";
    expect(resolveBodyMode(body, undefined)).toBe("html");
    const out = processEmailHtml(body, false);
    expect(out).toContain("Use");
    expect(out).toContain("to break a line in HTML.");
  });

  // The expensive direction, which must never happen: an UNKNOWN element
  // swallows its content, so misreading these deletes text outright.
  it("never routes an unknown-element body through the markup pipeline", () => {
    for (const body of [
      "Please contact <admin@example.com> about the invoice.",
      "ship it if a < b and b > c",
      "the tag <o:p> is Word-specific"
    ]) {
      expect(resolveBodyMode(body, undefined), `expected plain for ${body}`).toBe("plain");
    }
  });

  it("handles an empty or bracket-free body without calling it markup", () => {
    expect(resolveBodyMode("", undefined)).toBe("plain");
    expect(resolveBodyMode("just some ordinary text", undefined)).toBe("plain");
  });
});
