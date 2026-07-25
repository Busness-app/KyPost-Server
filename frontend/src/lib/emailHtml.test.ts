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
