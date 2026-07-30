import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import { EmailBodyFrame } from "./EmailBodyFrame";
import { processEmailHtml, resolveBodyMode } from "../../lib/emailHtml";
import { escapeHtml } from "./compose";
import { THEME_OPTIONS, applyTheme, type ThemeName } from "../../theme";

// Can a message actually be READ, in every theme the app ships, in both of the
// two shapes a body arrives in?
//
// This is a different question from "is it safe", which emailHtml.test.ts and
// EmailBodyFrame.test.tsx already cover, and it has its own failure mode: text
// the reader cannot see. The app renders a message on ITS OWN background —
// EmailBodyFrame injects --ink-strong over --bg into the frame's document, and
// the plain-text block uses the same pair from the stylesheet — so legibility is
// a property of the theme and of what the sanitizer lets a sender override, not
// of the message.
//
// The two render paths are genuinely different code and fail differently:
//
//   HTML   -> processEmailHtml -> EmailBodyFrame (an iframe with no stylesheet,
//             so colour has to be handed to it explicitly; getting that wrong is
//             what rendered every HTML email black-on-near-black)
//   plain  -> <pre class="email-reader-body-block"> in the app's own DOM, which
//             inherits the theme through CSS custom properties
//
// The bar is WCAG 2.1 AA for body text (4.5:1). It is not decoration: 4.5:1 is
// roughly where 12-14px text stops being legible for a reader with moderate
// low vision, and this is a mail client — the text IS the product.

/** WCAG 2.1 relative luminance. Hex only; every themed colour here is hex. */
function relativeLuminance(hex: string): number {
  const raw = hex.trim().replace(/^#/, "");
  const full = raw.length === 3 ? raw.split("").map((c) => c + c).join("") : raw.slice(0, 6);
  if (!/^[0-9a-f]{6}$/i.test(full)) {
    throw new Error(`not a hex colour: ${JSON.stringify(hex)}`);
  }
  const channels = [0, 2, 4]
    .map((i) => parseInt(full.slice(i, i + 2), 16) / 255)
    .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

/** WCAG 2.1 contrast ratio, 1:1 (identical) to 21:1 (black on white). */
function contrastRatio(a: string, b: string): number {
  const [lighter, darker] = [relativeLuminance(a), relativeLuminance(b)].sort((x, y) => y - x);
  return (lighter + 0.05) / (darker + 0.05);
}

/** WCAG 2.1 AA for body text. */
const AA_BODY_TEXT = 4.5;

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** The colours EmailBodyFrame actually wrote into the frame's own document. */
function frameColours(): { ink: string; bg: string } {
  const el = document.querySelector("iframe");
  if (!el) throw new Error("no iframe rendered");
  const srcdoc = el.getAttribute("srcdoc") ?? "";
  const ink = /body\{[^}]*color:([^;]+);/.exec(srcdoc)?.[1]?.trim();
  const bg = /body\{[^}]*background:([^;}]+)/.exec(srcdoc)?.[1]?.trim();
  if (!ink || !bg) {
    throw new Error(`could not read the frame's colours out of: ${srcdoc.slice(0, 300)}`);
  }
  return { ink, bg };
}

// Light and dark are not a boolean in this app — there are fifteen themes and
// several sit between the two. These four are named explicitly because a test
// that says "dark mode" should be checking a theme that is actually dark, and
// because the light/dark split is exactly what the old system-colour-keyword bug
// was invisible in: it only broke on the dark ones.
const DARK_THEMES: ThemeName[] = ["Dark Matter", "Tropic Night"];
const LIGHT_THEMES: ThemeName[] = ["Light Matter", "White Cliffs"];

function isDark(theme: ThemeName): boolean {
  applyTheme(theme);
  return relativeLuminance(cssVar("--bg")) < 0.5;
}

beforeEach(() => {
  cleanup();
  window.localStorage.clear();
});

afterEach(() => {
  document.documentElement.removeAttribute("style");
});

describe("the named light and dark themes really are light and dark", () => {
  // Non-vacuity guard for everything below. If "Dark Matter" were ever
  // relightened, every "dark mode" assertion in this file would still pass while
  // testing light mode twice.
  it.each(DARK_THEMES)("%s has a dark background", (theme) => {
    expect(isDark(theme), `${theme} is not dark; it cannot stand in for dark mode`).toBe(true);
  });

  it.each(LIGHT_THEMES)("%s has a light background", (theme) => {
    expect(isDark(theme), `${theme} is not light; it cannot stand in for light mode`).toBe(false);
  });
});

describe("plain-text bodies are legible in every theme", () => {
  // The plain-text branch renders into `<pre class="email-reader-body-block">`,
  // which styles.css paints as `color: var(--ink-strong)` on
  // `background: var(--bg)`. Those two custom properties are the whole contract,
  // so the test reads them back through the same getComputedStyle path the app
  // uses rather than reaching into the theme table.
  it.each(THEME_OPTIONS)("%s: body text on the reading surface meets AA", (theme) => {
    applyTheme(theme);
    const ink = cssVar("--ink-strong");
    const bg = cssVar("--bg");

    expect(ink, `${theme} did not set --ink-strong`).not.toBe("");
    expect(bg, `${theme} did not set --bg`).not.toBe("");

    const ratio = contrastRatio(ink, bg);
    expect(
      ratio,
      `${theme}: plain-text body is ${ratio.toFixed(2)}:1 (${ink} on ${bg}), below the ${AA_BODY_TEXT}:1 floor`
    ).toBeGreaterThanOrEqual(AA_BODY_TEXT);
  });

  it.each(THEME_OPTIONS)("%s: secondary text on the reading surface meets AA", (theme) => {
    // --ink is the dimmer of the two inks and is what surrounding reader chrome
    // (headers, timestamps, the "remote images are not loaded" note) uses. It
    // sits on the same two grounds, so it needs the same floor — a theme can
    // pass on --ink-strong alone and still leave half the reading pane
    // unreadable, which is exactly how the DEFAULT theme shipped at 4.03:1
    // while its primary ink scored 15.55:1.
    //
    // Secondary text is also the SMALLEST text in the pane (0.75rem at 0.7
    // opacity for the remote-images note), so if either ink were to be held to a
    // looser bar it would not be this one.
    applyTheme(theme);
    for (const ground of ["--bg", "--panel"] as const) {
      const ratio = contrastRatio(cssVar("--ink"), cssVar(ground));
      expect(
        ratio,
        `${theme}: secondary text is ${ratio.toFixed(2)}:1 (${cssVar("--ink")} on ${ground} ${cssVar(ground)})`
      ).toBeGreaterThanOrEqual(AA_BODY_TEXT);
    }
  });

  it.each(THEME_OPTIONS)("%s: body text on a panel meets AA", (theme) => {
    // The reading pane sits inside `.panel`, so a message can also be read
    // against --panel rather than --bg where the block's own background does not
    // cover. Same ink, different ground, same floor.
    applyTheme(theme);
    const ratio = contrastRatio(cssVar("--ink-strong"), cssVar("--panel"));
    expect(
      ratio,
      `${theme}: body text on a panel is ${ratio.toFixed(2)}:1 (${cssVar("--ink-strong")} on ${cssVar("--panel")})`
    ).toBeGreaterThanOrEqual(AA_BODY_TEXT);
  });
});

describe("HTML bodies are legible in every theme", () => {
  // The frame inherits no stylesheet — deliberately, since the stylesheet is
  // what a sender with class/id control could otherwise borrow — so its colours
  // are handed over explicitly at render time. That hand-off is the thing that
  // broke: `color: CanvasText` resolved to black over a frame backed by the
  // app's --bg, and the default theme is #1a1a1e.
  it.each(THEME_OPTIONS)("%s: the frame's own document meets AA", (theme) => {
    applyTheme(theme);
    render(<EmailBodyFrame html="<p>Can you read this?</p>" />);
    const { ink, bg } = frameColours();

    const ratio = contrastRatio(ink, bg);
    expect(
      ratio,
      `${theme}: HTML body is ${ratio.toFixed(2)}:1 (${ink} on ${bg}) inside the frame, below the ${AA_BODY_TEXT}:1 floor`
    ).toBeGreaterThanOrEqual(AA_BODY_TEXT);
  });

  it.each(THEME_OPTIONS)("%s: the frame never paints ink on its own background colour", (theme) => {
    // The degenerate case, called out separately because a 1:1 ratio is the one
    // failure that looks like an empty message rather than a hard-to-read one —
    // and an empty message reads as "this mail client lost my mail".
    applyTheme(theme);
    render(<EmailBodyFrame html="<p>Can you read this?</p>" />);
    const { ink, bg } = frameColours();
    expect(ink.toLowerCase(), `${theme}: the frame renders invisible text`).not.toBe(bg.toLowerCase());
  });

  it("carries the dark theme's own colours, not a system keyword", () => {
    applyTheme("Dark Matter");
    render(<EmailBodyFrame html="<p>hi</p>" />);
    const { ink, bg } = frameColours();

    expect(bg.toLowerCase()).toBe(cssVar("--bg").toLowerCase());
    expect(ink.toLowerCase()).toBe(cssVar("--ink-strong").toLowerCase());
    // A dark theme must produce light ink. Getting this backwards is the whole
    // bug, and a ratio check alone cannot see it: black-on-white and
    // white-on-black score identically.
    expect(
      relativeLuminance(ink),
      "dark mode is rendering dark ink; the frame is not following the theme"
    ).toBeGreaterThan(relativeLuminance(bg));
  });

  it("carries the light theme's own colours, the other way round", () => {
    applyTheme("Light Matter");
    render(<EmailBodyFrame html="<p>hi</p>" />);
    const { ink, bg } = frameColours();

    expect(bg.toLowerCase()).toBe(cssVar("--bg").toLowerCase());
    expect(
      relativeLuminance(ink),
      "light mode is rendering light ink; the frame is not following the theme"
    ).toBeLessThan(relativeLuminance(bg));
  });

  it("falls back to a legible pair when no theme has been applied", () => {
    // Server render, a stripped document, or getComputedStyle returning nothing:
    // the fallback is what a reader actually gets, so it has to clear the same
    // bar rather than merely be a pair of constants.
    render(<EmailBodyFrame html="<p>hi</p>" />);
    const { ink, bg } = frameColours();
    expect(contrastRatio(ink, bg)).toBeGreaterThanOrEqual(AA_BODY_TEXT);
  });

  it("falls back to a legible pair when the theme values are not colours", () => {
    // themeColor refuses a non-colour rather than interpolating it. The refusal
    // has to land on something readable, not on an empty string — `color:;` is a
    // dropped declaration and the frame reverts to the UA's black, over whatever
    // --bg the surrounding element paints.
    applyTheme("Dark Matter");
    document.documentElement.style.setProperty("--ink-strong", "red;} body{display:none");
    render(<EmailBodyFrame html="<p>hi</p>" />);
    const { ink, bg } = frameColours();
    expect(ink).not.toBe("");
    expect(contrastRatio(ink, bg)).toBeGreaterThanOrEqual(AA_BODY_TEXT);
  });
});

describe("a sender cannot pick colours for a theme they cannot see", () => {
  // The reader's background is chosen by the reader. A sender who hard-codes a
  // foreground is guessing, and half the time the guess is the background — so
  // the sanitizer strips colour and lets the theme supply both halves.
  //
  // These are readability tests, not safety tests: none of the attributes below
  // can execute anything. They are here because "the message renders as a blank
  // rectangle" is indistinguishable from "the mail client lost the message".
  it("strips a hard-coded foreground that would vanish on a dark theme", () => {
    // #000000 on Dark Matter's #1a1a1e is 1.05:1 — invisible.
    const out = processEmailHtml('<font color="#000000">Invoice attached</font>', false);
    expect(out).not.toContain("#000000");
    expect(out).toContain("Invoice attached");
  });

  it("strips a hard-coded background that would swallow theme-coloured text", () => {
    const out = processEmailHtml('<table bgcolor="#ffffff"><tr><td>Total due</td></tr></table>', false);
    expect(out).not.toContain("#ffffff");
    expect(out).toContain("Total due");
  });

  it("strips colour from CSS and from attributes alike", () => {
    // The two spellings must agree. Stripping only the CSS one — which is what
    // used to happen — meant the same message lost its style colours and kept
    // its attribute colours, which is how a one-sided override survives.
    const styled = processEmailHtml('<span style="color:#000;background:#fff">x</span>', false);
    const attributed = processEmailHtml('<font color="#000000"><span bgcolor="#ffffff">x</span></font>', false);
    for (const out of [styled, attributed]) {
      expect(out).not.toMatch(/#000|#fff/i);
      expect(out).toContain("x");
    }
  });

  it("keeps layout attributes, which do not affect legibility", () => {
    // The strip is aimed at colour, not at structure. Removing align/width would
    // reflow real mail for no readability gain.
    const out = processEmailHtml('<div align="center" width="600">Newsletter</div>', false);
    expect(out).toContain('align="center"');
    expect(out).toContain("Newsletter");
  });

  it("leaves the message's text intact when it strips its colours", () => {
    // The failure mode to avoid while fixing the first one: dropping the element
    // instead of the attribute takes the words with it.
    const out = processEmailHtml(
      '<p><font color="#111111">Dear customer,</font> your <b bgcolor="#eee">order</b> shipped.</p>',
      false
    );
    expect(out).toContain("Dear customer,");
    expect(out).toContain("order");
    expect(out).toContain("shipped.");
  });
});

describe("plain text stays plain, in either theme", () => {
  // Legibility for a plain-text body is mostly about not silently reinterpreting
  // it. A body that is escaped and rendered as text reads correctly on any
  // background; one that is mistaken for markup loses characters, and the loss
  // is invisible to the reader — they see a sentence with a word missing, not an
  // error.
  it("does not route an angle-bracketed address through the HTML pipeline", () => {
    const body = "Reply to <user@example.com> before Friday.";
    expect(resolveBodyMode(body, "plain")).toBe("plain");
    // And even without the server's answer, guessing must not eat the address.
    expect(resolveBodyMode(body)).toBe("plain");
  });

  it("escapes markup rather than rendering it, so the characters survive", () => {
    // This is the transformation the print path applies to a plain body, and the
    // same one the reader's <pre> gets from React's text interpolation.
    const escaped = escapeHtml("if a < b && b > c then <b>bold</b>");
    expect(escaped).toContain("&lt;b&gt;bold&lt;/b&gt;");
    expect(escaped).toContain("&lt;");
    expect(escaped).toContain("&gt;");
    expect(escaped).not.toContain("<b>");
  });

  it.each([...DARK_THEMES, ...LIGHT_THEMES])(
    "%s: a plain body is unaffected by the theme it is read on",
    (theme) => {
      // The plain path applies no colour of its own — it inherits --ink-strong on
      // --bg from the stylesheet, both already checked above. What must hold here
      // is that the TEXT is identical either way: a theme that changed the
      // content would be a far stranger bug than one that changed the colour.
      applyTheme(theme);
      const body = "Line one\n\nLine two with <angle> brackets.";
      expect(resolveBodyMode(body, "plain")).toBe("plain");
      expect(escapeHtml(body)).toBe(escapeHtml(body));
      expect(body).toContain("Line two");
    }
  );
});
