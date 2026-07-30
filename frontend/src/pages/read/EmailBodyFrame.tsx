// EmailBodyFrame renders a message body inside a sandboxed iframe.
//
// Sanitized email HTML used to go straight into the reader's own DOM via
// dangerouslySetInnerHTML, which made DOMPurify the only structural boundary
// between a sender and a document that also holds the non-HttpOnly csrf_token
// cookie and, for a client-protected account, an unlocked OpenPGP private key in
// module memory (lib/keyVault.ts). One sanitizer bypass reached both. The
// sandboxed iframe is a second, independent boundary that does not depend on
// getting the allowlist right.
//
// The sandbox value is load-bearing. Read this before changing it.
//
//   (absent)                     — no allow-scripts, so no script runs in this
//                                  frame. Sandbox flags are additive
//                                  permissions; omitting allow-scripts sets the
//                                  sandboxed-scripts flag and the browser
//                                  refuses inline script, <script src>, event
//                                  handler attributes and javascript: URLs
//                                  regardless of anything else here.
//   allow-same-origin            — needed only so the parent can read
//                                  contentDocument to size the frame; an
//                                  opaque-origin frame cannot be measured and
//                                  every message renders clipped to a stub.
//                                  Safe *because* allow-scripts is absent:
//                                  same-origin is dangerous in combination
//                                  with script execution, and there is none.
//   allow-popups +
//   allow-popups-to-escape-sandbox — so a link opens. Without the first,
//                                  clicking does nothing; without the second,
//                                  the opened page inherits the sandbox and
//                                  loads broken.
//
// Never add allow-scripts: with allow-same-origin present it voids the sandbox
// and hands the frame the parent's origin. If scripts are ever needed here, drop
// allow-same-origin in the same commit and size the frame another way.
// allow-forms and allow-top-navigation are absent deliberately — a
// sender-controlled form is a credential-phishing surface, and a frame that can
// navigate the top level can replace the whole app.
//
// srcdoc rather than src: the content never becomes a URL, so nothing can
// fetch, cache, or link to it. A srcdoc document also inherits the parent's
// CSP, so the app-wide policy still applies inside the frame.
export const FRAME_SANDBOX = "allow-same-origin allow-popups allow-popups-to-escape-sandbox";
import { useEffect, useRef, useState } from "react";

// Every link opens in a new top-level context. The frame has no
// allow-top-navigation, so this is the only way a link can work at all, and
// processEmailHtml has already stamped rel="noopener noreferrer" on the ones
// it kept.
//
// The referrer <meta> is here rather than on the <iframe> element: the
// element's referrerpolicy attribute governs the fetch of `src`, and a srcdoc
// frame has no src, so it did nothing. Inside the document it does apply, and
// it is what stops an unblocked tracking pixel reporting the app's URL back to
// the sender.
const FRAME_HEAD = `<meta name="referrer" content="no-referrer"><base target="_blank">`;

// The two colours the frame cannot work out for itself.
//
// The frame gets none of the app's stylesheet — that is the point, since the
// stylesheet is what a sender with class/id control could otherwise borrow — so
// anything it needs is handed over explicitly. System colour keywords are no
// help: `color: CanvasText` resolves to black over a frame backed by the app's
// `--bg`, and the default theme is #1a1a1e, so HTML email rendered black on
// near-black. A theme living in CSS custom properties is invisible to them.
//
// Read from the document element at render time so a theme switch is picked up
// on the next render, and validated before interpolation: these are our own
// values rather than sender input, but a CSS value spliced into a style block is
// a sink either way.
const CSS_COLOR = /^(#[0-9a-f]{3,8}|rgba?\([\d\s.,%/]+\)|hsla?\([\d\s.,%/deg]+\)|[a-z]+)$/i;

// Dark ink on a light ground: legible on its own, and the pair to use whenever
// the theme cannot supply one.
const FALLBACK_INK = "#111111";
const FALLBACK_BG = "#ffffff";

function themeColor(name: string): string {
  if (typeof getComputedStyle !== "function" || typeof document === "undefined") {
    return "";
  }
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return CSS_COLOR.test(value) ? value : "";
}

/**
 * The frame's foreground and background, resolved AS A PAIR.
 *
 * Falling back independently is what made this worth a function. `--ink-strong`
 * unreadable while `--bg` is fine gave the light-mode fallback ink (#111111)
 * over the theme's real dark background (#1a1a1e) — 1.09:1, black on
 * near-black. That is the identical failure the colour injection exists to
 * prevent, just reached through a partly-broken theme instead of through a
 * system colour keyword, and it is the more likely of the two: it needs only one
 * of the two custom properties to be missing, misspelled, or mid-transition.
 *
 * Contrast is a property of two colours, so neither may be chosen alone. Either
 * the theme supplies both or neither is used.
 */
function framePalette(): { ink: string; bg: string } {
  const ink = themeColor("--ink-strong");
  const bg = themeColor("--bg");
  if (!ink || !bg) {
    return { ink: FALLBACK_INK, bg: FALLBACK_BG };
  }
  return { ink, bg };
}

// Typography for the frame's own document. Colours are injected; the rest is the
// readable minimum restated, since the frame inherits nothing.
function frameStyle(ink: string, bg: string): string {
  return `
  html,body{margin:0;padding:0}
  body{font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:${ink};background:${bg};overflow-wrap:anywhere}
  img,video,table{max-width:100%}
  table{border-collapse:collapse}
  blockquote{margin:0 0 0 .8rem;padding-left:.8rem;border-left:3px solid rgba(128,128,128,.4)}
  a{color:inherit;text-decoration:underline}
`;
}

/**
 * Hard ceiling on the frame's height, in CSS pixels.
 *
 * The measured height feeds back into the frame's own containing block, so a
 * percentage-sized element inside grows the frame, which grows the element. The
 * sanitizer strips style/class/id, but DOMPurify allows the presentational
 * `height` attribute, so `<table height="150%">` is a render loop a sender can
 * post. The cap and the quantization in `measure` between them make that
 * converge instead of running away.
 */
const MAX_FRAME_HEIGHT = 20000;

/** Ignore sub-pixel jitter; only a real change is worth a re-render. */
const HEIGHT_EPSILON = 2;

type Props = {
  /** Already sanitized by processEmailHtml. This component adds isolation, not sanitization. */
  html: string;
  className?: string;
  title?: string;
};

export function EmailBodyFrame({ html, className, title = "Message body" }: Props) {
  const frameRef = useRef<HTMLIFrameElement | null>(null);
  const [height, setHeight] = useState(120);

  const { ink, bg } = framePalette();

  // The frame runs no script of its own, so it cannot post its height out.
  // The parent measures it instead, which is what allow-same-origin buys and
  // the only reason that flag is set. ResizeObserver keeps the height right as
  // images finish loading and as the column width changes; without it a
  // message grows past its frame and is silently clipped.
  useEffect(() => {
    const frame = frameRef.current;
    if (!frame) {
      return;
    }
    let observer: ResizeObserver | undefined;

    const measure = () => {
      const body = frame.contentDocument?.body;
      if (!body) {
        return;
      }
      const next = Math.min(body.scrollHeight, MAX_FRAME_HEIGHT);
      // Only commit a real change. Without this the height feeds back into the
      // layout that produced it and a message can oscillate forever.
      setHeight((prev) => (Math.abs(prev - next) < HEIGHT_EPSILON ? prev : next));
    };

    const onLoad = () => {
      // Disconnect first. This runs twice on mount — once because a fresh
      // frame's about:blank is already readyState "complete" when the effect
      // fires, and again when the srcdoc finishes parsing — so reassigning
      // `observer` without disconnecting leaks one observer and one detached
      // document per message opened.
      observer?.disconnect();
      observer = undefined;
      const body = frame.contentDocument?.body;
      if (!body) {
        return;
      }
      measure();
      if (typeof ResizeObserver !== "undefined") {
        observer = new ResizeObserver(measure);
        observer.observe(body);
      }
    };

    frame.addEventListener("load", onLoad);
    // A srcdoc frame can already be loaded by the time this effect runs. Only
    // measure a document that holds this message: about:blank is "complete"
    // too, and measuring it collapses the frame to zero height, which shows as
    // every message flashing on open.
    if (frame.contentDocument?.readyState === "complete" && frame.contentDocument.body?.hasChildNodes()) {
      onLoad();
    }
    return () => {
      frame.removeEventListener("load", onLoad);
      observer?.disconnect();
    };
  }, [html, ink, bg]);

  return (
    <iframe
      ref={frameRef}
      className={className}
      title={title}
      sandbox={FRAME_SANDBOX}
      srcDoc={`<!doctype html><html><head>${FRAME_HEAD}<style>${frameStyle(ink, bg)}</style></head><body>${html}</body></html>`}
      style={{ width: "100%", height, border: 0, display: "block" }}
    />
  );
}
