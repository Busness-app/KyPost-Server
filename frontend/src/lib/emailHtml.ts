import DOMPurify from "dompurify";

// sanitizeEmailHtml is the ONLY place untrusted email HTML becomes live
// markup. Every caller that turns an email body into DOM — the read view, and
// reply/forward quoting into the compose editor — must route through it as the
// LAST transformation step, so nothing added earlier survives untouched.
//
// Separate module so it can be tested directly; see emailHtml.test.ts.
//
// Two groups, forbidden for different reasons:
//
// forbiddenTags/forbiddenAttrs — unconditional, regardless of the remote
// content toggle.
//   - form/input/button/textarea/select/option: DOMPurify allows these by
//     default. A sender-controlled form inside the authenticated app is a
//     credential-phishing surface that looks like part of the client. The
//     CSP's form-action 'self' is a mitigation, not a reason to render it.
//   - style (tag and attribute): the CSP allows style-src 'unsafe-inline' and
//     email CSS is not scoped to the message container, so a sender with CSS
//     can hide the impersonation banner with
//     .notice-error{display:none!important}, repaint the PGP badge green, or
//     cover the viewport with a fixed-position overlay — none of which needs
//     script. These must NOT be coupled to blockRemoteContent: loading a
//     picture and restyling the application are different decisions, and only
//     the first is what the toggle asks about.
//
// blockRemoteContent adds background, svg, video, audio. Stripping <img>
// alone does not stop remote loads: background="...", SVG <image href>,
// <video poster>, <audio src> are all default-allowed and fetch eagerly, so
// they bypass "Show Images" and its anti-tracking-pixel intent. All three tags
// are in DOMPurify's DEFAULT_FORBID_CONTENTS, so forbidding them drops the
// whole subtree — no separate <source>/<track> entry needed.
const forbiddenTags = ["form", "input", "button", "textarea", "select", "option", "style"];
// class/id are stripped for the same reason as style: the app's stylesheet is
// global and unscoped, so a sender who can name our classes gets our CSS
// without needing any of their own. Five rules are position:fixed inset:0 at
// z-index up to 2600 — enough to cover the viewport with app-styled chrome,
// intercept every click and paint a forged "PGP verified" badge, all with no
// script and no remote content. `open` goes too: those rules are guarded by
// :not([open]), and DOMPurify allows the attribute by default.
//
// color/bgcolor are the presentational spelling of the same thing, and they are
// stripped for readability rather than for safety. A message is rendered on the
// reader's theme background (EmailBodyFrame injects --bg and --ink-strong; the
// plain-text block uses the same pair), and a sender cannot see which theme that
// is. `<font color="#000000">` is black on #1a1a1e under Dark Matter — the exact
// black-on-near-black failure the frame's own colour injection exists to fix,
// arriving from the sender instead of from a system colour keyword.
//
// STRIP BOTH OR NEITHER. Half of this pair is worse than all of it: a message
// that sets only a background keeps a dark panel under theme-light text, and one
// that sets only a foreground puts dark text on a dark theme. Since `style` is
// already stripped — which is how the overwhelming majority of HTML mail carries
// colour — leaving these two was an inconsistency, not a design: the same
// message lost its CSS colours and kept its attribute ones. Mail now renders in
// the reader's palette, always legible, and the layout attributes DOMPurify
// allows (align, width, height) are untouched.
const forbiddenAttrs = ["style", "class", "id", "open", "color", "bgcolor"];

// The URI schemes an email is allowed to link to.
//
// Pinned here rather than left to DOMPurify's default, which currently happens
// to be equivalent. Every client registers as the system handler for this
// app's own kypost:// scheme, so an
// <a href="kypost://native-pair?srv=https://evil.example&pt=..."> is a request
// to hand the user's device to an attacker's server. A dependency bump that
// widened the library default would silently reopen that with no test to
// notice; emailHtml.test.ts holds this one in place.
//
// The trailing alternations keep ordinary mail working — relative paths, bare
// fragments and protocol-relative URLs have no scheme to check. cid: is
// required for inline images.
const allowedUriSchemes = /^(?:(?:https?|mailto|tel|cid):|[^a-z]|[a-z][a-z0-9+.\-]*(?:[^a-z0-9+.\-:]|$))/i;

// Matches a leading "scheme:" so a refusal can name what it refused.
const leadingScheme = /^([a-z][a-z0-9+.\-]*):/i;

// DOMPurify's ATTR_WHITESPACE: the exact character class it strips from an
// attribute value before testing ALLOWED_URI_REGEXP. Mirrored, not
// approximated — if this pre-check normalizes less than DOMPurify does, a URL
// split by U+00A0 (or U+2028, U+3000, ...) is judged allowed here, emits no
// [Blocked link] marker, and is then refused by DOMPurify, leaving the silent
// dead-but-clickable anchor the marker exists to prevent.
const attrWhitespace =
  /[\u0000-\u0020\u00A0\u1680\u180E\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]/g;

function isAllowedUri(href: string): boolean {
  return allowedUriSchemes.test(href.replace(attrWhitespace, ""));
}

// blockRemoteContent defaults to TRUE. That default is the security property,
// not a convenience: a caller that wants remote content must say so, so
// forgetting the argument fails closed (a missing image) rather than open (a
// fired tracking pixel). Five call sites turn email HTML into DOM and only one
// of them is the read view that owns the toggle.
export function sanitizeEmailHtml(html: string, blockRemoteContent = true): string {
  return DOMPurify.sanitize(
    html,
    blockRemoteContent
      ? {
          ADD_ATTR: ["target"],
          ALLOWED_URI_REGEXP: allowedUriSchemes,
          FORBID_ATTR: [...forbiddenAttrs, "background"],
          FORBID_TAGS: [...forbiddenTags, "svg", "video", "audio"]
        }
      : { ADD_ATTR: ["target"], ALLOWED_URI_REGEXP: allowedUriSchemes, FORBID_ATTR: forbiddenAttrs, FORBID_TAGS: forbiddenTags }
  );
}

// looksLikeHtml is the last-resort check for a body whose MIME type is
// unavailable. Since pgpClient reads the mode off the decrypted entity's own
// Content-Type (lib/mimeContent.ts), that is one case: a mail-cache entry
// written before the server reported `bodyMode`. Prefer the reported answer; see
// resolveBodyMode.
//
// It asks the HTML parser instead of matching tag names, because a name list can
// only rot and both previous attempts were wrong in one direction or the other:
//
//   /<[^>]+>/                  matched "<user@example.com>" — RFC 5322's own
//                              address form, and the most common angle-bracket
//                              construct in plain-text mail.
//   a 34-tag allowlist         missed <center>, <o:p>, <dl>, <code>, <small>,
//                              <figure>, <article>, so HTML mail rendered as
//                              escaped source.
//
// Two signals, both required:
//
//   1. Something parsed as a real element. HTMLUnknownElement is what both
//      "<user@example.com>" and "<o:p>" become, so element presence alone
//      cannot separate them — but <center> and <figure> are real elements,
//      which is the half the allowlist kept missing.
//   2. The parse changed the text. If stripping markup leaves the input
//      byte-for-byte intact there was no markup: "a < b and b > c" survives
//      untouched, "<p>hi</p>" does not.
//
// It errs towards markup: prose mentioning a real tag ("use <br> to break a
// line") is indistinguishable from markup without a Content-Type, and this calls
// it markup. That cost is bounded — a known element renders as itself and the
// surrounding words survive, so the reader loses four literal characters. An
// unknown element instead swallows its content, which is how
// "<user@example.com>" used to vanish entirely; signal 1 rules that out, so do
// not relax it.
export function looksLikeHtml(body: string): boolean {
  // Cheap reject before touching the parser: no angle bracket, no markup.
  if (!body.includes("<")) {
    return false;
  }
  const doc = new DOMParser().parseFromString(body, "text/html");
  const hasRealElement = Array.from(doc.body.querySelectorAll("*")).some(
    (el) => !(el instanceof HTMLUnknownElement)
  );
  return hasRealElement && doc.body.textContent !== body;
}

/**
 * Decides how to render a body, preferring what the server said over any
 * inspection of the bytes.
 *
 * `mode` comes from imapadapter.clientBody / pgpmail.ParseContent, which read
 * it off the part's own Content-Type. It is absent only where the server
 * genuinely cannot know: a client-protected account's mail, which the browser
 * decrypts itself, and cache entries predating the field.
 */
export function resolveBodyMode(body: string, mode?: string): "html" | "plain" {
  if (mode === "html" || mode === "plain") {
    return mode;
  }
  return looksLikeHtml(body) ? "html" : "plain";
}

export function processEmailHtml(html: string, showImages: boolean): string {
  // Parse the whole thing as a document and work on its <body>. Never wrap in an
  // element and read that element's innerHTML back: the HTML parser closes the
  // wrapper on the first stray "</div>" in the message, so everything after it
  // becomes a sibling of the wrapper and is dropped — truncating the mail, and
  // skipping the anchor pass below for every link that landed outside.
  // Unbalanced div nesting is routine in real email.
  //
  // DOMParser also replaces the regex that used to cut content out of
  // <body>...</body>, which a "</body>" inside a comment or an attribute value
  // re-cut. document.body always exists here, full document or fragment.
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");
  const root = doc.body;

  root.querySelectorAll("a[href]").forEach((anchor) => {
    // Sanitizing alone strips the href and leaves the anchor: styled like a
    // link, indistinguishable from one, silently doing nothing when clicked. A
    // user who just read "Confirm your account" learns nothing from that and
    // goes looking for another way to comply. Replace it with a visible
    // refusal, as [Image Blocked] does below.
    const href = anchor.getAttribute("href") ?? "";
    if (!isAllowedUri(href)) {
      const scheme = href.replace(attrWhitespace, "").match(leadingScheme)?.[1]?.toLowerCase();
      anchor.replaceWith(doc.createTextNode(`[Blocked link: ${scheme ? `${scheme}:` : "unrecognized address"}]`));
      return;
    }
    anchor.setAttribute("target", "_blank");
    anchor.setAttribute("rel", "noopener noreferrer");
  });

  if (!showImages) {
    root.querySelectorAll("img").forEach((image) => {
      image.replaceWith(doc.createTextNode("[Image Blocked]"));
    });
  }

  return sanitizeEmailHtml(root.innerHTML, !showImages);
}
