import DOMPurify from "dompurify";

// sanitizeEmailHtml is the one and only place untrusted HTML email content
// (sender-controlled — the single highest-risk XSS input in a mail client)
// is allowed to become live markup. Every caller that turns an email body
// into DOM (the read view, and reply/forward quoting into the compose
// editor) must route through this as the *last* transformation step, so
// nothing added earlier survives untouched.
//
// It lives in its own module rather than inside ReadPage.tsx so it can be
// tested directly — see emailHtml.test.ts.
//
// blockRemoteContent additionally forbids style/background attributes and
// <style>, <svg>, <video>, and <audio> elements. Stripping <img> tags alone
// does not block remote-resource loading: a legacy background="..."
// attribute, an inline style="background-image:url(...)", a <style> block,
// an SVG <image href="...">, a <video poster="...">, or an <audio src="...">
// are all in DOMPurify's default allowlist and fetch a remote URL eagerly on
// render exactly like <img src> does, so they bypass the "Show Images"
// control (and its anti-tracking-pixel intent) unless explicitly forbidden
// here too. svg/video/audio are all in DOMPurify's own DEFAULT_FORBID_CONTENTS
// set, so forbidding these three tags drops their entire subtree (any
// <source>/<track> children included) rather than hoisting children to the
// top level — no separate child-tag entry is needed.
// Interactive form controls are forbidden unconditionally. DOMPurify allows
// <form>/<input>/<button> by default, and no legitimate email needs them —
// but a sender-controlled form rendered inside the authenticated app is a
// credential-phishing surface that looks exactly like part of the client.
// The CSP's form-action 'self' stops the submission reaching an attacker's
// origin, which is a mitigation, not a reason to render the form at all.
const forbiddenTags = ["form", "input", "button", "textarea", "select", "option"];

// The URI schemes an email is allowed to link to.
//
// Pinned here rather than left to DOMPurify's default, even though the current
// default happens to be equivalent. This app deliberately navigates to its own
// kypost:// scheme elsewhere (NotificationsPage's "Pair Desktop App"), and every
// client registers itself as that scheme's system handler — so an
// <a href="kypost://native-pair?srv=https://evil.example&pt=..."> in a message
// body is a request to hand the user's device to an attacker's server. Leaving
// that to a library default means one dependency bump that widened it silently
// reopens a pairing-phishing hole, with no test to notice. Pinning it makes the
// allowlist ours, and emailHtml.test.ts holds it in place.
//
// The trailing alternations are what keep ordinary mail working: relative paths,
// bare fragments, and protocol-relative URLs all have no scheme to check. cid:
// is required for inline image references.
const allowedUriSchemes = /^(?:(?:https?|mailto|tel|cid):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i;

// Matches a leading "scheme:" so a refusal can name what it refused.
const leadingScheme = /^([a-z][a-z0-9+.\-]*):/i;

// The exact character class DOMPurify strips from an attribute value before
// testing it against ALLOWED_URI_REGEXP (its ATTR_WHITESPACE). Mirrored rather
// than approximated: this pre-check used to strip only [\x00-\x20], so a URL
// split by U+00A0 (or U+2028, U+3000, ...) was judged *allowed* here — no
// [Blocked link] marker emitted — and then normalized to "javascript:" and
// refused by DOMPurify. The result was the silent dead-but-clickable-looking
// anchor this marker exists to prevent. Two normalizations, one decision.
const attrWhitespace =
  /[\u0000-\u0020\u00A0\u1680\u180E\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]/g;

function isAllowedUri(href: string): boolean {
  return allowedUriSchemes.test(href.replace(attrWhitespace, ""));
}

// blockRemoteContent defaults to TRUE, and that default is the security
// property — not a convenience.
//
// It used to default to false. The read view passed `!showImages` explicitly
// and so behaved correctly, but four sibling call sites (buildReplyBody,
// buildForwardBody, printEmails, and opening a draft) called
// `sanitizeEmailHtml(body)` with one argument and silently got the permissive
// branch. Pressing Reply on a message whose images the user had deliberately
// NOT unblocked dropped the quoted body into the compose editor via
// `editor.root.innerHTML`, and every tracking pixel, <style> block,
// background= attribute, SVG <image href>, <video poster> and <audio src>
// fired at once — defeating the entire control this function's FORBID list
// exists to implement.
//
// A caller that wants remote content must now say so. Forgetting the argument
// fails closed (a missing image) instead of open (a fired tracking pixel).
export function sanitizeEmailHtml(html: string, blockRemoteContent = true): string {
  return DOMPurify.sanitize(
    html,
    blockRemoteContent
      ? {
          ADD_ATTR: ["target"],
          ALLOWED_URI_REGEXP: allowedUriSchemes,
          FORBID_ATTR: ["style", "background"],
          FORBID_TAGS: [...forbiddenTags, "style", "svg", "video", "audio"]
        }
      : { ADD_ATTR: ["target"], ALLOWED_URI_REGEXP: allowedUriSchemes, FORBID_TAGS: forbiddenTags }
  );
}

export function processEmailHtml(html: string, showImages: boolean): string {
  // Extract body content if it's a full HTML document
  const bodyMatch = html.match(/<body[^>]*>([\s\S]*)<\/body>/i);
  const content = bodyMatch ? bodyMatch[1] : html;

  const parser = new DOMParser();
  const document = parser.parseFromString(`<div>${content}</div>`, "text/html");
  const root = document.body.firstElementChild;
  if (!root) {
    return sanitizeEmailHtml(content, !showImages);
  }

  root.querySelectorAll("a[href]").forEach((anchor) => {
    // Sanitizing alone would strip the href and leave the anchor behind: styled
    // like a link, indistinguishable from one, and silently doing nothing when
    // clicked. A user who just read "Confirm your account" learns nothing from
    // a dead link, and may well go looking for another way to comply. Replace
    // the whole anchor with a visible refusal instead — the same treatment
    // [Image Blocked] gets below, and the same choice the Android client makes
    // when it toasts a blocked scheme rather than swallowing the tap.
    const href = anchor.getAttribute("href") ?? "";
    if (!isAllowedUri(href)) {
      const scheme = href.replace(attrWhitespace, "").match(leadingScheme)?.[1]?.toLowerCase();
      anchor.replaceWith(document.createTextNode(`[Blocked link: ${scheme ? `${scheme}:` : "unrecognized address"}]`));
      return;
    }
    anchor.setAttribute("target", "_blank");
    anchor.setAttribute("rel", "noopener noreferrer");
  });

  if (!showImages) {
    root.querySelectorAll("img").forEach((image) => {
      image.replaceWith(document.createTextNode("[Image Blocked]"));
    });
  }

  return sanitizeEmailHtml(root.innerHTML, !showImages);
}
