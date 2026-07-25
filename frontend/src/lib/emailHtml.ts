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

export function sanitizeEmailHtml(html: string, blockRemoteContent = false): string {
  return DOMPurify.sanitize(
    html,
    blockRemoteContent
      ? {
          ADD_ATTR: ["target"],
          FORBID_ATTR: ["style", "background"],
          FORBID_TAGS: [...forbiddenTags, "style", "svg", "video", "audio"]
        }
      : { ADD_ATTR: ["target"], FORBID_TAGS: forbiddenTags }
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
