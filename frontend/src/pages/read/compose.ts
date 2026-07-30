// Building reply/forward bodies and reply-all recipient lists from a message.
//
// Quoting routes through processEmailHtml, NOT sanitizeEmailHtml: it must use
// the same pipeline the read view does (link blocking, img -> "[Image
// Blocked]", remote-content-blocking sanitize). sanitizeEmailHtml alone does
// not strip <img>, so quoting a message whose images the user chose not to
// unblock would fire its tracking pixels the moment they pressed Reply.

import { processEmailHtml } from "../../lib/emailHtml";
import { displayBody } from "./body";
import { firstAddressFromText, listAddressesFromText } from "../../lib/addressText";
import type { DecryptedView, InboxEmail } from "./types";
import { formatTimestamp } from "./format";

export function ensureSubjectPrefix(subject: string | undefined, prefix: "Re:" | "Fwd:"): string {
  const base = (subject ?? "").trim();
  if (base === "") {
    return prefix;
  }
  const lowerPrefix = prefix.toLowerCase();
  if (base.toLowerCase().startsWith(lowerPrefix)) {
    return base;
  }
  return `${prefix} ${base}`;
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// decrypted is the locally-decrypted view when there is one. Quoting a
// client-protected account's mail without it quoted the ENVELOPE — an armored
// blob or nothing at all — and paired the plaintext with the envelope's render
// mode. See read/body.ts.
export function buildReplyBody(email: InboxEmail, decrypted?: DecryptedView): string {
  const time = formatTimestamp(email.atUtc);
  const sender = email.sender || "-";
  const subject = email.subject || "(no subject)";
  const quoted = displayBody(email, decrypted);
  const body = quoted.body;
  const isHtml = quoted.mode === "html" && Boolean(body);
  // processEmailHtml, not sanitizeEmailHtml: quoting must go through the same
  // pipeline the read view uses (link blocking + img -> "[Image Blocked]" +
  // remote-content-blocking sanitize). sanitizeEmailHtml alone does not strip
  // <img>, so quoting a message the user chose not to unblock used to fire its
  // tracking pixels the moment they pressed Reply.
  const rendered = isHtml ? processEmailHtml(body, false) : `<pre style=\"white-space: pre-wrap; margin: 0;\">${escapeHtml(body)}</pre>`;
  return [
    "<p><br /></p>",
    `<p>On ${escapeHtml(time)}, ${escapeHtml(sender)} wrote:</p>`,
    "<blockquote style=\"margin: 0 0 0 0.8rem; padding-left: 0.8rem; border-left: 3px solid var(--line, #c2c7d0);\">",
    `<p><strong>Subject:</strong> ${escapeHtml(subject)}</p>`,
    rendered,
    "</blockquote>"
  ].join("");
}

export function buildForwardBody(email: InboxEmail, decrypted?: DecryptedView): string {
  const time = formatTimestamp(email.atUtc);
  const sender = email.sender || "-";
  const sentTo = email.sentTo || "-";
  const subject = email.subject || "(no subject)";
  const quoted = displayBody(email, decrypted);
  const body = quoted.body;
  const isHtml = quoted.mode === "html" && Boolean(body);
  // processEmailHtml, not sanitizeEmailHtml: quoting must go through the same
  // pipeline the read view uses (link blocking + img -> "[Image Blocked]" +
  // remote-content-blocking sanitize). sanitizeEmailHtml alone does not strip
  // <img>, so quoting a message the user chose not to unblock used to fire its
  // tracking pixels the moment they pressed Reply.
  const rendered = isHtml ? processEmailHtml(body, false) : `<pre style=\"white-space: pre-wrap; margin: 0;\">${escapeHtml(body)}</pre>`;
  return [
    "<p><br /></p>",
    "<p>---------- Forwarded message ----------</p>",
    `<p><strong>From:</strong> ${escapeHtml(sender)}</p>`,
    `<p><strong>Date:</strong> ${escapeHtml(time)}</p>`,
    `<p><strong>Subject:</strong> ${escapeHtml(subject)}</p>`,
    `<p><strong>To:</strong> ${escapeHtml(sentTo)}</p>`,
    rendered
  ].join("");
}

export function buildReplyAllRecipients(email: InboxEmail): { to: string; cc: string } {
  const sender = firstAddressFromText(email.sender || "");
  const senderKey = sender.toLowerCase();
  const recipients = [
    ...listAddressesFromText(email.sentTo || ""),
    ...listAddressesFromText(email.cc || "")
  ];
  const cc: string[] = [];
  const seen = new Set<string>();
  for (const recipient of recipients) {
    const key = recipient.toLowerCase();
    if (!recipient || key === senderKey || seen.has(key)) {
      continue;
    }
    seen.add(key);
    cc.push(recipient);
  }
  return { to: sender, cc: cc.join(", ") };
}

