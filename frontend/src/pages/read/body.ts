import { resolveBodyMode } from "../../lib/emailHtml";
import type { DecryptedView, InboxEmail } from "./types";

/**
 * The text to render for a message and the mode that goes with it. The two must
 * be chosen together, which is why this exists.
 *
 * A message has up to two bodies: the one the server sent, and — for a
 * client-protected account — the one this browser decrypted. Each carries its
 * own answer about which MIME part it came from, and the answers are not
 * interchangeable. The server's `bodyMode` describes the outer envelope, and a
 * multipart/encrypted envelope has no readable text part, so pairing the
 * decrypted plaintext with the envelope's mode reports "plain" for content that
 * may be markup, and an HTML message renders as escaped source.
 *
 * Four call sites picked these values independently — reader, reply, forward,
 * print — and three read `email.bodyMode` unconditionally while only the reader
 * accounted for the decrypted case. Returning the pair from one function makes
 * the mismatched combination unrepresentable.
 */
export function displayBody(email: InboxEmail, decrypted?: DecryptedView): {
  body: string;
  mode: "html" | "plain";
} {
  // A locally decrypted or verified body wins: for a client-protected account
  // the server sends no usable body at all for encrypted mail.
  //
  // The test is bodyFromVerifiedPart, NOT decrypted.body's truthiness. An empty
  // body from a check that succeeded means "the bytes we verified contain
  // nothing displayable" — an attachment-only signed message — and it must
  // render as nothing. Falling through to email.body there showed the server's
  // parse of the whole message, including parts outside the signature, under a
  // green badge. See CVE-2021-4126 for the same defect in Thunderbird.
  // `!error` is belt alongside the flag, not the test itself: the signed-only
  // failure path deliberately stores an EMPTY error so nothing is shown to the
  // reader, so an error check on its own would not catch it. The flag is what
  // does the work; this just keeps an errored view from ever winning.
  if (decrypted?.bodyFromVerifiedPart && !decrypted.error) {
    return {
      body: decrypted.body,
      // pgpClient read this off the decrypted entity's Content-Type. It is
      // undefined only for inline PGP, which has no MIME headers to read; that
      // is the one case that falls back to inspecting the bytes.
      mode: resolveBodyMode(decrypted.body, decrypted.bodyMode)
    };
  }
  const body = email.body ?? "";
  return { body, mode: resolveBodyMode(body, email.bodyMode) };
}
