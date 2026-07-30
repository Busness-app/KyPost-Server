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
  // A locally decrypted body wins: for a client-protected account the server
  // sends no usable body at all for encrypted mail.
  if (decrypted?.body) {
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
