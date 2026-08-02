import type { DecryptedView, InboxEmail } from "./types";

/**
 * What the inbox list's encryption column should say about one message.
 *
 * - `none` — not encrypted. The overwhelming majority of mail: company and
 *   transactional senders never encrypt, so the column is empty for most rows.
 * - `encrypted` — encrypted and readable, either because the server decrypted
 *   it (server custody) or because this browser already has.
 * - `locked` — encrypted, and nothing can be shown until the PGP key vault is
 *   unlocked. The wire signal is pgpEncrypted with no body and no
 *   pgpDecryptError, which is exactly what a client-protected account gets:
 *   the server cannot decrypt for it and does not pretend to.
 * - `failed` — decryption was attempted and did not work. The row's subject
 *   looks like ordinary mail but the body will never open, which is the one
 *   case where an unmarked row actively misleads.
 */
export type EncryptionState = "none" | "encrypted" | "locked" | "failed";

/**
 * Derives the column state from the message and any locally-decrypted view of
 * it. Pure, so the edge cases are testable without rendering the list.
 *
 * `local` is this browser's decrypt of a client-protected message, held in
 * component state and never sent anywhere. Its error wins over the server's:
 * for a client-protected account the server never saw the ciphertext, so it
 * has no verdict to offer.
 */
export function encryptionState(email: InboxEmail, local?: DecryptedView): EncryptionState {
  if (!email.pgpEncrypted) {
    return "none";
  }
  if (email.pgpDecryptError || local?.error) {
    return "failed";
  }
  if (local) {
    return "encrypted";
  }
  return email.body ? "encrypted" : "locked";
}

/**
 * The hover/screen-reader text for a state. Split from the glyph because
 * `encrypted` and `locked` render the same padlock and differ only here — the
 * column is meant to read as "padlock or nothing" at a glance, with the detail
 * available on demand rather than as a second symbol to learn.
 */
export function encryptionLabel(state: EncryptionState, decryptError?: string): string {
  switch (state) {
    case "failed":
      return `Could not decrypt: ${decryptError || "unknown error"}`;
    case "locked":
      return "Encrypted — unlock your PGP key to read";
    case "encrypted":
      return "Encrypted";
    default:
      return "";
  }
}
