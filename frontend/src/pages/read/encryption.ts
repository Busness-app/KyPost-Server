import type { DecryptedView, InboxEmail } from "./types";

/**
 * What the inbox list's encryption column should say about one message.
 *
 * - `none` — not encrypted. The overwhelming majority of mail: company and
 *   transactional senders never encrypt, so the column is empty for most rows.
 * - `encrypted` — encrypted and readable, either because the server decrypted
 *   it (server custody) or because this browser already has.
 * - `locked` — encrypted, and nothing can be shown until the PGP key vault is
 *   unlocked. Only reachable for a client-protected account, which is the only
 *   kind that has a vault to unlock.
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
 *
 * `clientProtected` is the account's custody mode, and it is what an empty body
 * means. Under CLIENT custody an encrypted message with no body and no error is
 * the wire shape of "the server cannot open this, your browser must" — locked.
 * Under SERVER custody the same shape means the server already decrypted it and
 * the plaintext simply had no text: an attachment-only message. Deriving locked
 * from the body alone told the owner of an attachment-only message to unlock a
 * key when there was nothing to unlock and no vault to unlock it with.
 */
export function encryptionState(
  email: InboxEmail,
  local?: DecryptedView,
  clientProtected = false
): EncryptionState {
  if (!email.pgpEncrypted) {
    return "none";
  }
  if (email.pgpDecryptError || local?.error) {
    return "failed";
  }
  if (local || email.body) {
    return "encrypted";
  }
  return clientProtected ? "locked" : "encrypted";
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
