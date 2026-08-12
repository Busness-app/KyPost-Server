import type { DecryptedView, InboxEmail } from "./types";

/**
 * What the reading pane should say about one message's signature.
 *
 * - `none` — no signature. Almost all mail.
 * - `checking` — the browser is fetching the signed bytes and verifying them.
 * - `verified` — a key the address book binds to this sender produced this
 *   signature. The strong claim, and the only one that reads as a pass.
 * - `mismatched` — a signature that checks out cryptographically, from a key
 *   that is NOT bound to the sender. Someone signed this; not the person the
 *   From header names.
 * - `unchecked` — signed, and we could not establish anything. No key bound to
 *   this sender, or the fetch or parse failed.
 *
 * `mismatched` and `unchecked` are kept apart because the copy for one is an
 * accusation and the copy for the other is an admission. Collapsing them —
 * which the old encrypted-only badge did, rendering "does not match sender" for
 * both — puts a warning on every first message from every new correspondent who
 * signs, and readers who learn to ignore it will ignore the real one too.
 */
export type SignatureState =
  | "none"
  | "checking"
  | "verified"
  | "mismatched"
  | "conflicted"
  | "unchecked";

/**
 * Derives the state from the message and this browser's verification of it.
 *
 * `local` wins over the server's fields wherever it exists: it is the verdict
 * this browser computed over bytes it fetched raw, while the message's own
 * pgpVerified can only ever come from the server. For signed-only mail the
 * server no longer sets it at all (see markSignedOnlyMessageContent); the
 * fallback remains for a server-protected account's ENCRYPTED mail, where the
 * server decrypted and verified in one step and there is no local view.
 */
export function signatureState(
  email: InboxEmail,
  local: DecryptedView | undefined,
  checking: boolean
): SignatureState {
  const signed = local ? local.signed : Boolean(email.pgpSigned);
  if (!signed) {
    return "none";
  }
  if (checking) {
    return "checking";
  }
  const verified = local ? local.verified : Boolean(email.pgpVerified);
  if (verified) {
    return "verified";
  }
  const fingerprint = local ? local.signerFingerprint : email.pgpSignerFingerprint;
  if (fingerprint) {
    return "mismatched";
  }
  // A changed key ranks above the generic admission. The server withholds the
  // key material for a contact that fails its TOFU pin, so the check cannot
  // run — and reporting that as "could not be checked" made the one event TOFU
  // exists to announce look identical to an unknown correspondent.
  return local?.signerConflict ? "conflicted" : "unchecked";
}

/** The badge text. Each string claims exactly what was established, no more. */
export function signatureLabel(state: SignatureState): string {
  switch (state) {
    case "verified":
      return "signature verified";
    case "mismatched":
      return "signature does not match sender";
    case "conflicted":
      return "this sender's key has changed";
    case "unchecked":
      // Deliberately does not say WHY. The client cannot distinguish "no bound
      // key" from "a bound key exists and did not sign this", because the
      // server ships a key list already filtered to the sender — so the old
      // "— no key for this sender" was false in exactly the impersonation case
      // the badge matters for.
      return "signature could not be checked";
    case "checking":
      return "checking signature…";
    default:
      return "";
  }
}
