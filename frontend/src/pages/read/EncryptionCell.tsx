import { encryptionLabel, encryptionState } from "./encryption";
import type { DecryptedView, InboxEmail } from "./types";

/**
 * The inbox list's encryption column: a padlock, or nothing.
 *
 * A padlock on every encrypted row, whether or not it opened. Earlier this
 * marking lived inside the Subject cell and appeared only when the row yielded
 * nothing readable, on the reasoning that marking decrypted mail would put a
 * symbol on most rows of a server-mode mailbox. That reasoning had the traffic
 * backwards: company and transactional senders never encrypt, so encrypted
 * mail is rare across a mailbox and the column is empty for most rows. What it
 * is not is evenly spread — it concentrates in Uncategorized, because an
 * encrypted message has no readable body for the classifier to sort on
 * (processor/poller.go tags it with the account default and skips the model).
 *
 * A failed decrypt keeps the same padlock rather than a second symbol, tinted
 * to mark it. That row is the one that misleads without a marking: the subject
 * reads like ordinary mail and the body will never open.
 */
export function EncryptionCell({ email, local }: { email: InboxEmail; local?: DecryptedView }) {
  const state = encryptionState(email, local);
  if (state === "none") {
    return <td className="inbox-cell inbox-col-lock" />;
  }
  const label = encryptionLabel(state, email.pgpDecryptError || local?.error);
  return (
    <td className="inbox-cell inbox-col-lock">
      <span
        className={`inbox-lock-icon ${state === "failed" ? "inbox-lock-icon-failed" : ""}`.trim()}
        title={label}
        aria-label={label}
        role="img"
      >
        🔒
      </span>
    </td>
  );
}
