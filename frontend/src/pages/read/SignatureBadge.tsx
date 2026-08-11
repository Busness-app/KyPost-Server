import { signatureLabel, signatureState } from "./signature";
import type { DecryptedView, InboxEmail } from "./types";

/**
 * The reading pane's signature badge.
 *
 * Rendered for any signed message, encrypted or not. It used to live inside the
 * encryption badge's conditional, so a signed-but-unencrypted message — the
 * whole population of mail that is authenticated without being secret — got no
 * indicator at all.
 *
 * The fingerprint hint appears only alongside a mismatch, where it is the
 * actionable part: it names the key that actually signed, so the reader can
 * tell an unknown correspondent apart from an impersonation of a known one.
 * Under a pass it would be noise, and under "could not be checked" there is no
 * fingerprint to show.
 */
export function SignatureBadge({
  email,
  local,
  checking
}: {
  email: InboxEmail;
  local?: DecryptedView;
  checking: boolean;
}) {
  const state = signatureState(email, local, checking);
  if (state === "none") {
    return null;
  }
  const fingerprint = local ? local.signerFingerprint : email.pgpSignerFingerprint;
  return (
    <>
      <span
        className={`security-badge ${state === "verified" ? "security-badge-on" : "security-badge-off"}`}
        style={{ marginLeft: 6 }}
      >
        <span className="security-dot" aria-hidden="true" />
        {signatureLabel(state)}
      </span>
      {state === "mismatched" && fingerprint ? (
        <span className="contacts-muted" style={{ marginLeft: 6 }}>
          signed by {fingerprint.slice(-16)}
        </span>
      ) : null}
    </>
  );
}
