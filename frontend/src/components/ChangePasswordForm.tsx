import { FormEvent, useState } from "react";
import { postJSON } from "../api/client";
import { credentialFields, deriveCredential, deriveNewCredential } from "../api/auth";
import { defaultIterations, newLoginSalt } from "../lib/authSecret";
import { loadPGPSession, rewrappedEnvelopeFor } from "../lib/pgpSession";

// Mirror of users.MinPasswordLen on the server.
//
// Duplicated rather than fetched because the server can no longer measure it: a
// converted account sends a derived auth secret, not the password. The floor has
// to be enforced where the password still exists, which is here. The server
// keeps enforcing it on the legacy plaintext path and on admin-set passwords.
const MIN_PASSWORD_LEN = 14;

export type ChangePasswordFormProps = {
  /** Shown read-only, and used for nothing else — the server answers for the session. */
  username: string;
  /** The sign-in password carried into a forced reset, so the user need not retype it. Empty on Security. */
  initialCurrentPassword?: string;
  /** Called after the password and re-wrapped PGP envelope have both committed. */
  onSuccess: () => void | Promise<void>;
};

export function ChangePasswordForm({ username, initialCurrentPassword, onSuccess }: ChangePasswordFormProps) {
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);

  async function submitPasswordChange(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setStatus("");
    const currentPassword = oldPassword || initialCurrentPassword || "";
    if (!currentPassword) {
      setStatus("Enter your current password from initial sign-in.");
      setBusy(false);
      return;
    }
    try {
      // MIN_PASSWORD_LEN is enforced here, in the client, because the server
      // cannot see the new password any more — that is the point of deriving the
      // credential locally. The server still checks length on the legacy
      // plaintext path and on admin-set passwords, which is where an operator
      // policy actually needs to bite.
      if ([...newPassword].length < MIN_PASSWORD_LEN) {
        setStatus(`New password must be at least ${MIN_PASSWORD_LEN} characters.`);
        setBusy(false);
        return;
      }

      // Build everything BEFORE writing anything, then send one request.
      //
      // The PGP key is sealed under the account password, so the credential and
      // the re-sealed envelope have to land together. They used to be two
      // sequential requests, and a dropped connection between them stranded the
      // key permanently — the only rewrap path re-derives from the current
      // password and so could never open the stale envelope again.
      const iterations = defaultIterations();
      const salt = newLoginSalt();
      const newAuthSecret = await deriveNewCredential(newPassword, salt, iterations);
      // Empty username: this flow always runs with a session (/api/auth/password
      // is withAuth), so the server answers for the caller AND tells us which
      // credential form it stores — which keeps a converted account's plaintext
      // password off the wire here. See credentialFields.
      const oldCredential = await deriveCredential("", currentPassword);
      const rewrappedPgpKey = await rewrappedEnvelopeFor(currentPassword, newPassword);

      await postJSON<{ ok: boolean }>("/api/auth/password", {
        ...credentialFields(oldCredential, "old"),
        newAuthSecret,
        newLoginSalt: salt,
        newIterations: iterations,
        ...(rewrappedPgpKey ? { rewrappedPgpKey } : {})
      });

      // The envelope, if there was one, is already committed alongside the
      // credential; refresh the cached snapshot so the UI reflects it.
      await loadPGPSession();

      setOldPassword("");
      setNewPassword("");
      setStatus("Password updated. You can now continue.");
      await onSuccess();
    } catch (err) {
      const message = err instanceof Error ? err.message : "";
      if (message.includes("401")) {
        setStatus("Password change failed. Sign in first, then try again.");
      } else {
        setStatus("Password change failed. Verify current password.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <form onSubmit={submitPasswordChange} className="auth-form">
        <header className="auth-head">
          <h1 className="auth-title">Choose a new password</h1>
          <p className="auth-lede">Your PGP key is re-encrypted under the new password automatically.</p>
        </header>

        <label className="auth-field">
          <span className="auth-label">Username</span>
          <input className="auth-input auth-input-code" value={username} autoComplete="username" readOnly />
        </label>
        <label className="auth-field">
          <span className="auth-label">Current password</span>
          <input
            className="auth-input"
            type="password"
            value={oldPassword}
            onChange={(e) => setOldPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        <label className="auth-field">
          <span className="auth-label">New password</span>
          <input
            className="auth-input"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            autoComplete="new-password"
          />
        </label>

        <button type="submit" className="auth-submit" disabled={busy}>
          {busy ? "Updating…" : "Update password"}
        </button>
      </form>

      {status ? (
        <p className="auth-status" role="status">
          {status}
        </p>
      ) : null}
    </>
  );
}
