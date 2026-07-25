import { useEffect, useRef, useState, type FormEvent } from "react";
import { useDialogOpen } from "../hooks/useDialogOpen";
import { unlockPGPSession } from "../lib/pgpSession";
import { toErrorMessage } from "../api/client";

type Props = {
  open: boolean;
  /** Why the key is needed, e.g. "to read this message". Shown to the user. */
  reason?: string;
  onUnlocked: () => void;
  onCancel: () => void;
};

/**
 * Prompts for the account password to unwrap the PGP private key.
 *
 * This appears on demand rather than at login: a user who never opens an
 * encrypted message should never be asked. It also appears again after every
 * reload, because the unwrapped key is held in page memory only — that is the
 * cost of the server not being able to read your mail, and the copy says so
 * rather than leaving people wondering why they keep being asked.
 */
export function PgpUnlockDialog({ open, reason, onUnlocked, onCancel }: Props) {
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useDialogOpen(dialogRef, open);

  // Never leave a typed password sitting in component state once the dialog
  // is dismissed, however it was dismissed.
  useEffect(() => {
    if (!open) {
      setPassword("");
      setError("");
    }
  }, [open]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await unlockPGPSession(password);
      setPassword("");
      onUnlocked();
    } catch (e) {
      setError(toErrorMessage(e, "could not unlock the key"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <dialog
      ref={dialogRef}
      className="rules-help-backdrop"
      aria-label="Unlock your PGP key"
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
      onClick={(event) => {
        if (event.target === dialogRef.current) {
          onCancel();
        }
      }}
    >
      <div className="rules-help-window" style={{ width: "min(460px, 94vw)" }} onClick={(event) => event.stopPropagation()}>
        <div className="rules-help-head">
          <h3>Unlock your PGP key</h3>
        </div>
        <div className="rules-help-body">
          <p className="contacts-muted">
            {reason ? `Your password is needed ${reason}. ` : ""}
            Your private key is encrypted with your account password, and this server cannot open it — so it has to be
            unlocked here each time the page loads.
          </p>
          <form onSubmit={submit}>
            <label htmlFor="pgp-unlock-password" style={{ display: "block", marginBottom: 4 }}>
              Account password
            </label>
            <input
              id="pgp-unlock-password"
              type="password"
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              style={{ width: "100%" }}
            />
            {error ? (
              <p className="security-badge security-badge-off" style={{ marginTop: 8 }} role="alert">
                {error}
              </p>
            ) : null}
            <div style={{ display: "flex", gap: 8, marginTop: 16, justifyContent: "flex-end" }}>
              <button type="button" className="contacts-action" onClick={onCancel} disabled={busy}>
                Cancel
              </button>
              <button type="submit" disabled={busy || password.length === 0}>
                {busy ? "Unlocking…" : "Unlock"}
              </button>
            </div>
          </form>
        </div>
      </div>
    </dialog>
  );
}
