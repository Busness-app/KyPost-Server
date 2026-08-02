import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { getJSON, toErrorMessage } from "../api/client";
import { reauthenticate } from "../api/auth";
import { useAuth } from "../auth";

/**
 * Holds back a screen until the person at the keyboard re-proves the account
 * credential and the second factor.
 *
 * The threat is the unattended session, not the stolen one: the Security page
 * lists key fingerprints and paired devices and hands out a backup of the PGP
 * private key, and until now anyone who walked up to a logged-in browser could
 * read and do all of it. Re-authentication is the only thing that distinguishes
 * the owner from whoever is sitting there, because the session cookie cannot.
 *
 * It is a UI gate and nothing else. The endpoints behind the page keep their
 * own step-ups (see api/pgp_stepup.go) and a caller who skips the page reaches
 * exactly what they always could — so do NOT move any authorisation decision
 * behind this component, and do not treat a pass here as one.
 */

/**
 * When the last successful step-up happened, and for whom.
 *
 * Module scope, so navigating away and back inside the window does not
 * re-prompt, and a reload always does — the same shape as the PGP vault, and
 * for the same reason: nothing that gates a screen should outlive the page it
 * was typed into. The username is part of the key because a logout and a second
 * sign-in in one tab never reloads the module, and one user's confirmation must
 * not answer for the next one's.
 */
let confirmedFor = "";
let confirmedAt = 0;
const CONFIRMATION_WINDOW_MS = 5 * 60_000;

/** Drops any live confirmation. Exported for logout and for tests. */
export function clearReauth() {
  confirmedFor = "";
  confirmedAt = 0;
}

function isConfirmed(username: string): boolean {
  return confirmedFor === username && Date.now() - confirmedAt < CONFIRMATION_WINDOW_MS;
}

type Props = {
  /** What the user is being asked to unlock, e.g. "your security settings". */
  what: string;
  children: ReactNode;
};

export function ReauthGate({ what, children }: Props) {
  const username = useAuth().username ?? "";
  const [confirmed, setConfirmed] = useState(() => isConfirmed(username));
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  // Undefined until the status call answers. The code field is shown while it
  // is unknown as well as when it is true: asking for a code nobody has costs a
  // moment's confusion, and not asking for one that IS required costs a failed
  // submit for every user with MFA on if the status call ever breaks.
  const [totpEnabled, setTotpEnabled] = useState<boolean | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (confirmed) return;
    let cancelled = false;
    getJSON<{ totpEnabled: boolean }>("/api/mfa/status")
      .then((s) => {
        if (!cancelled) setTotpEnabled(s.totpEnabled);
      })
      .catch(() => {
        if (!cancelled) setTotpEnabled(true);
      });
    return () => {
      cancelled = true;
    };
  }, [confirmed]);

  useEffect(() => {
    if (!confirmed) return;
    const remaining = Math.max(0, confirmedAt + CONFIRMATION_WINDOW_MS - Date.now());
    const timer = window.setTimeout(() => window.location.reload(), remaining);
    return () => window.clearTimeout(timer);
  }, [confirmed]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await reauthenticate(password, code.trim());
      confirmedFor = username;
      confirmedAt = Date.now();
      setPassword("");
      setCode("");
      setConfirmed(true);
    } catch (e) {
      setError(toErrorMessage(e, "could not confirm it is you"));
      // A wrong code is retried far more often than a wrong password, and the
      // recovery-code case has already spent the code that was typed.
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  if (confirmed) return <>{children}</>;

  return (
    // The page's own shell, so the gate reads as that page asking a question
    // rather than as a stray form the app dropped the user on.
    <section className="panel sec-page">
      <header className="sec-header">
        <h2>Confirm it is you</h2>
        <p>Unlock {what}.</p>
      </header>
      <div className="sec-card">
        <p className="sec-muted">
          This page shows your key fingerprints and paired devices, and can hand out a backup of your private key.
          Being signed in is not enough to see it — confirm your password
          {totpEnabled === false ? "" : " and two-factor code"} to continue.
        </p>
        <form className="auth-form sec-inline-form" onSubmit={(e) => void submit(e)}>
          <label>
            <div>Account password</div>
            <input
              type="password"
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </label>
          {totpEnabled === false ? null : (
            <label>
              <div>Two-factor code</div>
              <input
                type="text"
                inputMode="text"
                autoComplete="one-time-code"
                placeholder="123456 or a recovery code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </label>
          )}
          {error ? (
            <p className="sec-verdict sec-verdict-risk" role="alert">
              {error}
            </p>
          ) : null}
          <div className="sec-actions">
            <button type="submit" disabled={busy || password.length === 0}>
              {busy ? "Confirming…" : "Continue"}
            </button>
          </div>
        </form>
      </div>
    </section>
  );
}
