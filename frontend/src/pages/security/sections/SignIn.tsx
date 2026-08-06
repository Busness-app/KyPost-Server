import { FormEvent, useEffect, useState } from "react";
import QRCode from "qrcode";
import { postJSON, toErrorMessage } from "../../../api/client";
import { credentialFields, deriveCredential } from "../../../api/auth";
import type { MfaStatus } from "../types";

type SetupResponse = {
  secret: string;
  otpauthUri: string;
};

type ConfirmResponse = {
  ok: boolean;
  recoveryCodes: string[];
};

const noop = () => {};
const noopAsync = async () => {};

export type SignInProps = {
  /** Current MFA status. Optional so this renders (unenrolled) with zero props. */
  status?: MfaStatus | null;
  /** Refetches `status` after an enrollment/disable/regenerate mutation. */
  refreshStatus?: () => Promise<void>;
  // Recovery codes are shown here once, after confirm or regenerate, but
  // SecurityPage's own page-level summary also reads them (a just-confirmed
  // enrollment must flip "Password only" to "Password and code" immediately,
  // before status has been refetched) — so this is SecurityPage's state,
  // passed down, not a local copy.
  recoveryCodes?: string[];
  setRecoveryCodes?: (codes: string[]) => void;
  /** Surfaces a message on SecurityPage's shared, page-level status line. */
  setMessage?: (message: string) => void;
};

export function SignIn({
  status = null,
  refreshStatus = noopAsync,
  recoveryCodes = [],
  setRecoveryCodes = noop,
  setMessage = noop
}: SignInProps = {}) {
  const [busy, setBusy] = useState(false);

  // Enrollment state.
  const [setup, setSetup] = useState<SetupResponse | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [confirmCode, setConfirmCode] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  // Recovery-code display (shown once after confirm or regenerate).
  const [savedAcknowledged, setSavedAcknowledged] = useState(false);

  // Password-confirm modals.
  const [disablePassword, setDisablePassword] = useState("");
  const [showDisable, setShowDisable] = useState(false);
  const [regeneratePassword, setRegeneratePassword] = useState("");
  const [showRegenerate, setShowRegenerate] = useState(false);

  useEffect(() => {
    let cancelled = false;
    if (!setup?.otpauthUri) {
      setQrDataUrl("");
      return;
    }
    QRCode.toDataURL(setup.otpauthUri, { errorCorrectionLevel: "M", margin: 2, width: 220 })
      .then((dataUrl) => {
        if (!cancelled) {
          setQrDataUrl(dataUrl);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setQrDataUrl("");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [setup]);

  async function beginSetup() {
    setBusy(true);
    setMessage("");
    setRecoveryCodes([]);
    setSavedAcknowledged(false);
    try {
      const res = await postJSON<SetupResponse>("/api/mfa/totp/setup", {});
      setSetup(res);
      setConfirmCode("");
    } catch (err) {
      setMessage(toErrorMessage(err, "Failed to start enrollment."));
    } finally {
      setBusy(false);
    }
  }

  async function submitConfirm(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      // The password is required to ENABLE, not just to disable: enrolling a
      // factor the account owner does not hold is at least as consequential as
      // removing one, and a later password change does not undo it.
      const credential = await deriveCredential("", confirmPassword);
      const res = await postJSON<ConfirmResponse>("/api/mfa/totp/confirm", {
        code: confirmCode.trim(),
        ...credentialFields(credential)
      });
      setRecoveryCodes(res.recoveryCodes);
      setSavedAcknowledged(false);
      setSetup(null);
      setConfirmCode("");
      setConfirmPassword("");
      await refreshStatus();
    } catch (err) {
      setMessage(toErrorMessage(err, "Invalid code. Try again."));
    } finally {
      setBusy(false);
    }
  }

  async function submitDisable(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      // credentialFields sends only the form the account stores. Derived
      // against the caller's own session parameters — see api/auth.ts.
      const credential = await deriveCredential("", disablePassword);
      await postJSON<{ ok: boolean }>("/api/mfa/totp/disable", {
        ...credentialFields(credential)
      });
      setShowDisable(false);
      setDisablePassword("");
      setRecoveryCodes([]);
      setMessage("Two-factor authentication disabled.");
      await refreshStatus();
    } catch (err) {
      setMessage(toErrorMessage(err, "Failed to disable. Check your password."));
    } finally {
      setBusy(false);
    }
  }

  async function submitRegenerate(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      // credentialFields, like submitDisable twenty lines up and submitConfirm
      // above it. This was the one place in the whole frontend that posted a
      // bare account password, and it did not work: verifyAccountCredential
      // picks its verifier from what the ACCOUNT stores with no fallback, and
      // accounts convert to derived auth on first SPA sign-in — so a correct
      // plaintext password got a 401 on essentially every deployment. The
      // guaranteed failure then induced retries that re-sent the plaintext and
      // burned lockout strikes. On a client-protected account that plaintext
      // also derives the PGP key-wrapping key, which is the entire reason
      // authSecret.ts exists.
      const credential = await deriveCredential("", regeneratePassword);
      const res = await postJSON<ConfirmResponse>("/api/mfa/recovery-codes/regenerate", {
        ...credentialFields(credential)
      });
      setRecoveryCodes(res.recoveryCodes);
      setSavedAcknowledged(false);
      setShowRegenerate(false);
      setRegeneratePassword("");
      await refreshStatus();
    } catch (err) {
      setMessage(toErrorMessage(err, "Failed to regenerate. Check your password."));
    } finally {
      setBusy(false);
    }
  }

  function copyRecoveryCodes() {
    void navigator.clipboard?.writeText(recoveryCodes.join("\n"));
  }

  const showRecoveryPanel = recoveryCodes.length > 0;
  const totpOn = showRecoveryPanel || Boolean(status?.totpEnabled);

  return (
    <div className={`sec-card ${totpOn ? "sec-card-on" : ""}`}>
      <div className="sec-card-head">
        <p className="sec-eyebrow">Sign-in</p>
        <h3>Authenticator app</h3>
      </div>

      {showRecoveryPanel ? (
        <div className="sec-section">
          <h4>Save your recovery codes</h4>
          <p className="sec-muted">
            Store these one-time recovery codes somewhere safe. Each works once if you lose access to
            your authenticator. They will not be shown again.
          </p>
          <ul className="sec-codes">
            {recoveryCodes.map((code) => (
              <li key={code}>
                <code>{code}</code>
              </li>
            ))}
          </ul>
          <div className="sec-actions">
            <button type="button" className="sec-action-quiet" onClick={copyRecoveryCodes}>
              Copy codes
            </button>
          </div>
          <label className="sec-check">
            <input
              type="checkbox"
              checked={savedAcknowledged}
              onChange={(e) => setSavedAcknowledged(e.target.checked)}
            />
            I have saved these recovery codes
          </label>
          <div className="sec-actions">
            <button type="button" disabled={!savedAcknowledged} onClick={() => setRecoveryCodes([])}>
              Done
            </button>
          </div>
        </div>
      ) : status?.totpEnabled ? (
        <div className="sec-section">
          <p className="sec-muted">Recovery codes remaining: {status.recoveryCodesRemaining}</p>
          <div className="sec-actions">
            <button type="button" className="sec-action-quiet" onClick={() => setShowRegenerate(true)}>
              Regenerate recovery codes
            </button>
            <button type="button" className="sec-action-danger" onClick={() => setShowDisable(true)}>
              Disable two-factor auth
            </button>
          </div>

          {showRegenerate ? (
            <form onSubmit={submitRegenerate} className="auth-form sec-inline-form">
              <h4>Confirm your password</h4>
              <label>
                <div>Password</div>
                <input
                  type="password"
                  value={regeneratePassword}
                  onChange={(e) => setRegeneratePassword(e.target.value)}
                  autoComplete="current-password"
                />
              </label>
              <div className="sec-actions">
                <button type="submit" disabled={busy || regeneratePassword === ""}>
                  {busy ? "Working..." : "Regenerate"}
                </button>
                <button
                  type="button"
                  className="sec-action-quiet"
                  onClick={() => setShowRegenerate(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          ) : null}

          {showDisable ? (
            <form onSubmit={submitDisable} className="auth-form sec-inline-form">
              <h4>Confirm your password</h4>
              <label>
                <div>Password</div>
                <input
                  type="password"
                  value={disablePassword}
                  onChange={(e) => setDisablePassword(e.target.value)}
                  autoComplete="current-password"
                />
              </label>
              <div className="sec-actions">
                <button type="submit" className="sec-action-danger" disabled={busy || disablePassword === ""}>
                  {busy ? "Working..." : "Disable"}
                </button>
                <button
                  type="button"
                  className="sec-action-quiet"
                  onClick={() => setShowDisable(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          ) : null}
        </div>
      ) : setup ? (
        <form onSubmit={submitConfirm} className="auth-form sec-inline-form">
          <h4>Scan this code</h4>
          <p className="sec-muted">Scan it with your authenticator app, or enter the key by hand.</p>
          {qrDataUrl ? (
            <div className="sec-qr">
              <img src={qrDataUrl} alt="TOTP enrollment QR code" width={220} height={220} />
            </div>
          ) : null}
          <p className="sec-muted">
            Manual entry key: <span className="sec-secret">{setup.secret}</span>
          </p>
          <label>
            <div>Enter the 6-digit code to confirm</div>
            <input
              value={confirmCode}
              onChange={(e) => setConfirmCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
            />
          </label>
          <label>
            <div>Confirm your password</div>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              autoComplete="current-password"
            />
          </label>
          <div className="sec-actions">
            <button type="submit" disabled={busy || confirmCode.trim().length !== 6 || confirmPassword === ""}>
              {busy ? "Confirming..." : "Confirm and enable"}
            </button>
            <button type="button" className="sec-action-quiet" onClick={() => setSetup(null)}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div className="sec-section">
          <p className="sec-muted">Add an authenticator app as a second factor on sign-in.</p>
          <div className="sec-actions">
            <button type="button" disabled={busy} onClick={() => void beginSetup()}>
              {busy ? "Starting..." : "Enable 2FA"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
