import { FormEvent, useEffect, useState } from "react";
import QRCode from "qrcode";
import { getJSON, postJSON, toErrorMessage } from "../../../api/client";
import { credentialFields, deriveCredential } from "../../../api/auth";
import { useAuth } from "../../../auth";
import type { MfaStatus, TotpSetup } from "../types";
import { Password } from "./Password";

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
  // The in-progress TOTP enrollment secret from POST /api/mfa/totp/setup —
  // shown once (as a QR code and a manual-entry key) and never re-fetchable;
  // asking again mints a DIFFERENT secret. Lifted to SecurityPage for the
  // same reason recoveryCodes and MailKeys' recoverySecret are: the tab
  // strip can unmount this component while the user is mid-scan, and a local
  // copy would be silently destroyed by a trip to Devices and back, leaving
  // an orphan entry in the user's authenticator app for a secret the server
  // will no longer accept.
  setup?: TotpSetup | null;
  setSetup?: (setup: TotpSetup | null) => void;
};

export function SignIn({
  status = null,
  refreshStatus = noopAsync,
  recoveryCodes = [],
  setRecoveryCodes = noop,
  setMessage = noop,
  setup = null,
  setSetup = noop
}: SignInProps = {}) {
  const [busy, setBusy] = useState(false);

  const auth = useAuth();
  const [ssoConfig, setSSOConfig] = useState<{ enabled: boolean; issuerUrl: string } | null>(null);
  // A failed config read used to render exactly like "SSO is switched off":
  // the card disappeared. For an account that HAS a linked identity that also
  // takes away the unlink control, so the failure has to be visible.
  const [ssoConfigError, setSSOConfigError] = useState("");

  // Enrollment state.
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
  const [linkPassword, setLinkPassword] = useState("");
  const [linkCode, setLinkCode] = useState("");

  useEffect(() => {
    getJSON<{ enabled: boolean; issuerUrl: string }>("/api/auth/sso-config")
      .then((res) => {
        setSSOConfig(res);
        setSSOConfigError("");
      })
      .catch((error: unknown) => setSSOConfigError(toErrorMessage(error, "unknown error")));
  }, []);

  // Linking is a POST, not a link, because the server gates it on a re-entered
  // credential (and the second factor, when one is enrolled) before it will
  // authorize the redirect — a session alone used to be enough to bind a
  // directory identity to this account. The server answers with the provider
  // URL to navigate to; it cannot redirect us itself from a fetch.
  async function submitLinkSSO(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const credential = await deriveCredential("", linkPassword);
      const res = await postJSON<{ authorizeUrl: string }>("/api/settings/sso/link", {
        code: linkCode.trim(),
        ...credentialFields(credential)
      });
      setLinkPassword("");
      setLinkCode("");
      window.location.href = res.authorizeUrl;
    } catch (err) {
      setMessage(toErrorMessage(err, "Failed to start SSO linking. Check your password."));
      setBusy(false);
    }
  }

  async function unlinkSSO() {
    if (!confirm("Are you sure you want to unlink your SSO account?")) return;
    setBusy(true);
    try {
      await postJSON("/api/settings/sso/unlink", {});
      setMessage("SSO identity unlinked.");
      window.location.reload();
    } catch (err) {
      setMessage(toErrorMessage(err, "Failed to unlink SSO account."));
    } finally {
      setBusy(false);
    }
  }

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
      const res = await postJSON<TotpSetup>("/api/mfa/totp/setup", {});
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
    <>
      {/* Credentials before factors: "what I know" reads ahead of "what I
          also have" for someone here to lock the account down. */}
      <Password />

      {ssoConfigError ? (
        <div className="sec-card">
          <div className="sec-card-head">
            <p className="sec-eyebrow">Single Sign-On</p>
            <h3>KySignOn / OpenID Connect</h3>
          </div>
          <div className="sec-section">
            <p className="sec-muted">
              Single Sign-On settings could not be loaded ({ssoConfigError}). This is not the same
              as SSO being switched off — reload to try again.
            </p>
          </div>
        </div>
      ) : null}

      {ssoConfig?.enabled ? (
        <div className={`sec-card ${auth.ssoSub ? "sec-card-on" : ""}`}>
          <div className="sec-card-head">
            <p className="sec-eyebrow">Single Sign-On</p>
            <h3>KySignOn / OpenID Connect</h3>
          </div>
          <div className="sec-section">
            {auth.ssoSub ? (
              <div>
                <p className="sec-muted" style={{ marginBottom: "0.75rem" }}>
                  Your KyPost mailbox is paired to your central SSO identity.
                </p>
                <div
                  style={{
                    background: "rgba(77, 238, 234, 0.08)",
                    border: "1px solid rgba(77, 238, 234, 0.3)",
                    borderRadius: "6px",
                    padding: "0.75rem 1rem",
                    marginBottom: "1rem",
                  }}
                >
                  <strong style={{ color: "#4deeea" }}>SSO Identity Linked</strong>
                  <div className="sec-muted" style={{ fontSize: "0.85rem", marginTop: "0.25rem" }}>
                    Account: <code>{auth.ssoUsername || "Unknown"}</code>{" "}
                    {auth.ssoEmail ? `(${auth.ssoEmail})` : ""}<br />
                    Subject: <code>{auth.ssoSub}</code>
                  </div>
                </div>
                <div className="sec-actions">
                  <button
                    type="button"
                    className="sec-action-quiet"
                    style={{ color: "#ef4444", borderColor: "rgba(239, 68, 68, 0.4)" }}
                    disabled={busy}
                    onClick={unlinkSSO}
                  >
                    Unlink SSO Account
                  </button>
                </div>
              </div>
            ) : (
              <div>
                <p className="sec-muted" style={{ marginBottom: "0.75rem" }}>
                  Connect your central KySignOn / Authentik identity for 1-click single sign-on.
                </p>
                <form onSubmit={submitLinkSSO}>
                  <div>Confirm your password</div>
                  <input
                    type="password"
                    value={linkPassword}
                    onChange={(e) => setLinkPassword(e.target.value)}
                    autoComplete="current-password"
                    required
                  />
                  {status?.totpEnabled ? (
                    <>
                      <div>Two-factor code</div>
                      <input
                        type="text"
                        value={linkCode}
                        onChange={(e) => setLinkCode(e.target.value)}
                        autoComplete="one-time-code"
                        inputMode="numeric"
                        required
                      />
                    </>
                  ) : null}
                  <div className="sec-actions">
                    <button
                      type="submit"
                      className="button"
                      disabled={busy}
                      style={{
                        background: "#4deeea",
                        color: "#0d0f14",
                        fontWeight: 600,
                        borderRadius: "4px",
                        padding: "0.5rem 1rem",
                      }}
                    >
                      Link SSO Identity
                    </button>
                  </div>
                </form>
              </div>
            )}
          </div>
        </div>
      ) : null}

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
    </>
  );
}
