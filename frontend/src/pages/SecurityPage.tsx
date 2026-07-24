import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import QRCode from "qrcode";
import { getJSON, postJSON, putJSON, toErrorMessage } from "../api/client";
import {
  getPGPIdentity,
  generatePGPIdentity,
  importPGPIdentity,
  deletePGPIdentity,
  getPGPDiscoverySettings,
  updatePGPDiscoverySettings,
  listDiscoverySuppressions,
  removeDiscoverySuppression,
  type PGPIdentity,
  type DiscoverySettings,
  type DiscoverySuppression
} from "../api/pgp";
import { listContacts, type Contact } from "../api/contacts";

type ApproverDevice = {
  deviceId: string;
  deviceName?: string;
  platform?: string;
  approver: boolean;
};

type MfaStatus = {
  totpEnabled: boolean;
  recoveryCodesRemaining: number;
  pushMfaEnabled: boolean;
  approverDevices: ApproverDevice[];
};

type SetupResponse = {
  secret: string;
  otpauthUri: string;
};

type ConfirmResponse = {
  ok: boolean;
  recoveryCodes: string[];
};

export function SecurityPage() {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  // Enrollment state.
  const [setup, setSetup] = useState<SetupResponse | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [confirmCode, setConfirmCode] = useState("");

  // Recovery-code display (shown once after confirm or regenerate).
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [savedAcknowledged, setSavedAcknowledged] = useState(false);

  // Password-confirm modals.
  const [disablePassword, setDisablePassword] = useState("");
  const [showDisable, setShowDisable] = useState(false);
  const [regeneratePassword, setRegeneratePassword] = useState("");
  const [showRegenerate, setShowRegenerate] = useState(false);

  // PGP identity state.
  const [pgpIdentity, setPgpIdentity] = useState<PGPIdentity | null>(null);
  const [pgpLoading, setPgpLoading] = useState(true);
  const [pgpBusy, setPgpBusy] = useState(false);
  const [pgpStatus, setPgpStatus] = useState("");
  const [pgpImportOpen, setPgpImportOpen] = useState(false);
  const [pgpImportKey, setPgpImportKey] = useState("");
  const [pgpImportPassphrase, setPgpImportPassphrase] = useState("");
  const [selfContact, setSelfContact] = useState<Contact | null>(null);

  // PGP key-discovery settings.
  const [discoverySettings, setDiscoverySettings] = useState<DiscoverySettings | null>(null);
  const [discoveryBusy, setDiscoveryBusy] = useState(false);
  const [discoveryStatus, setDiscoveryStatus] = useState("");
  const [suppressions, setSuppressions] = useState<DiscoverySuppression[]>([]);

  useEffect(() => {
    let cancelled = false;
    getPGPDiscoverySettings()
      .then((settings) => {
        if (!cancelled) setDiscoverySettings(settings);
      })
      .catch(() => {
        if (!cancelled) setDiscoverySettings(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    listDiscoverySuppressions()
      .then((r) => {
        if (!cancelled) setSuppressions(r.suppressions);
      })
      .catch(() => {
        if (!cancelled) setSuppressions([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function allowDiscoveryAgain(email: string) {
    try {
      await removeDiscoverySuppression(email);
      setSuppressions((prev) => prev.filter((s) => s.email !== email));
    } catch {
      setDiscoveryStatus("Failed to update discovery opt-outs.");
    }
  }

  async function updateDiscoverySetting(patch: Partial<DiscoverySettings>) {
    if (!discoverySettings) return;
    const next = { ...discoverySettings, ...patch };
    setDiscoverySettings(next);
    setDiscoveryBusy(true);
    setDiscoveryStatus("");
    try {
      const saved = await updatePGPDiscoverySettings(next);
      setDiscoverySettings(saved);
    } catch (e) {
      setDiscoverySettings(discoverySettings);
      setDiscoveryStatus(`Failed to save: ${toErrorMessage(e, "unknown error")}`);
    } finally {
      setDiscoveryBusy(false);
    }
  }

  useEffect(() => {
    let cancelled = false;
    getPGPIdentity()
      .then((id) => {
        if (!cancelled) setPgpIdentity(id);
      })
      .catch(() => {
        if (!cancelled) setPgpIdentity(null);
      })
      .finally(() => {
        if (!cancelled) setPgpLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    listContacts()
      .then((all) => {
        if (!cancelled) setSelfContact(all.find((c) => c.isSelf) ?? null);
      })
      .catch(() => {
        if (!cancelled) setSelfContact(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleGeneratePGPIdentity() {
    setPgpBusy(true);
    setPgpStatus("");
    try {
      const id = await generatePGPIdentity();
      setPgpIdentity(id);
      setPgpStatus("New PGP identity generated.");
    } catch (e) {
      setPgpStatus(`Failed to generate identity: ${toErrorMessage(e, "unknown error")}`);
    } finally {
      setPgpBusy(false);
    }
  }

  async function handleImportPGPIdentity(e: FormEvent) {
    e.preventDefault();
    setPgpBusy(true);
    setPgpStatus("");
    try {
      const id = await importPGPIdentity(pgpImportKey, pgpImportPassphrase);
      setPgpIdentity(id);
      setPgpImportOpen(false);
      setPgpImportKey("");
      setPgpImportPassphrase("");
      setPgpStatus("PGP identity imported.");
    } catch (e) {
      setPgpStatus(`Failed to import identity: ${toErrorMessage(e, "unknown error")}`);
    } finally {
      setPgpBusy(false);
    }
  }

  async function handleDeletePGPIdentity() {
    if (!window.confirm("Delete your PGP identity? Mail encrypted to you will no longer be readable.")) {
      return;
    }
    setPgpBusy(true);
    setPgpStatus("");
    try {
      await deletePGPIdentity();
      setPgpIdentity(null);
      setPgpStatus("PGP identity deleted.");
    } catch (e) {
      setPgpStatus(`Failed to delete identity: ${toErrorMessage(e, "unknown error")}`);
    } finally {
      setPgpBusy(false);
    }
  }

  async function refreshStatus() {
    try {
      const res = await getJSON<MfaStatus>("/api/mfa/status");
      setStatus(res);
    } catch (err) {
      setMessage(toErrorMessage(err, "Failed to load security status."));
    }
  }

  useEffect(() => {
    void refreshStatus();
  }, []);

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
      const res = await postJSON<ConfirmResponse>("/api/mfa/totp/confirm", {
        code: confirmCode.trim()
      });
      setRecoveryCodes(res.recoveryCodes);
      setSavedAcknowledged(false);
      setSetup(null);
      setConfirmCode("");
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
      await postJSON<{ ok: boolean }>("/api/mfa/totp/disable", { password: disablePassword });
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
      const res = await postJSON<ConfirmResponse>("/api/mfa/recovery-codes/regenerate", {
        password: regeneratePassword
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

  async function togglePush(enabled: boolean) {
    setBusy(true);
    setMessage("");
    try {
      await putJSON<{ ok: boolean; pushMfaEnabled: boolean }>("/api/mfa/push/enabled", { enabled });
      await refreshStatus();
    } catch (err) {
      setMessage(toErrorMessage(err, "Failed to update push approval."));
    } finally {
      setBusy(false);
    }
  }

  async function toggleApprover(deviceId: string, approver: boolean) {
    setBusy(true);
    setMessage("");
    try {
      await putJSON<{ ok: boolean }>(
        `/api/notifications/native/devices/${encodeURIComponent(deviceId)}/mfa`,
        { approver }
      );
      await refreshStatus();
    } catch (err) {
      setMessage(toErrorMessage(err, "Failed to update device."));
    } finally {
      setBusy(false);
    }
  }

  function copyRecoveryCodes() {
    void navigator.clipboard?.writeText(recoveryCodes.join("\n"));
  }

  const showRecoveryPanel = recoveryCodes.length > 0;
  const totpOn = showRecoveryPanel || Boolean(status?.totpEnabled);
  const messageTone = message.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

  return (
    <section className="panel security-page">
      <header className="security-header">
        <h2>Security</h2>
        <p>Protect your account with an authenticator app, and optionally approve sign-ins from a paired device.</p>
      </header>

      {message ? <p className={messageTone}>{message}</p> : null}

      <div className="security-layout">
        <div className="security-card">
          <div className="security-card-head">
            <h3>Authenticator app (TOTP)</h3>
            <span className={`security-badge ${totpOn ? "security-badge-on" : "security-badge-off"}`}>
              <span className="security-dot" aria-hidden="true" />
              {totpOn ? "enabled" : "not enabled"}
            </span>
          </div>

          {showRecoveryPanel ? (
            <div className="security-section">
              <h4>Save your recovery codes</h4>
              <p className="security-muted">
                Store these one-time recovery codes somewhere safe. Each works once if you lose access to
                your authenticator. They will not be shown again.
              </p>
              <ul className="security-codes">
                {recoveryCodes.map((code) => (
                  <li key={code}>
                    <code>{code}</code>
                  </li>
                ))}
              </ul>
              <div className="security-actions">
                <button type="button" onClick={copyRecoveryCodes}>
                  Copy codes
                </button>
              </div>
              <label className="security-check">
                <input
                  type="checkbox"
                  checked={savedAcknowledged}
                  onChange={(e) => setSavedAcknowledged(e.target.checked)}
                />
                I have saved these recovery codes
              </label>
              <div className="security-actions">
                <button type="button" disabled={!savedAcknowledged} onClick={() => setRecoveryCodes([])}>
                  Done
                </button>
              </div>
            </div>
          ) : status?.totpEnabled ? (
            <div className="security-section">
              <p className="security-muted">Recovery codes remaining: {status.recoveryCodesRemaining}</p>
              <div className="security-actions">
                <button type="button" onClick={() => setShowRegenerate(true)}>
                  Regenerate recovery codes
                </button>
                <button type="button" className="security-action-danger" onClick={() => setShowDisable(true)}>
                  Disable two-factor auth
                </button>
              </div>

              {showRegenerate ? (
                <form onSubmit={submitRegenerate} className="auth-form security-inline-form">
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
                  <div className="security-actions">
                    <button type="submit" disabled={busy || regeneratePassword === ""}>
                      {busy ? "Working..." : "Regenerate"}
                    </button>
                    <button type="button" className="nav-link-button" onClick={() => setShowRegenerate(false)}>
                      Cancel
                    </button>
                  </div>
                </form>
              ) : null}

              {showDisable ? (
                <form onSubmit={submitDisable} className="auth-form security-inline-form">
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
                  <div className="security-actions">
                    <button type="submit" disabled={busy || disablePassword === ""}>
                      {busy ? "Working..." : "Disable"}
                    </button>
                    <button type="button" className="nav-link-button" onClick={() => setShowDisable(false)}>
                      Cancel
                    </button>
                  </div>
                </form>
              ) : null}
            </div>
          ) : setup ? (
            <form onSubmit={submitConfirm} className="auth-form security-inline-form">
              <h4>Scan this QR code</h4>
              <p className="security-muted">Scan with your authenticator app, or enter the key manually.</p>
              {qrDataUrl ? (
                <img src={qrDataUrl} alt="TOTP enrollment QR code" width={220} height={220} />
              ) : null}
              <p className="security-muted">
                Manual entry key: <code>{setup.secret}</code>
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
              <div className="security-actions">
                <button type="submit" disabled={busy || confirmCode.trim().length !== 6}>
                  {busy ? "Confirming..." : "Confirm and enable"}
                </button>
                <button type="button" className="nav-link-button" onClick={() => setSetup(null)}>
                  Cancel
                </button>
              </div>
            </form>
          ) : (
            <div className="security-section">
              <p className="security-muted">Add an authenticator app as a second factor on sign-in.</p>
              <div className="security-actions">
                <button type="button" disabled={busy} onClick={() => void beginSetup()}>
                  {busy ? "Starting..." : "Enable 2FA"}
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="security-card">
          <div className="security-card-head">
            <h3>Push approval</h3>
            <span
              className={`security-badge ${status?.pushMfaEnabled ? "security-badge-on" : "security-badge-off"}`}
            >
              <span className="security-dot" aria-hidden="true" />
              {status?.pushMfaEnabled ? "enabled" : "not enabled"}
            </span>
          </div>

          {!status?.totpEnabled ? (
            <p className="security-muted">
              Enable an authenticator app (TOTP) above first. Push approval always keeps TOTP as a
              fallback, so it can only be turned on once TOTP is active.
            </p>
          ) : (
            <div className="security-section">
              <p className="security-muted">
                Approve sign-ins from a paired device. You can still use your authenticator code at any
                time.
              </p>
              <label className="security-check">
                <input
                  type="checkbox"
                  checked={Boolean(status?.pushMfaEnabled)}
                  disabled={busy}
                  onChange={(e) => void togglePush(e.target.checked)}
                />
                Enable push approval
              </label>
              {status && status.approverDevices.length > 0 ? (
                <ul className="security-devices">
                  {status.approverDevices.map((device) => (
                    <li key={device.deviceId}>
                      <label className="security-check">
                        <input
                          type="checkbox"
                          checked={device.approver}
                          disabled={busy}
                          onChange={(e) => void toggleApprover(device.deviceId, e.target.checked)}
                        />
                        {device.deviceName?.trim() || device.platform || device.deviceId} — may approve
                        sign-ins
                      </label>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="security-muted">
                  No paired devices yet. Pair a device on the Notifications page to use push approval.
                </p>
              )}
            </div>
          )}
        </div>

        <div className="security-card">
          <div className="security-card-head">
            <h3>Email Encryption (PGP)</h3>
            <span className={`security-badge ${pgpIdentity ? "security-badge-on" : "security-badge-off"}`}>
              <span className="security-dot" aria-hidden="true" />
              {pgpIdentity ? "configured" : "not configured"}
            </span>
          </div>
          {pgpLoading ? (
            <p className="contacts-muted">Loading...</p>
          ) : pgpIdentity ? (
            <>
              <p className="contacts-pgp-fingerprint">
                Fingerprint: {pgpIdentity.fingerprint} · Source: {pgpIdentity.source}
              </p>
              <p className="contacts-muted">
                {selfContact ? (
                  <>Sharing contact card: {selfContact.fn} · <Link to="/contacts">Manage in Contacts</Link></>
                ) : (
                  <>No contact card set — <Link to="/contacts">add one in Contacts</Link> and mark it as yours to include it when sharing your PGP key.</>
                )}
              </p>
              <details>
                <summary className="contacts-muted">Show public key</summary>
                <pre className="contact-details-notes">{pgpIdentity.publicKey}</pre>
              </details>
              <button type="button" onClick={() => void handleDeletePGPIdentity()} disabled={pgpBusy}>
                Delete identity
              </button>
            </>
          ) : (
            <>
              <button type="button" onClick={() => void handleGeneratePGPIdentity()} disabled={pgpBusy}>
                Generate new identity
              </button>
              <button type="button" onClick={() => setPgpImportOpen(!pgpImportOpen)} disabled={pgpBusy}>
                Import existing key
              </button>
              {pgpImportOpen ? (
                <form onSubmit={(e) => void handleImportPGPIdentity(e)}>
                  <label>
                    <div>Armored private key</div>
                    <textarea
                      value={pgpImportKey}
                      onChange={(e) => setPgpImportKey(e.target.value)}
                      rows={4}
                      placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
                      required
                    />
                  </label>
                  <label>
                    <div>Passphrase (leave blank if none)</div>
                    <input
                      type="password"
                      value={pgpImportPassphrase}
                      onChange={(e) => setPgpImportPassphrase(e.target.value)}
                    />
                  </label>
                  <button type="submit" disabled={pgpBusy}>Import</button>
                </form>
              ) : null}
            </>
          )}
          {pgpStatus ? <p className="contacts-muted">{pgpStatus}</p> : null}

          {discoverySettings ? (
            <div className="security-section">
              <h4>Key discovery</h4>
              <label className="security-check">
                <input
                  type="checkbox"
                  checked={discoverySettings.autoEncryptWhenKeyKnown}
                  disabled={discoveryBusy}
                  onChange={(e) => void updateDiscoverySetting({ autoEncryptWhenKeyKnown: e.target.checked })}
                />
                Encrypt automatically when I have a recipient's key
              </label>
              <label className="security-check">
                <input
                  type="checkbox"
                  checked={discoverySettings.storeDiscoveredKeys}
                  disabled={discoveryBusy}
                  onChange={(e) => void updateDiscoverySetting({ storeDiscoveredKeys: e.target.checked })}
                />
                Save keys I discover to my contacts
              </label>
              <label className="security-check">
                <input
                  type="checkbox"
                  checked={discoverySettings.advertiseAutocrypt}
                  disabled={discoveryBusy}
                  onChange={(e) => void updateDiscoverySetting({ advertiseAutocrypt: e.target.checked })}
                />
                Advertise my public key on outgoing mail (Autocrypt)
              </label>
              <p className="security-muted">
                Adds an Autocrypt header so people you email can automatically discover your key. On by
                default.
              </p>
              {discoveryStatus ? <p className="contacts-muted">{discoveryStatus}</p> : null}
              {suppressions.length > 0 ? (
                <div className="security-subsection">
                  <h5>Discovery opt-outs</h5>
                  <ul className="security-list">
                    {suppressions.map((s) => (
                      <li key={s.email}>
                        <span>
                          {s.email} <span className="contacts-muted">({s.reason})</span>
                        </span>
                        <button type="button" onClick={() => void allowDiscoveryAgain(s.email)}>
                          Allow discovery again
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </section>
  );
}
