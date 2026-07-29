import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router";
import QRCode from "qrcode";
import { getJSON, postJSON, putJSON, toErrorMessage } from "../api/client";
import { deriveCredential } from "../api/auth";
import {
  getPGPIdentity,
  generatePGPIdentity,
  deletePGPIdentity,
  storeClientPGPIdentity,
  exportLegacyPGPKey,
  getPGPDiscoverySettings,
  updatePGPDiscoverySettings,
  listDiscoverySuppressions,
  removeDiscoverySuppression,
  type PGPIdentity,
  type DiscoverySettings,
  type DiscoverySuppression
} from "../api/pgp";
import { generateIdentity, importIdentity } from "../lib/pgpClient";
import { wrapPrivateKey } from "../lib/keyVault";
import {
  lockPGPSession,
  loadPGPSession,
  rewrapUnlockedKeyUnder,
  subscribePGPSession,
  unlockPGPSession,
  type PGPSessionState
} from "../lib/pgpSession";
import { unlockWithArmoredKey } from "../lib/keyVault";
import { PgpUnlockDialog } from "../components/PgpUnlockDialog";
import { listContacts, type Contact } from "../api/contacts";

type ApproverDevice = {
  deviceId: string;
  deviceName?: string;
  platform?: string;
  approver: boolean;
  // Absent on older servers, which had no notion of an ineligible transport.
  // Treat undefined as eligible so this page keeps working against one.
  canApprove?: boolean;
  cannotApproveReason?: string;
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
  // Which side of the "can my phone read this" question the user picked; false keeps the key
  // in the browser, which is the mode nothing should downgrade away from by accident.
  const [pgpReadOnMobile, setPgpReadOnMobile] = useState(false);
  const [pgpImportKey, setPgpImportKey] = useState("");
  const [pgpImportPassphrase, setPgpImportPassphrase] = useState("");
  // Cold-start PGP state (protection mode, wrapped key, unlock status).
  const [pgpSession, setPgpSession] = useState<PGPSessionState | null>(null);
  const [unlockOpen, setUnlockOpen] = useState(false);
  const [migratePassword, setMigratePassword] = useState("");
  const [migrateOpen, setMigrateOpen] = useState(false);

  // Stale-envelope recovery: the stored PGP envelope is sealed under an OLDER
  // password than the account's, so nothing can open it with the current one.
  // Two passwords are needed to fix it — the old one to unlock, the current one
  // to re-seal.
  const [recoverOpen, setRecoverOpen] = useState(false);
  const [recoverOldPassword, setRecoverOldPassword] = useState("");
  const [recoverCurrentPassword, setRecoverCurrentPassword] = useState("");
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

  // Subscribe to the shared PGP session so this page and the rest of the app
  // agree on protection mode and lock state.
  useEffect(() => subscribePGPSession(setPgpSession), []);
  useEffect(() => {
    void loadPGPSession();
  }, []);

  /**
   * Generates the keypair in the browser and uploads only the public half
   * plus an envelope wrapped under the account password. The server never
   * sees the private key, which is the whole point — so this needs the
   * password here, at creation, not just a session.
   */
  async function handleGeneratePGPIdentity() {
    const password = window.prompt(
      "Enter your account password.\n\nYour new private key will be encrypted with it before it leaves this browser. " +
        "This server will not be able to decrypt it — keep a backup of the key."
    );
    if (!password) {
      return;
    }
    setPgpBusy(true);
    setPgpStatus("");
    try {
      // Addresses come from the server, which knows the IMAP account address
      // and every verified send-as alias. Guessing here would mint a key that
      // WKD and Autocrypt then refuse to serve.
      const session = await loadPGPSession();
      const addresses = session.bootstrap?.suggestedUserIDs ?? [];
      if (addresses.length === 0) {
        setPgpStatus("Configure your mail account first — the key needs your email address as its User ID.");
        return;
      }
      const name = selfContact?.fn?.trim() || session.bootstrap?.displayName || "KyPost user";
      const generated = await generateIdentity(name, addresses[0], addresses.slice(1));
      const wrapped = await wrapPrivateKey(generated.armoredPrivateKey, password);
      const id = await storeClientPGPIdentity(generated.armoredPublicKey, JSON.stringify(wrapped), "generated");
      // Hold the fresh key for this page so the user is not immediately asked
      // to unlock a key they just made.
      unlockWithArmoredKey(generated.armoredPrivateKey);
      setPgpIdentity(id);
      await loadPGPSession();
      setPgpStatus("New PGP identity generated. Back up your key: an admin password reset makes it unrecoverable.");
    } catch (e) {
      setPgpStatus(`Failed to generate identity: ${toErrorMessage(e, "unknown error")}`);
    } finally {
      setPgpBusy(false);
    }
  }

  /**
   * The other branch of the mobile question: the server generates and keeps the
   * key, so it can decrypt for paired devices.
   *
   * This is a real reduction in protection, not a convenience toggle, so it is
   * never the default and never described as end-to-end. Claiming end-to-end
   * while holding the key is the exact defect this whole mode split exists to
   * close — see docs/E2E_PGP.md.
   */
  async function handleGenerateServerPGPIdentity() {
    if (
      !window.confirm(
        "Generate a key this server holds?\n\n" +
          "This server will be able to read every message encrypted to you, and so will anyone " +
          "who gains access to it or its backups. Choose this only if reading encrypted mail on " +
          "your phone matters more than keeping it from the server."
      )
    ) {
      return;
    }
    setPgpBusy(true);
    setPgpStatus("");
    try {
      const id = await generatePGPIdentity();
      setPgpIdentity(id);
      await loadPGPSession();
      setPgpStatus("PGP identity generated. This server holds the key and can read your encrypted mail.");
    } catch (e) {
      setPgpStatus(`Failed to generate identity: ${toErrorMessage(e, "unknown error")}`);
    } finally {
      setPgpBusy(false);
    }
  }

  /**
   * Migrates a legacy server-held key: the server hands it back once (after
   * re-verifying the password), the browser rewraps it, and the
   * server-readable copy is deleted by the upload.
   */
  async function handleMigrateToClientProtection(e: FormEvent) {
    e.preventDefault();
    setPgpBusy(true);
    setPgpStatus("");
    try {
      const exported = await exportLegacyPGPKey(migratePassword);
      const wrapped = await wrapPrivateKey(exported.privateKey, migratePassword);
      const id = await storeClientPGPIdentity(exported.publicKey, JSON.stringify(wrapped), "imported");
      unlockWithArmoredKey(exported.privateKey);
      setPgpIdentity(id);
      setMigrateOpen(false);
      setMigratePassword("");
      await loadPGPSession();
      setPgpStatus(
        "Migrated. This server can no longer read your encrypted mail. Back up your key — an admin password reset now makes it unrecoverable."
      );
    } catch (err) {
      setPgpStatus(`Migration failed: ${toErrorMessage(err, "unknown error")}`);
    } finally {
      setPgpBusy(false);
    }
  }

  /**
   * Recovers a PGP envelope that is out of step with the account password.
   *
   * This is reachable when a password change committed but the matching rewrap
   * did not — which used to be a permanent loss. The rewrap was a second HTTP
   * request fired after the password write, so a dropped connection between them
   * left the envelope sealed under a password the user no longer had, and every
   * rewrap path re-derived from the CURRENT password and therefore could never
   * open it. The only escape was deleting the identity, losing every message ever
   * encrypted to it.
   *
   * The two writes are atomic now (one request — see LoginPage), so this should
   * never be needed again. It exists for accounts already stranded by the old
   * flow, and because "should never happen" is not a recovery plan.
   */
  async function handleRecoverStaleEnvelope(e: FormEvent) {
    e.preventDefault();
    setPgpBusy(true);
    setPgpStatus("");
    try {
      // Unlock with the OLD password — this only touches memory.
      await unlockPGPSession(recoverOldPassword);
      // Then re-seal under the current one and upload.
      await rewrapUnlockedKeyUnder(recoverCurrentPassword);
      setRecoverOpen(false);
      setRecoverOldPassword("");
      setRecoverCurrentPassword("");
      setPgpStatus("Your PGP key is re-encrypted under your current password.");
    } catch (err) {
      setPgpStatus(
        `Recovery failed: ${toErrorMessage(err, "unknown error")}. Check that the first password is the one your key was last encrypted under.`
      );
    } finally {
      setPgpBusy(false);
    }
  }

  async function handleImportPGPIdentity(e: FormEvent) {
    e.preventDefault();
    setPgpBusy(true);
    setPgpStatus("");
    try {
      const password = window.prompt(
        "Enter your account password.\n\nThe imported key will be encrypted with it before it leaves this browser."
      );
      if (!password) {
        return;
      }
      // The key's own passphrase (if any) only unlocks it for the import; it
      // is then rewrapped under the account password, so the user has one
      // secret to remember rather than two.
      const imported = await importIdentity(pgpImportKey, pgpImportPassphrase);
      const wrapped = await wrapPrivateKey(imported.armoredPrivateKey, password);
      const id = await storeClientPGPIdentity(imported.armoredPublicKey, JSON.stringify(wrapped), "imported");
      unlockWithArmoredKey(imported.armoredPrivateKey);
      setPgpIdentity(id);
      setPgpImportOpen(false);
      setPgpImportKey("");
      setPgpImportPassphrase("");
      await loadPGPSession();
      setPgpStatus("PGP identity imported and encrypted with your account password.");
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
      // Both forms: the server checks whichever the account stores. Derived
      // against the caller's own session parameters — see api/auth.ts.
      const { authSecret } = await deriveCredential("", disablePassword);
      await postJSON<{ ok: boolean }>("/api/mfa/totp/disable", {
        password: disablePassword,
        authSecret
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
                  {status.approverDevices.map((device) => {
                    // Older servers omit canApprove entirely; undefined means
                    // eligible, so this page degrades cleanly against one.
                    const eligible = device.canApprove !== false;
                    const name = device.deviceName?.trim() || device.platform || device.deviceId;
                    return (
                      <li key={device.deviceId}>
                        <label className="security-check">
                          <input
                            type="checkbox"
                            checked={eligible && device.approver}
                            disabled={busy || !eligible}
                            onChange={(e) => void toggleApprover(device.deviceId, e.target.checked)}
                          />
                          {name} — {eligible ? "may approve sign-ins" : "cannot approve sign-ins"}
                        </label>
                        {!eligible && (
                          <p className="security-muted">
                            {device.cannotApproveReason ||
                              "This device's push delivery cannot carry sign-in approvals. Mail notifications still work."}
                          </p>
                        )}
                      </li>
                    );
                  })}
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

              {pgpSession?.bootstrap?.protection === "client" ? (
                <div className="security-section">
                  <span className="security-badge security-badge-on">
                    <span className="security-dot" aria-hidden="true" />
                    End-to-end: this server cannot read your encrypted mail
                  </span>
                  <p className="contacts-muted">
                    Your private key is encrypted with your account password and unlocked only in this browser tab.{" "}
                    {pgpSession.unlocked ? "It is unlocked for this session." : "It is locked — you will be asked for your password when you open or send encrypted mail."}
                  </p>
                  <p className="contacts-muted">
                    <strong>Keep a backup of your key.</strong> Because the server cannot open it, an admin password
                    reset makes it permanently unrecoverable along with every message encrypted to it.
                  </p>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    {pgpSession.unlocked ? (
                      <button type="button" className="contacts-action" onClick={() => lockPGPSession()}>
                        Lock key
                      </button>
                    ) : (
                      <button type="button" onClick={() => setUnlockOpen(true)}>
                        Unlock key
                      </button>
                    )}
                    <button type="button" className="contacts-action" onClick={() => setRecoverOpen((v) => !v)}>
                      Key won&apos;t unlock?
                    </button>
                  </div>
                  {recoverOpen ? (
                    <form onSubmit={(e) => void handleRecoverStaleEnvelope(e)}>
                      <p className="contacts-muted">
                        If your key stopped opening with your current password, a past password change saved only
                        half-way. Enter the password your key was last encrypted under, plus your current one, and it
                        will be re-encrypted to match.
                      </p>
                      <label>
                        <div>Password your key was last encrypted under</div>
                        <input
                          type="password"
                          autoComplete="off"
                          value={recoverOldPassword}
                          onChange={(e) => setRecoverOldPassword(e.target.value)}
                        />
                      </label>
                      <label>
                        <div>Your current account password</div>
                        <input
                          type="password"
                          autoComplete="current-password"
                          value={recoverCurrentPassword}
                          onChange={(e) => setRecoverCurrentPassword(e.target.value)}
                        />
                      </label>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        <button
                          type="submit"
                          disabled={pgpBusy || recoverOldPassword === "" || recoverCurrentPassword === ""}
                        >
                          Re-encrypt key
                        </button>
                        <button type="button" className="contacts-action" onClick={() => setRecoverOpen(false)}>
                          Cancel
                        </button>
                      </div>
                    </form>
                  ) : null}
                </div>
              ) : pgpSession?.bootstrap?.migrationAvailable ? (
                <div className="security-section">
                  <span className="security-badge security-badge-off">
                    <span className="security-dot" aria-hidden="true" />
                    This server can read your encrypted mail
                  </span>
                  <p className="contacts-muted">
                    Your private key is stored on this server, encrypted with a key kept on the same machine. Anyone
                    with access to the server or its backups can decrypt everything you have received. Migrating moves
                    the key under your account password so only your browser can open it.
                  </p>
                  <p className="contacts-muted">
                    After migrating, an admin password reset will make the key unrecoverable — export a backup first.
                  </p>
                  {migrateOpen ? (
                    <form onSubmit={(e) => void handleMigrateToClientProtection(e)}>
                      <label>
                        <div>Confirm your account password</div>
                        <input
                          type="password"
                          autoComplete="current-password"
                          value={migratePassword}
                          onChange={(e) => setMigratePassword(e.target.value)}
                          required
                        />
                      </label>
                      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                        <button type="submit" disabled={pgpBusy || migratePassword.length === 0}>
                          {pgpBusy ? "Migrating…" : "Migrate to end-to-end"}
                        </button>
                        <button
                          type="button"
                          className="contacts-action"
                          onClick={() => {
                            setMigrateOpen(false);
                            setMigratePassword("");
                          }}
                          disabled={pgpBusy}
                        >
                          Cancel
                        </button>
                      </div>
                    </form>
                  ) : (
                    <button type="button" onClick={() => setMigrateOpen(true)} disabled={pgpBusy}>
                      Migrate to end-to-end
                    </button>
                  )}
                </div>
              ) : null}
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
              {/*
                The choice is framed as the question a user can actually answer, not as a
                protection mode. "Client vs server key custody" is not something most people
                can weigh; "can my phone read this" is. The mode follows from the answer.

                Defaults to no, so nothing downgrades by inattention.
              */}
              <fieldset className="security-choice">
                <legend>Read encrypted mail on your phone?</legend>
                <label>
                  <input
                    type="radio"
                    name="pgp-mobile-readable"
                    checked={!pgpReadOnMobile}
                    onChange={() => setPgpReadOnMobile(false)}
                    disabled={pgpBusy}
                  />
                  <strong>No</strong> (recommended) — only this browser can decrypt. Nobody with
                  access to the server can read your encrypted mail, and the mobile app will show
                  these messages as unreadable with a link to open them here.
                </label>
                <label>
                  <input
                    type="radio"
                    name="pgp-mobile-readable"
                    checked={pgpReadOnMobile}
                    onChange={() => setPgpReadOnMobile(true)}
                    disabled={pgpBusy}
                  />
                  <strong>Yes</strong> — this server stores your key so it can decrypt for your
                  devices. Anyone with access to the server, its disk, or its backups can read your
                  encrypted mail.
                </label>
              </fieldset>
              <button
                type="button"
                onClick={() =>
                  void (pgpReadOnMobile ? handleGenerateServerPGPIdentity() : handleGeneratePGPIdentity())
                }
                disabled={pgpBusy}
              >
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
          <PgpUnlockDialog
            open={unlockOpen}
            reason="to unlock your PGP key for this session"
            onUnlocked={() => setUnlockOpen(false)}
            onCancel={() => setUnlockOpen(false)}
          />

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
              <label className="security-check">
                <input
                  type="checkbox"
                  checked={discoverySettings.publishWKD}
                  disabled={discoveryBusy}
                  onChange={(e) => void updateDiscoverySetting({ publishWKD: e.target.checked })}
                />
                Publish my public key via Web Key Directory (WKD)
              </label>
              <p className="security-muted">
                Lets people look up your key at your mail domain. Requires an administrator to have set up
                WKD for that domain. On by default.
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
