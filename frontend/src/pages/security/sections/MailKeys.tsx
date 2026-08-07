import { ChangeEvent, FormEvent, useEffect, useState } from "react";
import { Link } from "react-router";
import { toErrorMessage } from "../../../api/client";
import {
  generatePGPIdentity,
  deletePGPIdentity,
  storeClientPGPIdentity,
  rewrapPGPPrivateKey,
  exportLegacyPGPKey,
  getPGPDiscoverySettings,
  updatePGPDiscoverySettings,
  listDiscoverySuppressions,
  removeDiscoverySuppression,
  type PGPIdentity,
  type DiscoverySettings,
  type DiscoverySuppression
} from "../../../api/pgp";
import { generateIdentity, importIdentity } from "../../../lib/pgpClient";
import {
  createRecoveryBackup,
  requireUnlockedKey,
  restoreRecoveryBackup,
  wrapPrivateKey,
  type RecoveryBackup
} from "../../../lib/keyVault";
import {
  lockPGPSession,
  loadPGPSession,
  rewrapUnlockedKeyUnder,
  unlockPGPSession,
  type PGPSessionState
} from "../../../lib/pgpSession";
import { unlockWithArmoredKey } from "../../../lib/keyVault";
import { listContacts, type Contact } from "../../../api/contacts";

const noop = () => {};

export type MailKeysProps = {
  /** Optional so this renders (as "loading") with zero props. */
  pgpIdentity?: PGPIdentity | null;
  setPgpIdentity?: (identity: PGPIdentity | null) => void;
  pgpLoading?: boolean;
  pgpSession?: PGPSessionState | null;
  /** Opens SecurityPage's page-level PgpUnlockDialog. */
  setUnlockOpen?: (open: boolean) => void;
  // Lifted to SecurityPage rather than local: this is the one-time secret
  // that opens a just-downloaded PGP recovery backup, shown exactly once and
  // never re-derivable. Before this split, SecurityPage never unmounted on a
  // tab switch, so the reveal survived one; now the tab strip can unmount
  // this component mid-display, and a local copy would be silently destroyed
  // by switching to Sign-in or Devices and back. Lifting it, like
  // recoveryCodes on SignIn, means it is simply still there when this
  // remounts.
  recoverySecret?: string;
  setRecoverySecret?: (secret: string) => void;
};

export function MailKeys({
  pgpIdentity = null,
  setPgpIdentity = noop,
  pgpLoading = false,
  pgpSession = null,
  setUnlockOpen = noop,
  recoverySecret = "",
  setRecoverySecret = noop
}: MailKeysProps = {}) {
  const [pgpBusy, setPgpBusy] = useState(false);
  const [pgpStatus, setPgpStatus] = useState("");
  const [pgpImportOpen, setPgpImportOpen] = useState(false);
  // Which side of the "can my phone read this" question the user picked; false keeps the key
  // in the browser, which is the mode nothing should downgrade away from by accident.
  const [pgpReadOnMobile, setPgpReadOnMobile] = useState(false);
  const [pgpImportKey, setPgpImportKey] = useState("");
  const [pgpImportPassphrase, setPgpImportPassphrase] = useState("");
  const [migratePassword, setMigratePassword] = useState("");
  const [migrateOpen, setMigrateOpen] = useState(false);
  // Backing out a server-custody key before it becomes unrecoverable. Needs its
  // own password prompt because export-legacy re-verifies the account
  // credential, and its own open flag so it does not share the migrate form.
  const [legacyBackupOpen, setLegacyBackupOpen] = useState(false);
  const [legacyBackupPassword, setLegacyBackupPassword] = useState("");

  // Stale-envelope recovery: the stored PGP envelope is sealed under an OLDER
  // password than the account's, so nothing can open it with the current one.
  // Two passwords are needed to fix it — the old one to unlock, the current one
  // to re-seal.
  const [recoverOpen, setRecoverOpen] = useState(false);
  const [recoverOldPassword, setRecoverOldPassword] = useState("");
  const [recoverCurrentPassword, setRecoverCurrentPassword] = useState("");
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [restoreSecret, setRestoreSecret] = useState("");
  const [restorePassword, setRestorePassword] = useState("");
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
      // The same password is the step-up credential: replacing an existing
      // identity needs the account password, not just a session.
      const id = await storeClientPGPIdentity(
        generated.armoredPublicKey,
        JSON.stringify(wrapped),
        "generated",
        password
      );
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
    // Creating a published identity is gated on the account credential, first
    // one or not: a session alone used to be enough, and an attacker holding a
    // stolen cookie could install their own key as this account's published
    // identity — WKD serves it and Autocrypt advertises it, both on by default,
    // so the substitution outlives the session that made it.
    const password = window.prompt(
      "Enter your account password to confirm.\n\nThis publishes a new key for your address: " +
        "WKD serves it and your outgoing mail advertises it."
    );
    if (!password) {
      return;
    }
    setPgpBusy(true);
    setPgpStatus("");
    try {
      const id = await generatePGPIdentity(password);
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
      const id = await storeClientPGPIdentity(
        exported.publicKey,
        JSON.stringify(wrapped),
        "imported",
        migratePassword
      );
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

  /**
   * Writes a recovery backup to disk and reveals the secret that opens it.
   *
   * Shared by both custody modes, which differ only in where the armored key
   * came from — the browser's own vault, or a one-time export of the copy the
   * server still holds. The file format, the one-time secret and the warning
   * that follows must not differ between them.
   */
  function saveRecoveryBackup(backup: RecoveryBackup, fingerprint: string, secret: string) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(backup)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `kypost-pgp-recovery-${fingerprint.slice(0, 8)}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    setRecoverySecret(secret);
  }

  async function handleDownloadRecoveryBackup() {
    setPgpBusy(true);
    setPgpStatus("");
    try {
      const bootstrap = pgpSession?.bootstrap;
      // The fingerprint is checked, not assumed. It is the one field here that
      // comes from a different response than the public key beside it, and a
      // missing one used to surface as a TypeError inside the download rather
      // than as an error about the identity — after the backup had already been
      // built, so the user was told the backup failed while its one-time secret
      // was silently discarded. Falling back to the bootstrap keeps a browser
      // talking to an older server working rather than dead.
      const fingerprint = pgpIdentity?.fingerprint || bootstrap?.fingerprint || "";
      if (!bootstrap || bootstrap.protection !== "client" || !fingerprint) {
        throw new Error("A client-protected identity is required.");
      }
      const { backup, secret } = await createRecoveryBackup(
        requireUnlockedKey(),
        fingerprint,
        bootstrap.publicKey
      );
      saveRecoveryBackup(backup, fingerprint, secret);
    } catch (e) {
      setPgpStatus(`Backup failed: ${toErrorMessage(e, "unlock your key first")}`);
    } finally {
      setPgpBusy(false);
    }
  }

  /**
   * The same backup for a key the server still holds.
   *
   * A server-custody key is recoverable by an admin, so the backup buys less
   * here than it does under client custody — but it is the only copy that
   * survives the migration cliff. Migrating puts the key beyond the server's
   * reach, and from that moment a password reset destroys it and every message
   * ever encrypted to it, so the file has to exist BEFORE the migration, which
   * is the one point at which no client-side vault exists to make it from.
   *
   * It goes through export-legacy rather than any new endpoint: that call
   * already hands this browser the armored key after a fresh password, which is
   * exactly what the migration flow above does with it, and it refuses once the
   * account is client-protected. Nothing here widens what the server will give
   * out. The key is wrapped under a one-time secret before it touches disk —
   * a bare .asc download is deliberately not offered, because an unprotected
   * private key in a downloads folder is the failure this whole page exists to
   * prevent.
   */
  async function handleDownloadLegacyBackup(e: FormEvent) {
    e.preventDefault();
    if (!pgpIdentity) return;
    setPgpBusy(true);
    setPgpStatus("");
    try {
      const exported = await exportLegacyPGPKey(legacyBackupPassword);
      const { backup, secret } = await createRecoveryBackup(
        exported.privateKey,
        pgpIdentity.fingerprint,
        exported.publicKey
      );
      saveRecoveryBackup(backup, pgpIdentity.fingerprint, secret);
      setLegacyBackupOpen(false);
      setLegacyBackupPassword("");
    } catch (err) {
      setPgpStatus(`Backup failed: ${toErrorMessage(err, "check your password and try again")}`);
    } finally {
      setPgpBusy(false);
    }
  }

  function handleRestoreFileSelected(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setRestoreFile(file);
    setRestoreSecret("");
    setRestorePassword("");
    setPgpStatus("");
  }

  function cancelRestore() {
    setRestoreFile(null);
    setRestoreSecret("");
    setRestorePassword("");
  }

  async function handleRestoreSubmit(e: FormEvent) {
    e.preventDefault();
    if (!restoreFile) return;
    setPgpBusy(true);
    setPgpStatus("");
    try {
      const restored = await restoreRecoveryBackup(await restoreFile.text(), restoreSecret);
      const imported = await importIdentity(restored.privateKey, "");
      // Optional-chained through the fingerprint too, not just the identity:
      // the check below already treats a missing one as "cannot match", which
      // is the safe answer, and this is the same crash the recovery backup hit.
      const expected = pgpIdentity?.fingerprint?.toUpperCase();
      if (!expected || imported.fingerprint !== expected || restored.fingerprint.toUpperCase() !== expected) {
        throw new Error("This backup belongs to a different PGP identity.");
      }
      const wrapped = await wrapPrivateKey(imported.armoredPrivateKey, restorePassword);
      await rewrapPGPPrivateKey(JSON.stringify(wrapped), restorePassword);
      unlockWithArmoredKey(imported.armoredPrivateKey);
      setRecoverySecret("");
      cancelRestore();
      await loadPGPSession();
      setPgpStatus("PGP key restored and re-encrypted with your current account password.");
    } catch (err) {
      setPgpStatus(`Restore failed: ${toErrorMessage(err, "check the file and recovery secret")}`);
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
      const id = await storeClientPGPIdentity(
        imported.armoredPublicKey,
        JSON.stringify(wrapped),
        "imported",
        password
      );
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
    // The account password, not just the confirmation. This is the one action
    // on this page that cannot be undone by any later one — a stolen session
    // could otherwise make every message ever encrypted to this key unreadable,
    // permanently, in a single request.
    const password = window.prompt(
      "Enter your account password to confirm deleting your PGP identity.\n\n" +
        "This cannot be undone: mail already encrypted to this key stays unreadable."
    );
    if (!password) {
      return;
    }
    setPgpBusy(true);
    setPgpStatus("");
    try {
      await deletePGPIdentity(password);
      setPgpIdentity(null);
      setPgpStatus("PGP identity deleted.");
    } catch (e) {
      setPgpStatus(`Failed to delete identity: ${toErrorMessage(e, "unknown error")}`);
    } finally {
      setPgpBusy(false);
    }
  }

  // Four states, not two: an identity whose custody is still loading must not be
  // reported as server-held, because that is the alarming answer.
  const keyCustody: "none" | "client" | "server" | "unknown" = !pgpIdentity
    ? pgpLoading
      ? "unknown"
      : "none"
    : !pgpSession?.bootstrap
      ? "unknown"
      : pgpSession.bootstrap.protection === "client"
        ? "client"
        : "server";

  return (
    <>
      <div
        className={`sec-card ${
          keyCustody === "client" ? "sec-card-on" : keyCustody === "server" ? "sec-card-risk" : ""
        }`}
      >
        <div className="sec-card-head">
          <p className="sec-eyebrow">Encryption</p>
          <h3>Email encryption (PGP)</h3>
        </div>
        {pgpLoading ? (
          <p className="sec-muted">Loading...</p>
        ) : pgpIdentity ? (
          <>
            <p className="sec-fingerprint">
              <span className="sec-muted-inline">fingerprint</span> {pgpIdentity.fingerprint}
              <br />
              <span className="sec-muted-inline">source</span> {pgpIdentity.source}
            </p>

            {pgpSession?.bootstrap?.protection === "client" ? (
              <div className="sec-section">
                <p className="sec-verdict sec-verdict-ok">
                  <span className="sec-pip sec-pip-on" aria-hidden="true" />
                  <span>End-to-end. This server cannot read your encrypted mail.</span>
                </p>
                <p className="sec-muted">
                  Your private key is encrypted with your account password and unlocked only in this browser tab.{" "}
                  {pgpSession.unlocked ? "It is unlocked for this session." : "It is locked — you will be asked for your password when you open or send encrypted mail."}
                </p>
                <p className="sec-muted">
                  <strong>Keep a backup of your key.</strong> Because the server cannot open it, an admin password
                  reset makes it permanently unrecoverable along with every message encrypted to it.
                </p>
                <div className="sec-actions">
                  {pgpSession.unlocked ? (
                    <button type="button" className="sec-action-quiet" onClick={() => lockPGPSession()}>
                      Lock key
                    </button>
                  ) : (
                    <button type="button" onClick={() => setUnlockOpen(true)}>
                      Unlock key
                    </button>
                  )}
                  <button
                    type="button"
                    className="sec-action-quiet"
                    onClick={() => setRecoverOpen((v) => !v)}
                  >
                    Key won&apos;t unlock?
                  </button>
                </div>
                {recoverOpen ? (
                  <form
                    onSubmit={(e) => void handleRecoverStaleEnvelope(e)}
                    className="auth-form sec-inline-form"
                  >
                    <h4>Re-encrypt your key</h4>
                    <p className="sec-muted">
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
                    <div className="sec-actions">
                      <button
                        type="submit"
                        disabled={pgpBusy || recoverOldPassword === "" || recoverCurrentPassword === ""}
                      >
                        Re-encrypt key
                      </button>
                      <button
                        type="button"
                        className="sec-action-quiet"
                        onClick={() => setRecoverOpen(false)}
                      >
                        Cancel
                      </button>
                    </div>
                  </form>
                ) : null}
                <div className="sec-actions">
                  <button
                    type="button"
                    className="sec-action-primary"
                    disabled={pgpBusy || !pgpSession.unlocked}
                    onClick={() => void handleDownloadRecoveryBackup()}
                  >
                    Download recovery backup
                  </button>
                  <label className="sec-action-file sec-action-quiet">
                    Restore recovery backup
                    <input
                      type="file"
                      accept="application/json,.json"
                      hidden
                      disabled={pgpBusy}
                      onChange={(e) => handleRestoreFileSelected(e)}
                    />
                  </label>
                </div>
                {restoreFile ? (
                  <form className="sec-inline-form" onSubmit={(e) => void handleRestoreSubmit(e)}>
                    <h4>Restore from {restoreFile.name}</h4>
                    <label className="sec-label">
                      Recovery secret
                      <input
                        type="password"
                        className="sec-input"
                        value={restoreSecret}
                        onChange={(e) => setRestoreSecret(e.target.value)}
                        autoComplete="off"
                        required
                      />
                    </label>
                    <label className="sec-label">
                      Current account password
                      <input
                        type="password"
                        className="sec-input"
                        value={restorePassword}
                        onChange={(e) => setRestorePassword(e.target.value)}
                        autoComplete="current-password"
                        required
                      />
                    </label>
                    <div className="sec-actions">
                      <button type="submit" disabled={pgpBusy}>Restore</button>
                      <button type="button" className="sec-action-quiet" disabled={pgpBusy} onClick={cancelRestore}>
                        Cancel
                      </button>
                    </div>
                  </form>
                ) : null}
              </div>
            ) : pgpSession?.bootstrap?.migrationAvailable ? (
              <div className="sec-section">
                <p className="sec-verdict sec-verdict-risk">
                  <span className="sec-pip sec-pip-risk" aria-hidden="true" />
                  <span>This server can read your encrypted mail.</span>
                </p>
                <p className="sec-muted">
                  Your private key is stored on this server, encrypted with a key kept on the same machine. Anyone
                  with access to the server or its backups can decrypt everything you have received. Migrating moves
                  the key under your account password so only your browser can open it.
                </p>
                <p className="sec-muted">
                  After migrating, an admin password reset will make the key unrecoverable — export a backup first.
                </p>
                {legacyBackupOpen ? (
                  <form
                    onSubmit={(e) => void handleDownloadLegacyBackup(e)}
                    className="auth-form sec-inline-form"
                  >
                    <h4>Confirm your password</h4>
                    <p className="sec-muted">
                      The key is wrapped in this browser under a one-time secret shown after the download, so the
                      file is safe to keep in a password manager or a cloud drive.
                    </p>
                    <label>
                      <div>Account password</div>
                      <input
                        type="password"
                        autoComplete="current-password"
                        value={legacyBackupPassword}
                        onChange={(e) => setLegacyBackupPassword(e.target.value)}
                        required
                      />
                    </label>
                    <div className="sec-actions">
                      <button type="submit" disabled={pgpBusy || legacyBackupPassword.length === 0}>
                        {pgpBusy ? "Preparing…" : "Download backup"}
                      </button>
                      <button
                        type="button"
                        className="sec-action-quiet"
                        onClick={() => {
                          setLegacyBackupOpen(false);
                          setLegacyBackupPassword("");
                        }}
                        disabled={pgpBusy}
                      >
                        Cancel
                      </button>
                    </div>
                  </form>
                ) : (
                  <div className="sec-actions">
                    <button
                      type="button"
                      className="sec-action-primary"
                      onClick={() => setLegacyBackupOpen(true)}
                      disabled={pgpBusy}
                    >
                      Download recovery backup
                    </button>
                  </div>
                )}
                {migrateOpen ? (
                  <form
                    onSubmit={(e) => void handleMigrateToClientProtection(e)}
                    className="auth-form sec-inline-form"
                  >
                    <h4>Confirm your password</h4>
                    <label>
                      <div>Account password</div>
                      <input
                        type="password"
                        autoComplete="current-password"
                        value={migratePassword}
                        onChange={(e) => setMigratePassword(e.target.value)}
                        required
                      />
                    </label>
                    <div className="sec-actions">
                      <button type="submit" disabled={pgpBusy || migratePassword.length === 0}>
                        {pgpBusy ? "Migrating…" : "Migrate to end-to-end"}
                      </button>
                      <button
                        type="button"
                        className="sec-action-quiet"
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
                  <div className="sec-actions">
                    <button type="button" onClick={() => setMigrateOpen(true)} disabled={pgpBusy}>
                      Migrate to end-to-end
                    </button>
                  </div>
                )}
              </div>
            ) : null}
            {/*
              Outside the custody branches on purpose: both of them produce a
              backup, and both owe the user the secret that opens it. A copy
              per branch is a copy that gets fixed in one place.
            */}
            {recoverySecret ? (
              <div className="sec-inline-form">
                <h4>Store this recovery secret</h4>
                <p className="sec-muted">
                  The downloaded file is useless without this secret. KyPost does not store it. Anyone with both
                  can decrypt your historical mail.
                </p>
                <p className="sec-fingerprint"><code>{recoverySecret}</code></p>
                <div className="sec-actions">
                  <button
                    type="button"
                    className="sec-action-quiet"
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(recoverySecret);
                        setPgpStatus("Recovery secret copied.");
                      } catch {
                        setPgpStatus("Copy failed — select and copy the secret manually.");
                      }
                    }}
                  >
                    Copy secret
                  </button>
                  <button type="button" onClick={() => setRecoverySecret("")}>Done</button>
                </div>
              </div>
            ) : null}
            <p className="sec-muted">
              {selfContact ? (
                <>Sharing contact card: {selfContact.fn} · <Link to="/contacts">Manage in Contacts</Link></>
              ) : (
                <>No contact card set — <Link to="/contacts">add one in Contacts</Link> and mark it as yours to include it when sharing your PGP key.</>
              )}
            </p>
            <details className="sec-details">
              <summary>Show public key</summary>
              <pre className="sec-pubkey">{pgpIdentity.publicKey}</pre>
            </details>
            <div className="sec-actions">
              <button
                type="button"
                className="sec-action-danger"
                onClick={() => void handleDeletePGPIdentity()}
                disabled={pgpBusy}
              >
                Delete identity
              </button>
            </div>
          </>
        ) : (
          <>
            {/*
              The choice is framed as the question a user can actually answer, not as a
              protection mode. "Client vs server key custody" is not something most people
              can weigh; "can my phone read this" is. The mode follows from the answer.

              Defaults to no, so nothing downgrades by inattention.
            */}
            <fieldset className="sec-choice">
              <legend>Read encrypted mail on your phone?</legend>
              <label>
                <input
                  type="radio"
                  name="pgp-mobile-readable"
                  checked={!pgpReadOnMobile}
                  onChange={() => setPgpReadOnMobile(false)}
                  disabled={pgpBusy}
                />
                <span>
                  <strong>No</strong> (recommended) — only this browser can decrypt. Nobody with
                  access to the server can read your encrypted mail, and the mobile app will show
                  these messages as unreadable with a link to open them here.
                </span>
              </label>
              <label>
                <input
                  type="radio"
                  name="pgp-mobile-readable"
                  checked={pgpReadOnMobile}
                  onChange={() => setPgpReadOnMobile(true)}
                  disabled={pgpBusy}
                />
                <span>
                  <strong>Yes</strong> — this server stores your key so it can decrypt for your
                  devices. Anyone with access to the server, its disk, or its backups can read your
                  encrypted mail.
                </span>
              </label>
            </fieldset>
            <div className="sec-actions">
              <button
                type="button"
                onClick={() =>
                  void (pgpReadOnMobile ? handleGenerateServerPGPIdentity() : handleGeneratePGPIdentity())
                }
                disabled={pgpBusy}
              >
                Generate new identity
              </button>
              <button
                type="button"
                className="sec-action-quiet"
                onClick={() => setPgpImportOpen(!pgpImportOpen)}
                disabled={pgpBusy}
              >
                Import existing key
              </button>
            </div>
            {pgpImportOpen ? (
              <form
                onSubmit={(e) => void handleImportPGPIdentity(e)}
                className="auth-form sec-inline-form"
              >
                <h4>Import a key</h4>
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
                <div className="sec-actions">
                  <button type="submit" disabled={pgpBusy}>Import</button>
                </div>
              </form>
            ) : null}
          </>
        )}
        {pgpStatus ? <p className="sec-muted">{pgpStatus}</p> : null}

        {discoverySettings ? (
          <div className="sec-subsection">
            <h5>Key discovery</h5>
            <label className="sec-check">
              <input
                type="checkbox"
                checked={discoverySettings.autoEncryptWhenKeyKnown}
                disabled={discoveryBusy}
                onChange={(e) => void updateDiscoverySetting({ autoEncryptWhenKeyKnown: e.target.checked })}
              />
              Encrypt automatically when I have a recipient's key
            </label>
            <label className="sec-check">
              <input
                type="checkbox"
                checked={discoverySettings.storeDiscoveredKeys}
                disabled={discoveryBusy}
                onChange={(e) => void updateDiscoverySetting({ storeDiscoveredKeys: e.target.checked })}
              />
              Save keys I discover to my contacts
            </label>
            <label className="sec-check">
              <input
                type="checkbox"
                checked={discoverySettings.advertiseAutocrypt}
                disabled={discoveryBusy}
                onChange={(e) => void updateDiscoverySetting({ advertiseAutocrypt: e.target.checked })}
              />
              Advertise my public key on outgoing mail (Autocrypt)
            </label>
            <p className="sec-check-note">
              Adds an Autocrypt header so people you email can automatically discover your key. On by
              default.
            </p>
            <label className="sec-check">
              <input
                type="checkbox"
                checked={discoverySettings.publishWKD}
                disabled={discoveryBusy}
                onChange={(e) => void updateDiscoverySetting({ publishWKD: e.target.checked })}
              />
              Publish my public key via Web Key Directory (WKD)
            </label>
            <p className="sec-check-note">
              Lets people look up your key at your mail domain. Requires an administrator to have set up
              WKD for that domain. On by default.
            </p>
            {discoveryStatus ? <p className="sec-muted">{discoveryStatus}</p> : null}
            {suppressions.length > 0 ? (
              <div className="sec-subsection">
                <h5>Discovery opt-outs</h5>
                <ul className="sec-list">
                  {suppressions.map((s) => (
                    <li key={s.email}>
                      <span>
                        {s.email} <span className="sec-muted-inline">({s.reason})</span>
                      </span>
                      <button
                        type="button"
                        className="sec-action-quiet"
                        onClick={() => void allowDiscoveryAgain(s.email)}
                      >
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
    </>
  );
}
