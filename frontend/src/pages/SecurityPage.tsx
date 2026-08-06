import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { getJSON, toErrorMessage } from "../api/client";
import { listNativeDevices, type NativeDeliveryMode, type NativeDevice } from "../api/devices";
import { getPGPIdentity, type PGPIdentity } from "../api/pgp";
import {
  loadPGPSession,
  subscribePGPSession,
  type PGPSessionState
} from "../lib/pgpSession";
import { PgpUnlockDialog } from "../components/PgpUnlockDialog";
import { countApprovers, joinDeviceRows } from "./security/deviceJoin";
import { SECURITY_TABS, SECURITY_TAB_LABELS, resolveSecurityTab, type SecurityTab } from "./security/tabs";
import type { MfaStatus, TotpSetup } from "./security/types";
import { SignIn } from "./security/sections/SignIn";
import { Devices } from "./security/sections/Devices";
import { MailKeys } from "./security/sections/MailKeys";

export function SecurityPage() {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [message, setMessage] = useState("");

  // In the URL so the prose elsewhere ("pair a device on Security's Devices
  // tab") can be a link, and so a reload keeps you where you were.
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = resolveSecurityTab(searchParams.get("tab"));
  function setActiveTab(tab: SecurityTab) {
    const next = new URLSearchParams(searchParams);
    next.set("tab", tab);
    setSearchParams(next, { replace: true });
  }

  // Paired devices. The inventory comes from its own endpoint rather than from
  // the pairing endpoint, which mints a credential as a side effect — see
  // api/devices.ts. Pairing itself is lazy, inside PairingPanel.
  //
  // Lives here, not in Devices, because the page-level summary below (paired
  // count, approver count) is visible regardless of which tab is active, and
  // that summary would otherwise go stale the moment the Devices tab unmounts.
  const [nativeDevices, setNativeDevices] = useState<NativeDevice[]>([]);
  const [devicesError, setDevicesError] = useState("");
  const [deliveryMode, setDeliveryMode] = useState<NativeDeliveryMode>("push");

  // Recovery-code display (shown once after confirm or regenerate, inside
  // SignIn) — kept here rather than in SignIn because the page-level summary's
  // "Password and code" pip must flip the instant codes are issued, not only
  // after the next status refetch.
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);

  // The in-progress TOTP enrollment secret (POST /api/mfa/totp/setup). Kept
  // here, not in SignIn, so switching Security tabs mid-scan does not
  // silently destroy the only secret the server will accept for this
  // enrollment — see SignInProps for the full reasoning.
  const [totpSetup, setTotpSetup] = useState<TotpSetup | null>(null);

  // The one-time secret that opens a just-downloaded PGP recovery backup.
  // Kept here, not in MailKeys, so switching Security tabs away and back
  // does not silently destroy it — see MailKeysProps for the full reasoning.
  const [recoverySecret, setRecoverySecret] = useState("");

  // PGP identity state. Kept here, not in MailKeys, for the same reason as
  // nativeDevices above: the page-level summary's key-custody pip, and the
  // Devices tab's enrollment card, both need this regardless of which tab is
  // mounted.
  const [pgpIdentity, setPgpIdentity] = useState<PGPIdentity | null>(null);
  const [pgpLoading, setPgpLoading] = useState(true);
  // Cold-start PGP state (protection mode, wrapped key, unlock status).
  const [pgpSession, setPgpSession] = useState<PGPSessionState | null>(null);
  const [unlockOpen, setUnlockOpen] = useState(false);

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

  // Subscribe to the shared PGP session so this page and the rest of the app
  // agree on protection mode and lock state.
  useEffect(() => subscribePGPSession(setPgpSession), []);
  useEffect(() => {
    void loadPGPSession();
  }, []);

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

  const refreshDevices = useCallback(async () => {
    try {
      const next = await listNativeDevices();
      setNativeDevices(Array.isArray(next.devices) ? next.devices : []);
      // Older servers omit it; leave the toggle showing what it already had
      // rather than silently asserting "push".
      if (next.deliveryMode) {
        setDeliveryMode(next.deliveryMode === "pull" ? "pull" : "push");
      }
      setDevicesError("");
    } catch (err) {
      // Empty the list rather than leave a stale one claiming a device is still
      // paired. The error below says why it is empty, so this does not read as
      // the reassuring "nothing is paired".
      setNativeDevices([]);
      setDevicesError(toErrorMessage(err, "Could not read your paired devices."));
    }
  }, []);

  useEffect(() => {
    void refreshDevices();
  }, [refreshDevices]);

  const showRecoveryPanel = recoveryCodes.length > 0;
  const totpOn = showRecoveryPanel || Boolean(status?.totpEnabled);
  const pushOn = Boolean(status?.pushMfaEnabled);
  // One list from two sources — see pages/security/deviceJoin.ts for what
  // happens when they disagree.
  const deviceRows = joinDeviceRows(nativeDevices, status?.approverDevices ?? []);
  const approverCount = countApprovers(deviceRows);
  const approvalsOn = pushOn && approverCount > 0;
  const pairedCount = nativeDevices.length;

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

  const messageTone = message.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

  return (
    <section className="panel sec-page">
      <header className="sec-header">
        <h2>Security</h2>
        <p>Who can sign in as you, which devices you trust, and who can read your mail.</p>
      </header>

      {message ? <p className={messageTone}>{message}</p> : null}

      {/* Where you stand, stated as consequences rather than as feature names —
          the consequence is the part the reader is actually deciding about. */}
      <ul className="sec-custody">
        <li>
          <p className="sec-eyebrow">Sign-in</p>
          <span className="sec-custody-state">
            <span className={`sec-pip ${totpOn ? "sec-pip-on" : ""}`} aria-hidden="true" />
            {totpOn ? "Password and code" : "Password only"}
          </span>
          <p>
            {totpOn
              ? "Signing in needs a code from your authenticator as well as your password."
              : "Anyone who learns your password can sign in as you."}
          </p>
        </li>
        <li>
          <p className="sec-eyebrow">Devices</p>
          <span className="sec-custody-state">
            <span className={`sec-pip ${approvalsOn ? "sec-pip-on" : ""}`} aria-hidden="true" />
            {pairedCount === 0
              ? "None paired"
              : `${pairedCount} paired, ${approverCount} can approve`}
          </span>
          <p>
            {approvalsOn
              ? "You can approve a sign-in with a tap instead of typing a code."
              : pushOn
                ? "Push approval is on, but no device is set to approve sign-ins."
                : "Sign-ins are confirmed with a code, not a device."}
          </p>
        </li>
        <li>
          <p className="sec-eyebrow">Mail</p>
          <span className="sec-custody-state">
            <span
              className={`sec-pip ${
                keyCustody === "client" ? "sec-pip-on" : keyCustody === "server" ? "sec-pip-risk" : ""
              }`}
              aria-hidden="true"
            />
            {keyCustody === "client"
              ? "End-to-end"
              : keyCustody === "server"
                ? "Server holds your key"
                : keyCustody === "none"
                  ? "No encryption key"
                  : "Checking"}
          </span>
          <p>
            {keyCustody === "client"
              ? "Only this browser can open mail encrypted to you."
              : keyCustody === "server"
                ? "This server, and anyone who reaches it or its backups, can read your encrypted mail."
                : keyCustody === "none"
                  ? "Nobody can send you encrypted mail until you set up a PGP key."
                  : "Reading your key's custody."}
          </p>
        </li>
      </ul>

      <div className="sec-tabs" role="tablist" aria-label="Security sections">
        {SECURITY_TABS.map((tab) => (
          <button
            key={tab}
            type="button"
            role="tab"
            aria-selected={activeTab === tab}
            className={`sec-tab${activeTab === tab ? " active" : ""}`}
            onClick={() => setActiveTab(tab)}
          >
            {SECURITY_TAB_LABELS[tab]}
          </button>
        ))}
      </div>

      <div className="sec-layout">
        {activeTab === "signin" ? (
          <SignIn
            status={status}
            refreshStatus={refreshStatus}
            recoveryCodes={recoveryCodes}
            setRecoveryCodes={setRecoveryCodes}
            setMessage={setMessage}
            setup={totpSetup}
            setSetup={setTotpSetup}
          />
        ) : null}

        {activeTab === "devices" ? (
          <Devices
            status={status}
            refreshStatus={refreshStatus}
            setMessage={setMessage}
            deviceRows={deviceRows}
            devicesError={devicesError}
            refreshDevices={refreshDevices}
            deliveryMode={deliveryMode}
            setDeliveryMode={setDeliveryMode}
            pushOn={pushOn}
            approvalsOn={approvalsOn}
            pgpFingerprint={pgpIdentity?.fingerprint ?? ""}
            pgpClientProtected={keyCustody === "client"}
            pgpUnlocked={pgpSession?.unlocked ?? false}
            setUnlockOpen={setUnlockOpen}
            onGoToSignIn={() => setActiveTab("signin")}
          />
        ) : null}

        {activeTab === "mail" ? (
          <MailKeys
            pgpIdentity={pgpIdentity}
            setPgpIdentity={setPgpIdentity}
            pgpLoading={pgpLoading}
            pgpSession={pgpSession}
            setUnlockOpen={setUnlockOpen}
            recoverySecret={recoverySecret}
            setRecoverySecret={setRecoverySecret}
          />
        ) : null}
      </div>

      {/* Page level, outside the tabs on purpose: the Devices tab's enrollment
          card also asks for an unlock, and a dialog mounted only under Mail
          would leave that button setting a flag nothing renders. */}
      <PgpUnlockDialog
        open={unlockOpen}
        reason="to unlock your PGP key for this session"
        onUnlocked={() => setUnlockOpen(false)}
        onCancel={() => setUnlockOpen(false)}
      />
    </section>
  );
}
