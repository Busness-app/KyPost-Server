import { useState } from "react";
import { deleteJSON, postJSON, putJSON, toErrorMessage } from "../../../api/client";
import type { NativeDeliveryMode } from "../../../api/devices";
import { DeviceEnrollmentCard } from "../../../components/DeviceEnrollmentCard";
import { DeviceList } from "../DeviceList";
import { PairingPanel } from "../PairingPanel";
import type { DeviceRow } from "../deviceJoin";
import type { MfaStatus } from "../types";

const noop = () => {};
const noopAsync = async () => {};

export type DevicesProps = {
  /** Current MFA status. Optional so this renders (no push approval) with zero props. */
  status?: MfaStatus | null;
  refreshStatus?: () => Promise<void>;
  /** Surfaces a message on SecurityPage's shared, page-level status line. */
  setMessage?: (message: string) => void;
  /**
   * The device inventory, joined against `status.approverDevices` — computed
   * once in SecurityPage because its own page-level summary (paired/approver
   * counts) needs the same join, and a second copy here could disagree with it.
   */
  deviceRows?: DeviceRow[];
  devicesError?: string;
  refreshDevices?: () => Promise<void>;
  deliveryMode?: NativeDeliveryMode;
  setDeliveryMode?: (mode: NativeDeliveryMode) => void;
  pushOn?: boolean;
  approvalsOn?: boolean;
  /** The account's PGP fingerprint, for the device-enrollment card. */
  pgpFingerprint?: string;
  /** Whether the PGP identity is client-protected — the only mode with a key to seal. */
  pgpClientProtected?: boolean;
  /** Whether the PGP vault is unlocked right now. */
  pgpUnlocked?: boolean;
  /** Opens SecurityPage's page-level PgpUnlockDialog. */
  setUnlockOpen?: (open: boolean) => void;
  /** Switches SecurityPage to the Sign-in tab. */
  onGoToSignIn?: () => void;
};

export function Devices({
  status = null,
  refreshStatus = noopAsync,
  setMessage = noop,
  deviceRows = [],
  devicesError = "",
  refreshDevices = noopAsync,
  deliveryMode = "push",
  setDeliveryMode = noop,
  pushOn = false,
  approvalsOn = false,
  pgpFingerprint = "",
  pgpClientProtected = false,
  pgpUnlocked = false,
  setUnlockOpen = noop,
  onGoToSignIn = noop
}: DevicesProps = {}) {
  const [busy, setBusy] = useState(false);
  const [deviceRemoveBusyId, setDeviceRemoveBusyId] = useState("");
  const [unpairBusy, setUnpairBusy] = useState(false);
  const [pairingOpen, setPairingOpen] = useState(false);
  const [deliveryModeBusy, setDeliveryModeBusy] = useState(false);

  async function changeDeliveryMode(mode: NativeDeliveryMode) {
    if (mode === deliveryMode || deliveryModeBusy) {
      return;
    }
    const previous = deliveryMode;
    setDeliveryMode(mode); // optimistic
    setDeliveryModeBusy(true);
    try {
      const res = await putJSON<{ ok: boolean; deliveryMode: NativeDeliveryMode }>(
        "/api/notifications/native/mode",
        { mode }
      );
      setDeliveryMode(res.deliveryMode === "pull" ? "pull" : "push");
      setMessage(res.deliveryMode === "pull"
        ? "Switched to App Pull notifications (bypasses Cloudflare and Firebase)."
        : "Switched to relay push notifications.");
    } catch (err) {
      setDeliveryMode(previous); // roll back
      setMessage(`Failed to change notification delivery: ${toErrorMessage(err, "unknown error")}`);
    } finally {
      setDeliveryModeBusy(false);
    }
  }

  async function removeDevice(deviceId: string) {
    const cleaned = deviceId.trim();
    if (!cleaned) {
      return;
    }
    setDeviceRemoveBusyId(cleaned);
    try {
      await deleteJSON<{ ok: boolean; removed: boolean; devices: number }>(
        "/api/notifications/native/devices",
        { deviceId: cleaned }
      );
      await refreshDevices();
      // The removed device may have been an approver, so the MFA status is now
      // stale too — refreshing only the inventory would leave its approver row
      // behind, flagged as missing from a list it was just removed from.
      await refreshStatus();
      setMessage("Removed paired device.");
    } catch (err) {
      setMessage(`Failed to remove paired device: ${toErrorMessage(err, "unknown error")}`);
    } finally {
      setDeviceRemoveBusyId("");
    }
  }

  async function revokePairedDevices() {
    setUnpairBusy(true);
    try {
      await postJSON<{ ok: boolean }>("/api/notifications/native/unpair", {});
      await refreshDevices();
      await refreshStatus();
      setMessage("Revoked every paired device.");
    } catch (err) {
      setMessage(`Failed to revoke paired devices: ${toErrorMessage(err, "unknown error")}`);
    } finally {
      setUnpairBusy(false);
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

  return (
    <>
      <div className="sec-card">
        <div className="sec-card-head">
          <p className="sec-eyebrow">Devices</p>
          <h3>Pair a new device</h3>
        </div>
        {pairingOpen ? (
          <>
            <PairingPanel
              onDevicesMayHaveChanged={() => void refreshDevices()}
              onStatus={setMessage}
            />
            <div className="sec-actions">
              <button type="button" className="sec-action-quiet" onClick={() => setPairingOpen(false)}>
                Done
              </button>
            </div>
          </>
        ) : (
          <div className="sec-section">
            <p className="sec-muted">
              Pairing shows a code that is valid for ninety seconds. It stays hidden until you ask for
              it, so simply having this page open never leaves a live pairing code on your screen.
            </p>
            <div className="sec-actions">
              <button type="button" onClick={() => setPairingOpen(true)}>
                Pair a new device
              </button>
            </div>
          </div>
        )}
      </div>

      <div className={`sec-card ${approvalsOn ? "sec-card-on" : ""}`}>
        <div className="sec-card-head">
          <p className="sec-eyebrow">Devices</p>
          <h3>Your devices</h3>
        </div>

        <div className="sec-section">
          {!status?.totpEnabled ? (
            <p className="sec-muted">
              Sign-in approval needs an authenticator app first — set one up on the{" "}
              <button type="button" className="sec-link-button" onClick={onGoToSignIn}>
                Sign-in tab
              </button>
              . Push approval always keeps a code as its fallback, so it can only be turned on once
              that is active.
            </p>
          ) : (
            <label className="sec-check">
              <input
                type="checkbox"
                checked={pushOn}
                disabled={busy}
                onChange={(e) => void togglePush(e.target.checked)}
              />
              Let a paired device approve sign-ins with a tap
            </label>
          )}

          {devicesError ? (
            <p className="sec-verdict sec-verdict-risk">{devicesError}</p>
          ) : (
            <DeviceList
              rows={deviceRows}
              pushEnabled={pushOn && Boolean(status?.totpEnabled)}
              approvalsKnown={status !== null}
              busy={busy}
              removingId={deviceRemoveBusyId}
              onToggleApprover={(id, approver) => void toggleApprover(id, approver)}
              onRemove={(id) => void removeDevice(id)}
            />
          )}
        </div>

        <div className="sec-section">
          <h4>How pushes reach your devices</h4>
          <p className="sec-muted">
            App Pull fetches notifications straight from this server over HTTP, bypassing Cloudflare
            and Firebase.
          </p>
          <div className="sec-delivery-toggle" role="group" aria-label="Notification delivery method">
            <button
              type="button"
              className={`sec-delivery-option${deliveryMode === "push" ? " active" : ""}`}
              aria-pressed={deliveryMode === "push"}
              onClick={() => void changeDeliveryMode("push")}
              disabled={deliveryModeBusy}
            >
              Relay Push
            </button>
            <button
              type="button"
              className={`sec-delivery-option${deliveryMode === "pull" ? " active" : ""}`}
              aria-pressed={deliveryMode === "pull"}
              onClick={() => void changeDeliveryMode("pull")}
              disabled={deliveryModeBusy}
            >
              App Pull
            </button>
          </div>
        </div>

        {deviceRows.length > 0 ? (
          <div className="sec-section">
            <div className="sec-actions">
              <button
                type="button"
                className="sec-action-danger"
                onClick={() => void revokePairedDevices()}
                disabled={unpairBusy}
              >
                {unpairBusy ? "Revoking..." : "Revoke every paired device"}
              </button>
            </div>
          </div>
        ) : null}
      </div>

      {/* Kept as its own card rather than folded into the rows above: it
          applies only to a client-protected account, so as a column it would
          be blank for everyone else — and it owns the enrollment ceremony,
          whose security rests on refetching the device list when the identity
          changes. See api/devices.ts. */}
      <DeviceEnrollmentCard
        fingerprint={pgpFingerprint}
        clientProtected={pgpClientProtected}
        unlocked={pgpUnlocked}
        onRequestUnlock={() => setUnlockOpen(true)}
      />
    </>
  );
}
