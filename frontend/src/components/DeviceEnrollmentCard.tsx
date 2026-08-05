import { useCallback, useEffect, useState } from "react";
import { toErrorMessage } from "../api/client";
import { listNativeDevices, type NativeDevice } from "../api/devices";
import { putDeviceEnvelope } from "../api/pgp";
import { requireUnlockedKey } from "../lib/keyVault";
import { sealEnvelopeForDevice, verifyEnrollmentCode } from "../lib/deviceEnrollment";

/**
 * "Encrypted mail on your devices" — the browser half of device enrollment.
 *
 * A paired phone cannot open the account's PGP envelope, because that envelope
 * is sealed under the account password and pairing never learns it. Enrollment
 * gives the device its own sealing, opened by its secure element.
 *
 * THE SECURITY OF THIS WHOLE FEATURE IS ONE COMPARISON, and it happens here.
 * The server stores and serves the device's public key, so the server is the
 * party that can substitute its own and then open anything sealed to it. The
 * user types a code the device derived from the key in its own keystore; this
 * card derives the same code from the key the server handed over. If they
 * differ, the server substituted, and the ceremony refuses to seal.
 *
 * See docs/superpowers/specs/2026-08-05-device-enrollment-2b-design.md.
 */

export type DeviceEnrollmentCardProps = {
  /** The account's PGP fingerprint. Bound into the envelope's AAD. */
  fingerprint: string;
  /** True when protection is "client" — the only mode with a key to seal. */
  clientProtected: boolean;
  /** Whether the vault is open right now. */
  unlocked: boolean;
  /** Opens the page's existing PgpUnlockDialog. */
  onRequestUnlock: () => void;
};

type EnrollmentState = "unsupported" | "available" | "enrolled";

/**
 * What this device can do, from what it has published.
 *
 * "unsupported" is the pre-2c state and also the permanent state of any client
 * that cannot hold a non-extractable key — it is not an error and must not read
 * as one.
 */
function enrollmentState(device: NativeDevice): EnrollmentState {
  if (!device.enrollmentPublicKey) return "unsupported";
  return device.encryptionEnrolled ? "enrolled" : "available";
}

function deviceLabel(device: NativeDevice): string {
  return device.deviceName?.trim() || device.platform || device.deviceId;
}

/**
 * One run of the ceremony.
 *
 * `publicKey` is snapshotted here rather than read from the device list at seal
 * time, and that is not a convenience. Verifying against one fetch and sealing
 * against another would let a server answer honestly once and hostilely once —
 * the comparison passes on bytes that are never sealed to, which is the exact
 * attack the comparison exists to catch, arriving through a refetch.
 */
type Ceremony = {
  device: NativeDevice;
  publicKey: string;
};

export function DeviceEnrollmentCard({
  fingerprint,
  clientProtected,
  unlocked,
  onRequestUnlock
}: DeviceEnrollmentCardProps) {
  const [devices, setDevices] = useState<NativeDevice[]>([]);
  const [error, setError] = useState("");
  const [ceremony, setCeremony] = useState<Ceremony | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [failure, setFailure] = useState("");
  const [busy, setBusy] = useState(false);

  function openCeremony(device: NativeDevice) {
    setCeremony({ device, publicKey: device.enrollmentPublicKey ?? "" });
    setCode("");
    setPassword("");
    setFailure("");
  }

  async function submit() {
    if (!ceremony || busy) return;
    setBusy(true);
    setFailure("");
    try {
      // FIRST, before anything derives: a locked vault is an ordinary state and
      // must not surface as the substituted-key alarm.
      let armored: string;
      try {
        armored = requireUnlockedKey();
      } catch {
        setFailure("locked");
        return;
      }

      const { device, publicKey } = ceremony;

      // THE GATE. Everything below it is unreachable without a match.
      if (!(await verifyEnrollmentCode(publicKey, device.deviceId, code))) {
        setFailure("mismatch");
        return;
      }

      const envelope = await sealEnvelopeForDevice(publicKey, device.deviceId, fingerprint, armored);
      await putDeviceEnvelope(device.deviceId, envelope, password);
      setCeremony(null);
      await refresh();
    } catch (e) {
      setFailure(toErrorMessage(e, "Could not store the sealing."));
    } finally {
      setBusy(false);
    }
  }

  const refresh = useCallback(async () => {
    try {
      const next = await listNativeDevices();
      setDevices(Array.isArray(next.devices) ? next.devices : []);
      setError("");
    } catch (e) {
      // Clear the list rather than leave a stale one on screen. This matters
      // most on the identity-change refetch this component exists to
      // guarantee: a list held over from the old identity would keep
      // asserting "this device can read your encrypted mail" about sealings
      // that no longer exist server-side. An empty list here is not the
      // reassuring "no devices" story — the error message below says so.
      setDevices([]);
      setError(toErrorMessage(e, "Could not read your paired devices."));
    }
  }, []);

  // `fingerprint` is in the deps deliberately. Replacing the identity clears
  // every non-password slot on the server, so every device's enrollment marker
  // becomes false — and a list cached across that change would keep showing
  // devices as able to read mail they can no longer open.
  useEffect(() => {
    if (clientProtected) void refresh();
  }, [clientProtected, fingerprint, refresh]);

  // Nothing to seal, so nothing to offer. The PGP card above this one is where
  // an account without a client-held key gets told about it.
  if (!clientProtected || !fingerprint) return null;

  return (
    <div className="sec-card">
      <div className="sec-card-head">
        <p className="sec-eyebrow">Mail</p>
        <h3>Encrypted mail on your devices</h3>
      </div>
      <p className="sec-muted">
        A paired device cannot read your encrypted mail until you enroll it. Enrolling gives that
        device its own copy of your key, opened by its secure hardware rather than your password.
      </p>
      {error ? (
        <p className="sec-muted">{error}</p>
      ) : devices.length === 0 ? (
        <p className="sec-muted">
          No paired devices yet. Pair a device on the Notifications page first.
        </p>
      ) : (
        <ul className="sec-devices">
          {devices.map((device) => {
            const state = enrollmentState(device);
            return (
              <li key={device.deviceId}>
                <span className="sec-device-name">{deviceLabel(device)}</span>
                {state === "enrolled" ? (
                  <p className="sec-muted">This device can read your encrypted mail.</p>
                ) : state === "available" ? (
                  <>
                    <p className="sec-muted">Not enrolled. It cannot read your encrypted mail.</p>
                    <button type="button" onClick={() => openCeremony(device)}>
                      Enroll
                    </button>
                  </>
                ) : (
                  <p className="sec-muted">
                    This device's app is too old to be enrolled. Update it and pair again.
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {!unlocked ? (
        <p className="sec-muted">
          <button type="button" onClick={onRequestUnlock}>
            Unlock your key
          </button>{" "}
          before enrolling a device.
        </p>
      ) : null}
      {ceremony ? (
        <div className="sec-modal">
          <h4>Enroll {deviceLabel(ceremony.device)}</h4>
          <p className="sec-muted">
            Start enrollment on that device and type the ten-character code it shows. The code is
            good for two to four minutes depending on when the device generated it.
          </p>
          <label>
            Code from your device
            <input
              value={code}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => {
                setCode(e.target.value);
                // Clearing the refusal on edit is what makes it
                // non-click-through-able: the only way past a mismatch is to
                // type something different.
                setFailure("");
              }}
            />
          </label>
          <label>
            Account password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          {failure === "locked" ? (
            <p className="sec-muted">
              Unlock your key before enrolling this device. Nothing was sent.
            </p>
          ) : failure === "mismatch" ? (
            <p className="sec-warn">
              That code does not match. The key this server gave the browser is not the key on that
              device — so your key was NOT sent to it. Do not try again on this server without
              checking with whoever runs it.
            </p>
          ) : failure ? (
            <p className="sec-warn">{failure}</p>
          ) : null}
          <button type="button" disabled={busy || !!failure} onClick={() => void submit()}>
            Verify and enroll
          </button>
          <button type="button" disabled={busy} onClick={() => setCeremony(null)}>
            Cancel
          </button>
        </div>
      ) : null}
    </div>
  );
}
