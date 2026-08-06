import { useCallback, useEffect, useState } from "react";
import { toErrorMessage } from "../api/client";
import { listNativeDevices, type NativeDevice } from "../api/devices";
import { deleteDeviceEnvelope, putDeviceEnvelope } from "../api/pgp";
import { requireUnlockedKey } from "../lib/keyVault";
import {
  explainEnrollmentFailure,
  sealEnvelopeForDevice,
  verifyEnrollmentCode,
  type EnrollmentFailure
} from "../lib/deviceEnrollment";

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
  // Sentinels only — never server- or exception-derived text. `failure`
  // gates the submit button ("mismatch" locks it) and selects the alarming
  // substituted-key copy, so the space it can hold must stay closed to
  // whatever an adversarial server's error text says. Free-text failures go
  // to `ceremonyError` instead.
  const [failure, setFailure] = useState<EnrollmentFailure | "locked" | "">("");
  const [ceremonyError, setCeremonyError] = useState("");
  const [attempts, setAttempts] = useState(0);
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState<NativeDevice | null>(null);
  const [removePassword, setRemovePassword] = useState("");
  const [removeError, setRemoveError] = useState("");

  function openCeremony(device: NativeDevice) {
    // Mutually exclusive with the remove-sealing panel: without this, enrolling
    // one device while a remove confirmation for another is open renders two
    // "Account password" fields at once, inviting an entry into the wrong one.
    setRemoving(null);
    setCeremony({ device, publicKey: device.enrollmentPublicKey ?? "" });
    setCode("");
    setPassword("");
    setFailure("");
    setCeremonyError("");
    setAttempts(0);
  }

  async function submit() {
    if (!ceremony || busy) return;
    setBusy(true);
    setFailure("");
    setCeremonyError("");
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
        // Strictly downstream of the refusal: this only chooses which message
        // to show. Nothing past this point seals, so what it concludes cannot
        // widen what the gate accepted.
        let why: EnrollmentFailure;
        try {
          why = await explainEnrollmentFailure(publicKey, device.deviceId, code);
        } catch (e) {
          // Nothing was sealed or sent — this diagnostic runs strictly after
          // the gate already refused, so a failure here must not read like the
          // "Could not store the sealing." copy below, which implies a store
          // was attempted.
          setCeremonyError(toErrorMessage(e, "Could not check that code. Nothing was sent."));
          return;
        }
        // A malformed entry is a finger, not a server. Spending an attempt on
        // it would end the ceremony over three typos.
        if (why !== "malformed") setAttempts((n) => n + 1);
        setFailure(why);
        return;
      }

      const envelope = await sealEnvelopeForDevice(publicKey, device.deviceId, fingerprint, armored);
      await putDeviceEnvelope(device.deviceId, envelope, password);
      setCeremony(null);
      await refresh();
    } catch (e) {
      setCeremonyError(toErrorMessage(e, "Could not store the sealing."));
    } finally {
      setBusy(false);
    }
  }

  async function removeSealing() {
    if (!removing || busy) return;
    setBusy(true);
    try {
      await deleteDeviceEnvelope(removing.deviceId, removePassword);
      setRemoving(null);
      setRemovePassword("");
      setRemoveError("");
      await refresh();
    } catch (e) {
      // Scoped to the confirmation panel, not the list-level `error` state:
      // that state gates whether the whole device list renders at all, so
      // reusing it here would make a wrong password on ONE device's removal
      // hide every OTHER device from the list underneath the still-open
      // confirmation — the wrong impression for a security-sensitive control.
      setRemoveError(toErrorMessage(e, "Could not remove the sealing."));
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
    // Not a bypass — the ceremony snapshots its key at open time, so an
    // identity change cannot widen what a still-open dialog would seal to.
    // The remove-sealing panel has no such snapshot to protect it and no
    // reason to survive an identity change, so it closes here.
    //
    // The enroll ceremony deliberately does NOT close here: this effect is
    // also the only pre-submit trigger this component has for a second
    // `listNativeDevices` fetch, and the regression test for the snapshot
    // property above (`the gate > seals to the key it verified, not to a
    // later one`) exercises it by rerendering with a new fingerprint while
    // the ceremony is open, precisely to prove the snapshot — not the live
    // list — is what reaches the seal. Auto-closing the ceremony here would
    // make that property untestable through this component's public surface
    // without adding a refresh path that does not otherwise exist yet.
    setRemoving(null);
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
                  <>
                    <p className="sec-muted">This device can read your encrypted mail.</p>
                    <button
                      type="button"
                      onClick={() => {
                        // Mutually exclusive with the enroll ceremony, and a
                        // clean slate: without these, opening this panel while
                        // an enroll ceremony is open renders two "Account
                        // password" fields at once, and reopening this panel
                        // for a different device could still show a password
                        // typed for the last one.
                        setCeremony(null);
                        setRemoving(device);
                        setRemovePassword("");
                        setRemoveError("");
                      }}
                    >
                      Remove sealing
                    </button>
                  </>
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
        <div className="sec-inline-form">
          <h4>Enroll {deviceLabel(ceremony.device)}</h4>
          <p className="sec-muted">
            Start enrollment on that device and type the fourteen-character code it shows. The code is
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
                // Before the state split these were one variable, so editing
                // the code also cleared a transport error. Only clearing
                // `failure` here would leave "Could not store the sealing."
                // on screen while the user retypes.
                setCeremonyError("");
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
          ) : failure === "malformed" ? (
            <p className="sec-muted">
              The code is fourteen characters, shown as XXXXXXX-XXXXXXX. Type all of it.
            </p>
          ) : failure === "expired" ? (
            <p className="sec-muted">
              That code has expired. Ask the device for a fresh one and type it. If this keeps
              happening, check that the device's clock is correct — a clock running fast fails every
              time.
            </p>
          ) : failure === "mismatch" ? (
            <>
              <p className="sec-verdict sec-verdict-risk">
                That code does not match. The key this server gave the browser is not the key on that
                device — so your key was NOT sent to it. Do not try again on this server without
                checking with whoever runs it.
              </p>
              <p className="sec-muted">
                What this does not defend: the server ships this page's JavaScript. A hostile server
                could serve a modified bundle that seals to the right key anyway and leaks it some
                other way — no check running in the browser can catch that, because the browser is
                running code the server chose. This catches a server that stored or served the wrong
                device key; it cannot catch a server that is actively serving you modified code.
              </p>
            </>
          ) : ceremonyError ? (
            <p className="sec-verdict sec-verdict-risk">{ceremonyError}</p>
          ) : null}
          <div className="sec-actions">
            {attempts >= 3 ? (
              <p className="sec-muted">
                Too many failed attempts. Start enrollment again on the device to get a new code.
              </p>
            ) : (
              // Locked only by a mismatch, deliberately. A rejected step-up
              // credential, a locked vault or a transport error are ordinary
              // retryable failures — dead-ending the button behind them would
              // force the user to re-enter a code that is only valid for one or
              // two 120-second buckets, making the forced retry likely to fail as
              // expired. A mismatch is the one refusal that must not be
              // click-through-able.
              <button
                type="button"
                disabled={busy || failure === "mismatch"}
                onClick={() => void submit()}
              >
                Verify and enroll
              </button>
            )}
            <button type="button" disabled={busy} onClick={() => setCeremony(null)}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}
      {removing ? (
        <div className="sec-inline-form">
          <h4>Remove {deviceLabel(removing)}'s sealing</h4>
          <p className="sec-verdict sec-verdict-risk">
            This removes the copy on the server. It does not erase the copy that device already has
            — once a device has taken its sealing, it keeps working offline and the server cannot
            reach it.
          </p>
          <p className="sec-muted">
            To actually stop a device you no longer control from reading new mail, replace your key
            in the section above. That invalidates every device's sealing, and each one you still
            use has to enroll again.
          </p>
          <label>
            Account password
            <input
              type="password"
              value={removePassword}
              onChange={(e) => setRemovePassword(e.target.value)}
            />
          </label>
          {removeError ? <p className="sec-verdict sec-verdict-risk">{removeError}</p> : null}
          <div className="sec-actions">
            <button type="button" disabled={busy} onClick={() => void removeSealing()}>
              Remove it
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setRemoving(null);
                setRemoveError("");
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
