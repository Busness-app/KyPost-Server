import { useState } from "react";
import { toErrorMessage } from "../api/client";
import { waitForDeviceEnrollment, type NativeDevice } from "../api/devices";
import { deleteDeviceEnvelope, putDeviceEnvelope } from "../api/pgp";
import { requireUnlockedKey } from "../lib/keyVault";
import type { MailAccess } from "../pages/security/deviceJoin";
import {
  explainEnrollmentFailure,
  sealEnvelopeForDevice,
  verifyEnrollmentCode,
  type EnrollmentFailure
} from "../lib/deviceEnrollment";

/**
 * Whether a paired device can read encrypted mail — the browser half of device
 * enrollment, rendered in the device's own row.
 *
 * A paired phone cannot open the account's PGP envelope, because that envelope
 * is sealed under the account password and pairing never learns it. Enrollment
 * gives the device its own sealing, opened by its secure element.
 *
 * THE SECURITY OF THIS WHOLE FEATURE IS ONE COMPARISON, and it happens here.
 * The server stores and serves the device's public key, so the server is the
 * party that can substitute its own and then open anything sealed to it. The
 * user types a code the device derived from the key in its own keystore; this
 * panel derives the same code from the key the server handed over. If they
 * differ, the server substituted, and the ceremony refuses to seal.
 *
 * See docs/superpowers/specs/2026-08-05-device-enrollment-2b-design.md and
 * docs/superpowers/specs/2026-08-06-device-mail-access-in-rows-design.md.
 */

export type MailPanel = "none" | "enroll" | "remove";

function deviceLabel(device: NativeDevice): string {
  return device.deviceName?.trim() || device.platform || device.deviceId;
}

/**
 * The row's answer to "can this device read my encrypted mail", plus the
 * control that changes it. Presentational — which panel is open is the parent's
 * business, because only one row may have one open at a time.
 */
export function DeviceMailAccessStatus({
  mailAccess,
  clientProtected,
  fingerprint,
  onOpenPanel,
  onRefresh
}: {
  mailAccess: MailAccess;
  clientProtected: boolean;
  fingerprint: string;
  onOpenPanel: (panel: Exclude<MailPanel, "none">) => void;
  /** Re-reads the device list — see the "unsupported" branch for why. */
  onRefresh: () => void;
}) {
  // Nothing to seal, so nothing to say. The Encryption tab is where an account
  // without a client-held key gets told about it, and a row the inventory does
  // not back has no sealing state to report.
  if (!clientProtected || !fingerprint || mailAccess === "unknown") return null;

  if (mailAccess === "unsupported") {
    // TWO situations, indistinguishable here: a device publishes its key when
    // the ceremony starts ON THE DEVICE, so every phone looks like this between
    // pairing and starting setup — not only one whose app predates the feature.
    // Naming the second reading alone sent users with a current app off to pair
    // again, from the one row they would think to look at.
    //
    // "Check again" because the event that ends this state happens on the other
    // device, and this list is fetched on mount. Without it a browser opened
    // before the phone published cannot reach the ceremony at all, however long
    // the user waits.
    return (
      <>
        <p className="sec-muted">
          Not set up for encrypted mail. Start encryption setup on the device itself, then check
          again here. If it offers no such option, its app is too old to be enrolled.
        </p>
        <button type="button" onClick={onRefresh}>
          Check again
        </button>
      </>
    );
  }
  if (mailAccess === "enrolled") {
    return (
      <>
        <p className="sec-muted">This device can read your encrypted mail.</p>
        <button type="button" onClick={() => onOpenPanel("remove")}>
          Remove sealing
        </button>
      </>
    );
  }
  return (
    <>
      <p className="sec-muted">Not enrolled. It cannot read your encrypted mail.</p>
      <button type="button" onClick={() => onOpenPanel("enroll")}>
        Enroll
      </button>
    </>
  );
}

/**
 * The open ceremony or removal confirmation for one row, or nothing.
 *
 * Rendering nothing is what unmounts the panel's state. That is how a password
 * typed into one device's confirmation cannot survive into another's — there is
 * no clearing code to forget to write.
 */
export function DeviceMailPanel({
  device,
  panel,
  fingerprint,
  unlocked,
  onRequestUnlock,
  onClose,
  onChanged,
  awaitEnrollment = waitForDeviceEnrollment
}: {
  device: NativeDevice;
  panel: MailPanel;
  fingerprint: string;
  unlocked: boolean;
  onRequestUnlock: () => void;
  onClose: () => void;
  onChanged: () => void;
  /** Injectable so tests need not wait on real polling. */
  awaitEnrollment?: (deviceId: string) => Promise<boolean>;
}) {
  if (panel === "enroll") {
    return (
      // Keyed on the device so pointing the panel at a different one remounts
      // the ceremony, and so re-takes the key snapshot below.
      <EnrollPanel
        key={device.deviceId}
        device={device}
        fingerprint={fingerprint}
        unlocked={unlocked}
        onRequestUnlock={onRequestUnlock}
        onClose={onClose}
        onChanged={onChanged}
        awaitEnrollment={awaitEnrollment}
      />
    );
  }
  if (panel === "remove") {
    return (
      <RemovePanel key={device.deviceId} device={device} onClose={onClose} onChanged={onChanged} />
    );
  }
  return null;
}

function EnrollPanel({
  device,
  fingerprint,
  unlocked,
  onRequestUnlock,
  onClose,
  onChanged,
  awaitEnrollment
}: {
  device: NativeDevice;
  fingerprint: string;
  unlocked: boolean;
  onRequestUnlock: () => void;
  onClose: () => void;
  onChanged: () => void;
  awaitEnrollment: (deviceId: string) => Promise<boolean>;
}) {
  // THE SNAPSHOT. Captured once, when this panel mounts, and never re-read from
  // props. Verifying against one answer and sealing against another would let a
  // server answer honestly once and hostilely once — the comparison passes on
  // bytes that are never sealed to, which is the exact attack the comparison
  // exists to catch, arriving through a later render. The panel unmounts when
  // it closes, so reopening re-snapshots.
  const [publicKey] = useState(() => device.enrollmentPublicKey ?? "");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  // Sentinels only — never server- or exception-derived text. `failure` gates
  // the submit button ("mismatch" locks it) and selects the alarming
  // substituted-key copy, so the space it can hold must stay closed to whatever
  // an adversarial server's error text says. Free-text failures go to
  // `ceremonyError` instead.
  const [failure, setFailure] = useState<EnrollmentFailure | "locked" | "">("");
  const [ceremonyError, setCeremonyError] = useState("");
  const [attempts, setAttempts] = useState(0);
  const [busy, setBusy] = useState(false);
  // The second party's half of the ceremony. "waiting" is after a stored PUT
  // while the device has not answered; "pending" is that wait timing out, which
  // is a slow device and not a failed enrollment.
  const [confirming, setConfirming] = useState<"" | "waiting" | "pending">("");

  async function submit() {
    if (busy) return;
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

      // PAST THE POINT OF FAILURE. The sealing is stored; nothing below may
      // word itself as an error. All that is left is whether the device has
      // picked it up yet, and only the device can answer that — it reports
      // `encryptionEnrolled` itself, on its own route, after fetching and
      // opening this envelope. Reading the inventory at this instant always
      // says "not enrolled", which is how a success came to be shown as a
      // failure until the user reloaded the page.
      setConfirming("waiting");
      const confirmed = await awaitEnrollment(device.deviceId);
      onChanged();
      if (confirmed) {
        onClose();
        return;
      }
      setConfirming("pending");
    } catch (e) {
      setCeremonyError(toErrorMessage(e, "Could not store the sealing."));
    } finally {
      setBusy(false);
    }
  }

  // Both of these are downstream of a stored sealing, so the panel stops being
  // a form: there is nothing left to submit and nothing left that can fail.
  if (confirming === "waiting") {
    return (
      <div className="sec-inline-form">
        <h4>Enroll {deviceLabel(device)}</h4>
        {/* A live indicator for the same reason LoginPage's approval wait has
            one: without it, waiting on another device is indistinguishable
            from a stalled page. */}
        <p className="auth-waiting-row">
          <span className="auth-waiting" aria-hidden="true">
            <span />
            <span />
            <span />
          </span>
          Sealed. Waiting for {deviceLabel(device)} to confirm…
        </p>
      </div>
    );
  }

  if (confirming === "pending") {
    return (
      <div className="sec-inline-form">
        <h4>Enroll {deviceLabel(device)}</h4>
        <p className="sec-muted">
          Your key is sealed and stored for {deviceLabel(device)}. It hasn't confirmed yet — it will
          pick this up the next time it syncs, and this page will say so once it does. You do not
          need to enroll it again.
        </p>
        <div className="sec-actions">
          <button type="button" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="sec-inline-form">
      <h4>Enroll {deviceLabel(device)}</h4>
      <p className="sec-muted">
        Start enrollment on that device and type the fourteen-character code it shows. The code is
        good for two to four minutes depending on when the device generated it.
      </p>
      {!unlocked ? (
        <p className="sec-muted">
          <button type="button" onClick={onRequestUnlock}>
            Unlock your key
          </button>{" "}
          before enrolling this device.
        </p>
      ) : null}
      <label>
        Code from your device
        <input
          value={code}
          autoComplete="off"
          spellCheck={false}
          onChange={(e) => {
            setCode(e.target.value);
            // Clearing the refusal on edit is what makes it
            // non-click-through-able: the only way past a mismatch is to type
            // something different.
            setFailure("");
            // Before the state split these were one variable, so editing the
            // code also cleared a transport error. Only clearing `failure` here
            // would leave "Could not store the sealing." on screen while the
            // user retypes.
            setCeremonyError("");
          }}
        />
      </label>
      <label>
        Account password
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      {failure === "locked" ? (
        <p className="sec-muted">Unlock your key before enrolling this device. Nothing was sent.</p>
      ) : failure === "malformed" ? (
        <p className="sec-muted">
          The code is fourteen characters, shown as XXXX-XXX-XXXX-XXX. Type all of it.
        </p>
      ) : failure === "expired" ? (
        <p className="sec-muted">
          That code has expired. Ask the device for a fresh one and type it. If this keeps happening,
          check that the device's clock is correct — a clock running fast fails every time.
        </p>
      ) : failure === "mismatch" ? (
        <>
          <p className="sec-verdict sec-verdict-risk">
            That code does not match. The key this server gave the browser is not the key on that
            device — so your key was NOT sent to it. Do not try again on this server without checking
            with whoever runs it.
          </p>
          <p className="sec-muted">
            What this does not defend: the server ships this page's JavaScript. A hostile server could
            serve a modified bundle that seals to the right key anyway and leaks it some other way —
            no check running in the browser can catch that, because the browser is running code the
            server chose. This catches a server that stored or served the wrong device key; it cannot
            catch a server that is actively serving you modified code.
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
          // retryable failures — dead-ending the button behind them would force
          // the user to re-enter a code that is only valid for one or two
          // 120-second buckets, making the forced retry likely to fail as
          // expired. A mismatch is the one refusal that must not be
          // click-through-able.
          <button type="button" disabled={busy || failure === "mismatch"} onClick={() => void submit()}>
            Verify and enroll
          </button>
        )}
        <button type="button" disabled={busy} onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function RemovePanel({
  device,
  onClose,
  onChanged
}: {
  device: NativeDevice;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [removePassword, setRemovePassword] = useState("");
  const [removeError, setRemoveError] = useState("");
  const [busy, setBusy] = useState(false);
  const [removed, setRemoved] = useState(false);

  async function removeSealing() {
    if (busy) return;
    setBusy(true);
    try {
      await deleteDeviceEnvelope(device.deviceId, removePassword);
      onChanged();
      setRemoved(true);
    } catch (e) {
      // Scoped to this panel, never to anything that gates the device list:
      // a wrong password on ONE device's removal must not hide every OTHER
      // device underneath the still-open confirmation — the wrong impression
      // for a security-sensitive control.
      setRemoveError(toErrorMessage(e, "Could not remove the sealing."));
    } finally {
      setBusy(false);
    }
  }

  // Downstream of a stored deletion, so this stops being a form — and it has to
  // say something. The row above reads `encryptionEnrolled`, which ONLY the
  // device writes, so a successful removal leaves the row saying the device can
  // still read the mail. Closing silently made that indistinguishable from a
  // button that did nothing, and for a device enrolled longer than the seven-day
  // transport TTL there was genuinely nothing left on the server to delete.
  if (removed) {
    return (
      <div className="sec-inline-form">
        <h4>Remove {deviceLabel(device)}'s sealing</h4>
        <p className="sec-muted">
          The server's copy is gone. {deviceLabel(device)} keeps the copy it already took, so this
          row still shows it as able to read your mail — only that device can report otherwise. To
          cut it off, replace your key on the Encryption tab.
        </p>
        <div className="sec-actions">
          <button type="button" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="sec-inline-form">
      <h4>Remove {deviceLabel(device)}'s sealing</h4>
      <p className="sec-verdict sec-verdict-risk">
        This removes the copy on the server. It does not erase the copy that device already has —
        once a device has taken its sealing, it keeps working offline and the server cannot reach it.
      </p>
      <p className="sec-muted">
        To actually stop a device you no longer control from reading new mail, replace your key on
        the Encryption tab. That invalidates every device's sealing, and each one you still use has
        to enroll again.
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
        <button type="button" disabled={busy} onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}
