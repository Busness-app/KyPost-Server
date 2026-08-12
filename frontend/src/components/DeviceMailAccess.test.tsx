import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DeviceMailAccessStatus, DeviceMailPanel, type MailPanel } from "./DeviceMailAccess";
import type { NativeDevice } from "../api/devices";
import type { MailAccess } from "../pages/security/deviceJoin";
import { deriveEnrollmentCode, bucketFor } from "../lib/deviceEnrollment";

vi.mock("../api/client", () => ({
  toErrorMessage: (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback)
}));

const putDeviceEnvelope = vi.fn();
const deleteDeviceEnvelope = vi.fn();
const requireUnlockedKey = vi.fn();

vi.mock("../api/pgp", () => ({
  putDeviceEnvelope: (id: string, envelope: unknown, password: string) =>
    putDeviceEnvelope(id, envelope, password),
  deleteDeviceEnvelope: (id: string, password: string) => deleteDeviceEnvelope(id, password)
}));

vi.mock("../lib/keyVault", () => ({
  requireUnlockedKey: () => requireUnlockedKey()
}));

// deviceEnrollment is NOT mocked away — a test with a mocked derivation tests
// the mock, and "a substituted key" has to mean an actually different key
// producing an actually different code. The seal is wrapped in a spy only so a
// test can see WHICH key bytes reached it, and still runs for real.
const sealSpy = vi.fn();
vi.mock("../lib/deviceEnrollment", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/deviceEnrollment")>();
  return {
    ...actual,
    sealEnvelopeForDevice: (...args: Parameters<typeof actual.sealEnvelopeForDevice>) => {
      sealSpy(...args);
      return actual.sealEnvelopeForDevice(...args);
    }
  };
});

// A real, valid P-256 point, so sealEnvelopeForDevice's ECDH import succeeds.
// Generated once at module load rather than hard-coded, because a fixed point
// would have to be checked by hand against the curve.
const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
  "deriveBits"
]);
const HONEST_KEY = btoa(
  String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey)))
);

const otherPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
  "deriveBits"
]);
const SUBSTITUTED_KEY = btoa(
  String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("raw", otherPair.publicKey)))
);

async function codeFor(publicKeyB64: string, deviceId = "d1"): Promise<string> {
  return deriveEnrollmentCode(publicKeyB64, deviceId, bucketFor(Math.floor(Date.now() / 1000)));
}

async function startCeremony() {
  await userEvent.click(await screen.findByRole("button", { name: "Enroll" }));
}

async function submitCeremony(code: string, password = "hunter2") {
  await userEvent.type(screen.getByLabelText("Code from your device"), code);
  await userEvent.type(screen.getByLabelText("Account password"), password);
  await userEvent.click(screen.getByRole("button", { name: "Verify and enroll" }));
}

function device(over: Partial<NativeDevice> = {}): NativeDevice {
  return {
    deviceId: "d1",
    platform: "android",
    pushToken: "tok",
    deviceName: "Pixel",
    encryptionEnrolled: false,
    ...over
  };
}

// A stateful harness, so "click Enroll then submit" reads the same here as it
// does in the app: the parent owns which panel is open, the row asks for it.
function Harness({
  dev = device({ enrollmentPublicKey: HONEST_KEY }),
  mailAccess = "available" as MailAccess,
  clientProtected = true,
  fingerprint = "AAAA1111BBBB2222",
  unlocked = true,
  onRequestUnlock = () => {},
  onRefresh = () => {},
  onChanged = () => {},
  // Confirmed by default: the tests below are about the ceremony, not about
  // the wait, and an unset one would fall through to the real poller and keep
  // running after teardown.
  awaitEnrollment = async () => true
}: {
  dev?: NativeDevice;
  mailAccess?: MailAccess;
  clientProtected?: boolean;
  fingerprint?: string;
  unlocked?: boolean;
  onRequestUnlock?: () => void;
  onRefresh?: () => void;
  onChanged?: () => void;
  awaitEnrollment?: (deviceId: string) => Promise<boolean>;
}) {
  const [panel, setPanel] = useState<MailPanel>("none");
  return (
    <>
      <DeviceMailAccessStatus
        mailAccess={mailAccess}
        clientProtected={clientProtected}
        fingerprint={fingerprint}
        onOpenPanel={setPanel}
        onRefresh={onRefresh}
      />
      <DeviceMailPanel
        device={dev}
        panel={panel}
        fingerprint={fingerprint}
        unlocked={unlocked}
        onRequestUnlock={onRequestUnlock}
        onClose={() => setPanel("none")}
        onChanged={onChanged}
        awaitEnrollment={awaitEnrollment}
      />
    </>
  );
}

const enrolledDevice = () =>
  device({ enrollmentPublicKey: HONEST_KEY, encryptionEnrolled: true });

afterEach(cleanup);

beforeEach(() => {
  putDeviceEnvelope.mockReset();
  deleteDeviceEnvelope.mockReset();
  requireUnlockedKey.mockReset();
  sealSpy.mockReset();
  putDeviceEnvelope.mockResolvedValue({ ok: true });
  deleteDeviceEnvelope.mockResolvedValue({ ok: true });
  requireUnlockedKey.mockReturnValue("-----BEGIN PGP PRIVATE KEY BLOCK-----");
});

describe("the status cell", () => {
  it("offers enrollment for a device that has published a key", () => {
    render(<Harness />);
    expect(screen.getByText("Not enrolled. It cannot read your encrypted mail.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Enroll" })).toBeTruthy();
  });

  // A device publishes its key when the ceremony starts ON THE DEVICE, so this
  // is the state every phone is in between pairing and starting setup — not
  // only the state of an app too old to have the feature. The copy used to name
  // the second reading only, sending a user with a current app off to pair
  // again, and the row it appears in is the one place they would look.
  it("points a device that has published no key at its own setup", () => {
    render(<Harness mailAccess="unsupported" />);
    expect(screen.getByText(/start encryption setup on the device itself/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Enroll" })).toBeNull();
  });

  // The list is fetched on mount, and the event that ends this state happens on
  // the OTHER device. Without a way to re-read it, a browser opened before the
  // phone published its key can never reach the ceremony at all.
  it("re-reads the device list on request", async () => {
    const onRefresh = vi.fn();
    render(<Harness mailAccess="unsupported" onRefresh={onRefresh} />);

    await userEvent.click(screen.getByRole("button", { name: "Check again" }));

    expect(onRefresh).toHaveBeenCalled();
  });

  it("shows an enrolled device as able to read encrypted mail", () => {
    render(<Harness mailAccess="enrolled" />);
    expect(screen.getByText("This device can read your encrypted mail.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Remove sealing" })).toBeTruthy();
  });

  // Nothing to seal without a client-held key: the Encryption tab already tells
  // that story, and repeating it here as a broken affordance is worse.
  it("renders nothing when the account holds no client-protected key", () => {
    const { container } = render(
      <DeviceMailAccessStatus
        mailAccess="available"
        clientProtected={false}
        fingerprint="AAAA"
        onOpenPanel={() => {}}
        onRefresh={() => {}}
      />
    );
    expect(container.firstChild).toBeNull();
  });

  // Only the inventory knows about sealings, so a row it does not back has no
  // answer — and must not render the reassuring guess.
  it("renders nothing for a row the inventory does not back", () => {
    const { container } = render(
      <DeviceMailAccessStatus
        mailAccess="unknown"
        clientProtected
        fingerprint="AAAA"
        onOpenPanel={() => {}}
        onRefresh={() => {}}
      />
    );
    expect(container.firstChild).toBeNull();
  });
});

describe("the gate", () => {
  // THE test. A hostile server serves its own key; the user types the code
  // their phone actually shows. Assert the ABSENCE of the request, not the
  // presence of a warning — a warning beside a sent request is the failure
  // this whole design exists to prevent.
  it("issues no PUT when the served key is not the device's key", async () => {
    render(<Harness dev={device({ enrollmentPublicKey: SUBSTITUTED_KEY })} />);
    await startCeremony();

    await submitCeremony(await codeFor(HONEST_KEY));

    // Awaited first: the async chain (WebCrypto digests) has not necessarily
    // finished the instant the click's await resolves — the happy-path test
    // below proves that with its own vi.waitFor. Asserting the absence of the
    // PUT before the ceremony has settled would be vacuous; waiting for the
    // rendered refusal first proves the chain reached its message, but under a
    // warn-then-seal shape the message can paint before the PUT fires — so
    // also wait for `busy` to clear (the Cancel button is disabled by `busy`
    // alone) before trusting the absence assertion below.
    expect(await screen.findByText(/not the key on that device/i)).toBeTruthy();
    await vi.waitFor(() =>
      expect(screen.getByRole("button", { name: "Cancel" }).hasAttribute("disabled")).toBe(false)
    );
    expect(putDeviceEnvelope).not.toHaveBeenCalled();
  });

  it("seals and uploads when the code matches", async () => {
    render(<Harness />);
    await startCeremony();

    await submitCeremony(await codeFor(HONEST_KEY));

    await vi.waitFor(() => expect(putDeviceEnvelope).toHaveBeenCalledTimes(1));
    const [deviceId, envelope, password] = putDeviceEnvelope.mock.calls[0];
    expect(deviceId).toBe("d1");
    expect(password).toBe("hunter2");
    expect(envelope.alg).toBe("ECDH-P256+HKDF-SHA256+A256GCM");
  });

  // The original attack arriving through the back door of a later render:
  // verify against an honest key, then seal against whatever the props hold
  // now. The panel snapshots the key when it mounts, so a mid-ceremony change
  // cannot alter what gets sealed to.
  it("seals to the key it verified, not to a later one", async () => {
    const { rerender } = render(<Harness dev={device({ enrollmentPublicKey: HONEST_KEY })} />);
    await startCeremony();

    // The server flips its answer after the panel is open. Rerendering with the
    // substituted key is the props-level equivalent of the refetch this used to
    // be exposed to — if the panel read the key at seal time, this is where it
    // would pick up the wrong bytes.
    rerender(<Harness dev={device({ enrollmentPublicKey: SUBSTITUTED_KEY })} />);

    await submitCeremony(await codeFor(HONEST_KEY));

    await vi.waitFor(() => expect(putDeviceEnvelope).toHaveBeenCalledTimes(1));
    // The assertion that carries the property: the bytes handed to the seal are
    // the bytes that were verified, not the ones the props hold now.
    expect(sealSpy.mock.calls[0][0]).toBe(HONEST_KEY);
    expect(sealSpy.mock.calls[0][0]).not.toBe(SUBSTITUTED_KEY);
  });

  // A locked vault is mundane. Reporting it as a mismatch would show the most
  // alarming message in the product for the most ordinary cause.
  it("refuses a locked vault without calling it a mismatch", async () => {
    requireUnlockedKey.mockImplementation(() => {
      throw new Error("vault is locked");
    });
    render(<Harness />);
    await startCeremony();

    await submitCeremony(await codeFor(HONEST_KEY));

    // Awaited first for the same reason as the mismatch test above: it proves
    // the ceremony has reached the message. Then wait for `busy` to clear
    // (Cancel disables only on `busy`) before trusting the absence assertion —
    // under a warn-then-seal shape the message can paint before the PUT fires.
    expect(await screen.findByText(/nothing was sent/i)).toBeTruthy();
    await vi.waitFor(() =>
      expect(screen.getByRole("button", { name: "Cancel" }).hasAttribute("disabled")).toBe(false)
    );
    expect(putDeviceEnvelope).not.toHaveBeenCalled();
    expect(screen.queryByText(/not the key on that device/i)).toBeNull();
  });

  // There is no "seal anyway" — the refusal is not click-through-able because
  // there is nothing to click. Stronger than a warning asked to be respected.
  it("offers no way from a refusal to a seal", async () => {
    render(<Harness dev={device({ enrollmentPublicKey: SUBSTITUTED_KEY })} />);
    await startCeremony();
    await submitCeremony(await codeFor(HONEST_KEY));

    // Awaited first: the button is also disabled while the submit is in
    // flight (`busy`), so reading `disabled` before the mismatch has rendered
    // cannot distinguish "locked by the refusal" from "still working". Waiting
    // for the rendered mismatch first proves `busy` has cleared via the
    // `finally`, so the assertion below is pinned on `failure`, not on timing.
    await screen.findByText(/not the key on that device/i);

    expect(screen.queryByRole("button", { name: /anyway|continue|proceed|override/i })).toBeNull();
    // The submit button is disabled until the entry actually changes.
    expect(screen.getByRole("button", { name: "Verify and enroll" }).hasAttribute("disabled")).toBe(
      true
    );
    // `busy` clearing is what proves the async chain actually finished, not
    // just that the mismatch message painted — see the gate's "issues no PUT"
    // test for why that distinction matters under a warn-then-seal shape.
    await vi.waitFor(() =>
      expect(screen.getByRole("button", { name: "Cancel" }).hasAttribute("disabled")).toBe(false)
    );
    expect(putDeviceEnvelope).not.toHaveBeenCalled();
  });

  // Only a mismatch is non-click-through-able: a rejected step-up credential,
  // a locked vault, or a transport error is an ordinary retryable failure and
  // must not dead-end the ceremony behind a disabled button the user cannot
  // recover from without perturbing the (time-boxed) code field. The sibling
  // test above already pins that a mismatch stays disabled; this one pins the
  // other half in the same ceremony — a retryable failure re-enables, and a
  // mismatch reached afterward still locks it.
  it("re-enables submit after a retryable failure, but a mismatch still locks it", async () => {
    putDeviceEnvelope.mockRejectedValueOnce(new Error("wrong password"));
    render(<Harness />);
    await startCeremony();

    await submitCeremony(await codeFor(HONEST_KEY));

    await screen.findByText("wrong password");
    expect(screen.getByRole("button", { name: "Verify and enroll" }).hasAttribute("disabled")).toBe(
      false
    );

    // A well-formed but deliberately wrong code: still fourteen valid characters,
    // so this exercises the mismatch branch rather than the length check.
    const codeInput = screen.getByLabelText("Code from your device");
    await userEvent.clear(codeInput);
    await userEvent.type(codeInput, "00000000000000");
    await userEvent.click(screen.getByRole("button", { name: "Verify and enroll" }));

    await screen.findByText(/not the key on that device/i);
    expect(screen.getByRole("button", { name: "Verify and enroll" }).hasAttribute("disabled")).toBe(
      true
    );
  });
});

// The ceremony has two parties and only one of them is this browser. The PUT
// stores the sealed envelope; `encryptionEnrolled` is written ONLY by the
// device, on a device-authenticated route, after it has fetched that envelope
// and opened it. So at the instant the PUT returns, the device is still
// correctly reported as not enrolled — and reporting that as the outcome of the
// ceremony calls a success a failure.
describe("waiting for the device to confirm", () => {
  function deferred<T>() {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>((r) => {
      resolve = r;
    });
    return { promise, resolve };
  }

  it("keeps waiting instead of declaring an outcome when the PUT returns", async () => {
    const gate = deferred<boolean>();
    render(<Harness awaitEnrollment={() => gate.promise} />);
    await startCeremony();
    await submitCeremony(await codeFor(HONEST_KEY));

    await vi.waitFor(() => expect(putDeviceEnvelope).toHaveBeenCalledTimes(1));

    // Still on screen, still waiting — not closed, and not calling it done.
    expect(await screen.findByText(/waiting for Pixel to confirm/i)).toBeTruthy();
    gate.resolve(true);
  });

  it("reports success once the device confirms", async () => {
    const onChanged = vi.fn();
    render(<Harness awaitEnrollment={async () => true} onChanged={onChanged} />);
    await startCeremony();
    await submitCeremony(await codeFor(HONEST_KEY));

    await vi.waitFor(() => expect(onChanged).toHaveBeenCalled());
    // Closed: the row behind it now tells the story.
    await vi.waitFor(() =>
      expect(screen.queryByLabelText("Code from your device")).toBeNull()
    );
  });

  // The defect this whole describe exists for. A device that has not answered
  // yet has not failed — the key IS sealed and stored for it. Saying otherwise
  // sends the user to redo work that already succeeded.
  it("does not call a stored sealing a failure when the device is slow", async () => {
    render(<Harness awaitEnrollment={async () => false} />);
    await startCeremony();
    await submitCeremony(await codeFor(HONEST_KEY));

    const note = await screen.findByText(/hasn't confirmed yet/i);
    expect(note).toBeTruthy();
    expect(note.textContent).toMatch(/sealed and stored/i);
    // No failure language anywhere in the panel.
    expect(screen.queryByText(/could not store the sealing/i)).toBeNull();
    expect(screen.queryByText(/not the key on that device/i)).toBeNull();
  });
});

describe("the failure taxonomy", () => {
  it("reports an expired code as expiry, not as a substituted key", async () => {
    render(<Harness />);
    await startCeremony();

    const stale = await deriveEnrollmentCode(
      HONEST_KEY,
      "d1",
      bucketFor(Math.floor(Date.now() / 1000)) - 5
    );
    await submitCeremony(stale);

    // Wait for the message, then for `busy` to clear (Cancel disables only on
    // `busy`), before trusting the absence of the PUT — see the gate's
    // "issues no PUT" test above for why the ordering matters under a
    // warn-then-seal shape.
    expect(await screen.findByText(/expired/i)).toBeTruthy();
    await vi.waitFor(() =>
      expect(screen.getByRole("button", { name: "Cancel" }).hasAttribute("disabled")).toBe(false)
    );
    expect(putDeviceEnvelope).not.toHaveBeenCalled();
    expect(screen.queryByText(/not the key on that device/i)).toBeNull();
  });

  it("names a short entry as incomplete rather than as a mismatch", async () => {
    render(<Harness />);
    await startCeremony();

    await submitCeremony("5R9K6");

    // Wait for the message, then for `busy` to clear (Cancel disables only on
    // `busy`), before trusting the absence of the PUT — see the gate's
    // "issues no PUT" test above for why the ordering matters under a
    // warn-then-seal shape.
    expect(await screen.findByText(/fourteen characters/i)).toBeTruthy();
    await vi.waitFor(() =>
      expect(screen.getByRole("button", { name: "Cancel" }).hasAttribute("disabled")).toBe(false)
    );
    expect(putDeviceEnvelope).not.toHaveBeenCalled();
    expect(screen.queryByText(/not the key on that device/i)).toBeNull();
  });

  // Three, not one. The MFA control allows a single attempt because guessing
  // is cheap there; here guessing fifty bits is hopeless and typos are not.
  it("aborts the ceremony after three real attempts", async () => {
    render(<Harness dev={device({ enrollmentPublicKey: SUBSTITUTED_KEY })} />);
    await startCeremony();

    for (let i = 0; i < 3; i += 1) {
      const field = screen.getByLabelText("Code from your device");
      await userEvent.clear(field);
      await userEvent.type(field, await codeFor(HONEST_KEY));
      if (i === 0) await userEvent.type(screen.getByLabelText("Account password"), "hunter2");
      const submit = screen.queryByRole("button", { name: "Verify and enroll" });
      if (submit) await userEvent.click(submit);
    }

    // Wait for the abort message, then for `busy` to clear, before trusting
    // the absence of the PUT — same reasoning as the gate's "issues no PUT"
    // test: the Cancel button disables on `busy` alone, so it is the
    // observable that proves `submit` ran its `finally`.
    expect(await screen.findByText(/start enrollment again on the device/i)).toBeTruthy();
    await vi.waitFor(() =>
      expect(screen.getByRole("button", { name: "Cancel" }).hasAttribute("disabled")).toBe(false)
    );
    expect(putDeviceEnvelope).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Verify and enroll" })).toBeNull();
  });

  // A malformed entry is the user's finger, not the server's key. Spending an
  // attempt on it would end the ceremony over three typos.
  it("does not spend an attempt on a malformed entry", async () => {
    render(<Harness />);
    await startCeremony();

    for (let i = 0; i < 4; i += 1) {
      const field = screen.getByLabelText("Code from your device");
      await userEvent.clear(field);
      await userEvent.type(field, "5R9K6");
      if (i === 0) await userEvent.type(screen.getByLabelText("Account password"), "hunter2");
      await userEvent.click(screen.getByRole("button", { name: "Verify and enroll" }));
    }

    expect(screen.queryByText(/start enrollment again on the device/i)).toBeNull();
    expect(screen.getByRole("button", { name: "Verify and enroll" })).toBeTruthy();
  });
});

describe("revocation", () => {
  // The honest sentence. Without it "remove" reads as revocation, and the user
  // walks away believing a phone they no longer control cannot read their mail.
  it("says removal does not reach what the device already holds", async () => {
    render(<Harness mailAccess="enrolled" dev={enrolledDevice()} />);

    await userEvent.click(await screen.findByRole("button", { name: "Remove sealing" }));

    expect(await screen.findByText(/does not erase the copy that device already has/i)).toBeTruthy();
    expect(await screen.findByText(/replace your key/i)).toBeTruthy();
  });

  // The row's answer comes from `encryptionEnrolled`, which only the DEVICE
  // writes — so a successful removal changes nothing the user can see, and the
  // panel closing on its own was indistinguishable from a button that did
  // nothing. Say what happened instead.
  it("reports what a removal changed rather than closing silently", async () => {
    render(<Harness mailAccess="enrolled" dev={enrolledDevice()} />);
    await userEvent.click(await screen.findByRole("button", { name: "Remove sealing" }));

    await userEvent.type(screen.getByLabelText("Account password"), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: "Remove it" }));

    expect(await screen.findByText(/server's copy is gone/i)).toBeTruthy();
    // And why the row above it still says the device can read the mail.
    expect(screen.getByText(/only that device can report/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Done" })).toBeTruthy();
  });

  it("removes the server's copy with the account credential", async () => {
    render(<Harness mailAccess="enrolled" dev={enrolledDevice()} />);
    await userEvent.click(await screen.findByRole("button", { name: "Remove sealing" }));

    await userEvent.type(screen.getByLabelText("Account password"), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: "Remove it" }));

    await vi.waitFor(() => expect(deleteDeviceEnvelope).toHaveBeenCalledWith("d1", "hunter2"));
  });

  // Pins the review finding: a wrong step-up credential is a routine failure
  // for this control, and it must read as "this removal failed" — not as
  // "we can't see your paired devices," which is what happened when the
  // handler borrowed the fetch-level error state that gates the whole list.
  // Structural now — this panel has no state that could gate a list — but the
  // assertion stays, because that is the property, not the implementation.
  it("keeps the error scoped to the confirmation when a removal fails", async () => {
    deleteDeviceEnvelope.mockRejectedValue(new Error("wrong password"));
    render(<Harness mailAccess="enrolled" dev={enrolledDevice()} />);
    await userEvent.click(await screen.findByRole("button", { name: "Remove sealing" }));

    await userEvent.type(screen.getByLabelText("Account password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Remove it" }));

    expect(await screen.findByText("wrong password")).toBeTruthy();
    // The confirmation is still open and still names its device.
    expect(screen.getByText(/Pixel/)).toBeTruthy();
    expect(screen.queryByText(/could not read your paired devices/i)).toBeNull();
  });
});

describe("panel exclusivity", () => {
  it("shows one panel at a time, so two password fields never coexist", async () => {
    render(<Harness mailAccess="enrolled" dev={enrolledDevice()} />);
    await userEvent.click(screen.getByRole("button", { name: "Remove sealing" }));
    expect(screen.getAllByLabelText("Account password")).toHaveLength(1);
  });

  // No clearing code to forget to write: closing unmounts the panel, so the
  // typed password goes with it.
  it("forgets a typed password when the panel closes", async () => {
    render(<Harness mailAccess="enrolled" dev={enrolledDevice()} />);
    await userEvent.click(screen.getByRole("button", { name: "Remove sealing" }));
    await userEvent.type(screen.getByLabelText("Account password"), "typed-here");
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));

    await userEvent.click(screen.getByRole("button", { name: "Remove sealing" }));
    expect((screen.getByLabelText("Account password") as HTMLInputElement).value).toBe("");
  });
});
