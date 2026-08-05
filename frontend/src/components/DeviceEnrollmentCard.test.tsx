import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DeviceEnrollmentCard } from "./DeviceEnrollmentCard";
import type { NativeDevice } from "../api/devices";
import { deriveEnrollmentCode, bucketFor } from "../lib/deviceEnrollment";

const listNativeDevices = vi.fn();
vi.mock("../api/devices", () => ({ listNativeDevices: () => listNativeDevices() }));
vi.mock("../api/client", () => ({
  toErrorMessage: (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback)
}));

const putDeviceEnvelope = vi.fn();
const requireUnlockedKey = vi.fn();

vi.mock("../api/pgp", () => ({
  putDeviceEnvelope: (id: string, envelope: unknown, password: string) =>
    putDeviceEnvelope(id, envelope, password)
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

function renderCard(over: Partial<Parameters<typeof DeviceEnrollmentCard>[0]> = {}) {
  return render(
    <DeviceEnrollmentCard
      fingerprint="AAAA1111BBBB2222"
      clientProtected
      unlocked
      onRequestUnlock={() => {}}
      {...over}
    />
  );
}

afterEach(cleanup);

beforeEach(() => {
  listNativeDevices.mockReset();
  listNativeDevices.mockResolvedValue({ devices: [] });
  putDeviceEnvelope.mockReset();
  requireUnlockedKey.mockReset();
  sealSpy.mockReset();
  putDeviceEnvelope.mockResolvedValue({ ok: true });
  requireUnlockedKey.mockReturnValue("-----BEGIN PGP PRIVATE KEY BLOCK-----");
});

describe("DeviceEnrollmentCard", () => {
  it("offers enrollment for a device that has published a key", async () => {
    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: "KEY" })] });
    renderCard();

    expect(await screen.findByText("Pixel")).toBeTruthy();
    expect(await screen.findByRole("button", { name: "Enroll" })).toBeTruthy();
  });

  // Self-gating: until the mobile half ships, every device looks like this, so
  // the card offers nothing rather than a button leading nowhere.
  it("offers nothing for a device that has published no key", async () => {
    listNativeDevices.mockResolvedValue({ devices: [device()] });
    renderCard();

    expect(await screen.findByText("Pixel")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Enroll" })).toBeNull();
  });

  it("shows an enrolled device as able to read encrypted mail", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: "KEY", encryptionEnrolled: true })]
    });
    renderCard();

    expect(await screen.findByText(/can read your encrypted mail/i)).toBeTruthy();
  });

  // Nothing to seal without a client-held key: the PGP card above already
  // tells that story, and repeating it here as a broken affordance is worse.
  it("renders nothing when the account holds no client-protected key", () => {
    const { container } = renderCard({ clientProtected: false });
    expect(container.firstChild).toBeNull();
  });

  // Replacing the identity clears every non-password slot on the server, so a
  // list cached across that change would keep showing devices as able to read
  // mail they can no longer open.
  it("re-reads the list when the identity changes", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: "KEY", encryptionEnrolled: true })]
    });
    const { rerender } = renderCard();
    await screen.findByText("Pixel");
    expect(listNativeDevices).toHaveBeenCalledTimes(1);

    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: "KEY" })] });
    rerender(
      <DeviceEnrollmentCard
        fingerprint="CCCC3333DDDD4444"
        clientProtected
        unlocked
        onRequestUnlock={() => {}}
      />
    );

    await vi.waitFor(() => expect(listNativeDevices).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/not enrolled/i)).toBeTruthy();
  });

  // A failed fetch must not present as "no devices are enrolled" — that is the
  // reassuring answer and may be the wrong one.
  it("shows the error instead of the reassuring empty-state on a failed first load", async () => {
    listNativeDevices.mockRejectedValue(new Error("network down"));
    renderCard();

    expect(await screen.findByText("network down")).toBeTruthy();
    expect(screen.queryByText(/no paired devices yet/i)).toBeNull();
  });

  // Pins the security property the `fingerprint` dependency exists for: if the
  // identity-change refetch fails, the previous identity's device list must not
  // linger on screen claiming devices can still read mail they can no longer
  // open under the new identity.
  it("clears the device list on a failed refetch, rather than showing stale enrollment", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: "KEY", encryptionEnrolled: true })]
    });
    const { rerender } = renderCard();
    await screen.findByText(/can read your encrypted mail/i);

    listNativeDevices.mockRejectedValue(new Error("network down"));
    rerender(
      <DeviceEnrollmentCard
        fingerprint="CCCC3333DDDD4444"
        clientProtected
        unlocked
        onRequestUnlock={() => {}}
      />
    );

    await screen.findByText("network down");
    expect(screen.queryByText(/can read your encrypted mail/i)).toBeNull();
    expect(screen.queryByText("Pixel")).toBeNull();
  });
});

describe("the gate", () => {
  // THE test. A hostile server serves its own key; the user types the code
  // their phone actually shows. Assert the ABSENCE of the request, not the
  // presence of a warning — a warning beside a sent request is the failure
  // this whole design exists to prevent.
  it("issues no PUT when the served key is not the device's key", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: SUBSTITUTED_KEY })]
    });
    renderCard();
    await startCeremony();

    await submitCeremony(await codeFor(HONEST_KEY));

    expect(putDeviceEnvelope).not.toHaveBeenCalled();
    expect(await screen.findByText(/not the key on that device/i)).toBeTruthy();
  });

  it("seals and uploads when the code matches", async () => {
    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: HONEST_KEY })] });
    renderCard();
    await startCeremony();

    await submitCeremony(await codeFor(HONEST_KEY));

    await vi.waitFor(() => expect(putDeviceEnvelope).toHaveBeenCalledTimes(1));
    const [deviceId, envelope, password] = putDeviceEnvelope.mock.calls[0];
    expect(deviceId).toBe("d1");
    expect(password).toBe("hunter2");
    expect(envelope.alg).toBe("ECDH-P256+HKDF-SHA256+A256GCM");
  });

  // The original attack arriving through the back door of a refetch: verify
  // against an honest key, then seal against whatever the list holds now. The
  // ceremony snapshots the key when it opens, so a mid-ceremony refresh cannot
  // change what gets sealed to.
  it("seals to the key it verified, not to a later one", async () => {
    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: HONEST_KEY })] });
    renderCard();
    await startCeremony();

    // The server flips its answer after the dialog is open.
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: SUBSTITUTED_KEY })]
    });

    await submitCeremony(await codeFor(HONEST_KEY));

    await vi.waitFor(() => expect(putDeviceEnvelope).toHaveBeenCalledTimes(1));
    // The assertion that carries the property: the bytes handed to the seal are
    // the bytes that were verified, not the ones the list holds now.
    expect(sealSpy.mock.calls[0][0]).toBe(HONEST_KEY);
    expect(sealSpy.mock.calls[0][0]).not.toBe(SUBSTITUTED_KEY);
  });

  // A locked vault is mundane. Reporting it as a mismatch would show the most
  // alarming message in the product for the most ordinary cause.
  it("refuses a locked vault without calling it a mismatch", async () => {
    requireUnlockedKey.mockImplementation(() => {
      throw new Error("vault is locked");
    });
    listNativeDevices.mockResolvedValue({ devices: [device({ enrollmentPublicKey: HONEST_KEY })] });
    renderCard();
    await startCeremony();

    await submitCeremony(await codeFor(HONEST_KEY));

    expect(putDeviceEnvelope).not.toHaveBeenCalled();
    expect(screen.queryByText(/not the key on that device/i)).toBeNull();
    expect(await screen.findByText(/unlock your key/i)).toBeTruthy();
  });

  // There is no "seal anyway" — the refusal is not click-through-able because
  // there is nothing to click. Stronger than a warning asked to be respected.
  it("offers no way from a refusal to a seal", async () => {
    listNativeDevices.mockResolvedValue({
      devices: [device({ enrollmentPublicKey: SUBSTITUTED_KEY })]
    });
    renderCard();
    await startCeremony();
    await submitCeremony(await codeFor(HONEST_KEY));

    expect(screen.queryByRole("button", { name: /anyway|continue|proceed|override/i })).toBeNull();
    // The submit button is disabled until the entry actually changes.
    expect(screen.getByRole("button", { name: "Verify and enroll" }).hasAttribute("disabled")).toBe(
      true
    );
    expect(putDeviceEnvelope).not.toHaveBeenCalled();
  });
});
