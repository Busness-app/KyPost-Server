import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { DeviceEnrollmentCard } from "./DeviceEnrollmentCard";
import type { NativeDevice } from "../api/devices";

const listNativeDevices = vi.fn();
vi.mock("../api/devices", () => ({ listNativeDevices: () => listNativeDevices() }));
vi.mock("../api/client", () => ({
  toErrorMessage: (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback)
}));

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
});
