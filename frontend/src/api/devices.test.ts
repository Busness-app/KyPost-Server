import { beforeEach, describe, expect, it, vi } from "vitest";
import { listNativeDevices } from "./devices";

const getJSON = vi.fn();
vi.mock("./client", () => ({ getJSON: (path: string) => getJSON(path) }));

beforeEach(() => {
  getJSON.mockReset();
});

describe("listNativeDevices", () => {
  // The three enrollment fields are the whole reason this module exists:
  // NotificationsPage's private copy of the type predates them, so a device
  // that HAS published a key read as one that had not.
  it("passes the enrollment fields through", async () => {
    getJSON.mockResolvedValue({
      devices: [
        {
          deviceId: "d1",
          platform: "android",
          pushToken: "tok",
          enrollmentPublicKey: "BASE64KEY",
          enrollmentKeyAt: "2026-08-05T10:00:00Z",
          encryptionEnrolled: true
        }
      ]
    });

    const { devices } = await listNativeDevices();

    expect(getJSON).toHaveBeenCalledWith("/api/notifications/native/devices");
    expect(devices[0].enrollmentPublicKey).toBe("BASE64KEY");
    expect(devices[0].encryptionEnrolled).toBe(true);
  });

  it("reads a device that has published nothing as unenrolled", async () => {
    getJSON.mockResolvedValue({
      devices: [{ deviceId: "d2", platform: "ios", pushToken: "tok", encryptionEnrolled: false }]
    });

    const { devices } = await listNativeDevices();

    expect(devices[0].enrollmentPublicKey).toBeUndefined();
    expect(devices[0].encryptionEnrolled).toBe(false);
  });
});
