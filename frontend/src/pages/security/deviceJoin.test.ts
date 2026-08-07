import { describe, expect, it } from "vitest";
import {
  countApprovers,
  countMailEnrolled,
  deviceLabel,
  joinDeviceRows,
  type ApproverDevice
} from "./deviceJoin";
import type { NativeDevice } from "../../api/devices";

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

function approver(over: Partial<ApproverDevice> = {}): ApproverDevice {
  return { deviceId: "d1", approver: false, ...over };
}

describe("joinDeviceRows", () => {
  it("pairs an inventory device with its approver entry", () => {
    const rows = joinDeviceRows([device()], [approver({ approver: true })]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      deviceId: "d1",
      name: "Pixel",
      approver: true,
      canApprove: true,
      missingFromInventory: false,
      approvalUnavailable: false
    });
    expect(rows[0].device).toBeDefined();
  });

  it("treats an absent canApprove as eligible, so an older server still works", () => {
    const rows = joinDeviceRows([device()], [approver({ approver: true, canApprove: undefined })]);
    expect(rows[0].canApprove).toBe(true);
  });

  it("disables approval only when the server said so, and carries the reason", () => {
    const rows = joinDeviceRows(
      [device()],
      [approver({ canApprove: false, cannotApproveReason: "UnifiedPush cannot carry approvals" })]
    );
    expect(rows[0].canApprove).toBe(false);
    expect(rows[0].cannotApproveReason).toBe("UnifiedPush cannot carry approvals");
  });

  // The dangerous direction. An approver the list does not show is an approver
  // the user cannot revoke, so it is appended and flagged rather than dropped.
  it("keeps an approver the inventory has never heard of", () => {
    const rows = joinDeviceRows(
      [],
      [approver({ deviceId: "ghost", deviceName: "Old phone", approver: true })]
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      deviceId: "ghost",
      name: "Old phone",
      approver: true,
      missingFromInventory: true
    });
    expect(rows[0].device).toBeUndefined();
  });

  it("flags a paired device the MFA status did not mention, and does not claim it approves", () => {
    const rows = joinDeviceRows([device()], []);
    expect(rows[0]).toMatchObject({
      approver: false,
      canApprove: false,
      approvalUnavailable: true,
      missingFromInventory: false
    });
  });

  it("keeps the inventory's order and appends the strays after it", () => {
    const rows = joinDeviceRows(
      [device({ deviceId: "a", deviceName: "A" }), device({ deviceId: "b", deviceName: "B" })],
      [approver({ deviceId: "b" }), approver({ deviceId: "ghost", deviceName: "G" })]
    );
    expect(rows.map((r) => r.deviceId)).toEqual(["a", "b", "ghost"]);
  });

  it("matches each device once, so a duplicate approver entry cannot double a row", () => {
    const rows = joinDeviceRows([device()], [approver({ approver: true }), approver()]);
    expect(rows).toHaveLength(1);
    expect(rows[0].approver).toBe(true);
  });

  it("ignores an approver entry with no usable deviceId", () => {
    const rows = joinDeviceRows([], [approver({ deviceId: "   " })]);
    expect(rows).toEqual([]);
  });

  it("returns nothing for an account with no devices at all", () => {
    expect(joinDeviceRows([], [])).toEqual([]);
  });
});

describe("deviceLabel", () => {
  it("prefers the device name, falls back to platform, then to the id", () => {
    expect(deviceLabel(device({ deviceName: "Pixel" }))).toBe("Pixel");
    expect(deviceLabel(device({ deviceName: "  ", platform: "ios" }))).toBe("ios");
    expect(deviceLabel(device({ deviceName: "", platform: "", deviceId: "d9" }))).toBe("d9");
  });
});

describe("countApprovers", () => {
  it("counts only devices that are both flagged and eligible", () => {
    const rows = joinDeviceRows(
      [
        device({ deviceId: "a" }),
        device({ deviceId: "b" }),
        device({ deviceId: "c" })
      ],
      [
        approver({ deviceId: "a", approver: true }),
        approver({ deviceId: "b", approver: true, canApprove: false }),
        approver({ deviceId: "c", approver: false })
      ]
    );
    expect(countApprovers(rows)).toBe(1);
  });
});

describe("mailAccess", () => {
  it("reports a device that has taken its sealing as enrolled", () => {
    const rows = joinDeviceRows([device({ enrollmentPublicKey: "K", encryptionEnrolled: true })], []);
    expect(rows[0].mailAccess).toBe("enrolled");
  });

  it("reports a device that published a key but has not enrolled as available", () => {
    const rows = joinDeviceRows([device({ enrollmentPublicKey: "K" })], []);
    expect(rows[0].mailAccess).toBe("available");
  });

  // Not an error: this is every device before the mobile half ships, and the
  // permanent state of any client that cannot hold a non-extractable key.
  it("reports a device that published no key as unsupported", () => {
    const rows = joinDeviceRows([device()], []);
    expect(rows[0].mailAccess).toBe("unsupported");
  });

  // The inventory is the only source that knows about sealings, so a row it
  // does not back must not claim a state. Otherwise an approver-only row would
  // render as "too old to enroll", which is a guess presented as a fact.
  it("reports a row the inventory does not back as unknown", () => {
    const rows = joinDeviceRows([], [approver({ deviceId: "ghost", approver: true })]);
    expect(rows[0].missingFromInventory).toBe(true);
    expect(rows[0].mailAccess).toBe("unknown");
  });

  it("counts only enrolled devices", () => {
    const rows = joinDeviceRows(
      [
        device({ deviceId: "a", enrollmentPublicKey: "K", encryptionEnrolled: true }),
        device({ deviceId: "b", enrollmentPublicKey: "K" }),
        device({ deviceId: "c" })
      ],
      []
    );
    expect(countMailEnrolled(rows)).toBe(1);
  });
});
