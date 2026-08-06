// Reconciles the two sources that both describe "your paired devices" into the
// one list Security's Devices tab renders. Pure — no React — because the
// interesting part is what happens when the two disagree, and that is worth
// pinning in tests rather than discovering in a row that renders oddly.

import type { NativeDevice } from "../../api/devices";

/**
 * A device as `GET /api/mfa/status` describes it, which is a different question
 * from what the inventory answers: not "is this device paired" but "may it
 * approve a sign-in".
 */
export type ApproverDevice = {
  deviceId: string;
  deviceName?: string;
  platform?: string;
  approver: boolean;
  // Absent on older servers, which had no notion of an ineligible transport.
  // Treat undefined as eligible so the page keeps working against one.
  canApprove?: boolean;
  cannotApproveReason?: string;
};

export type DeviceRow = {
  deviceId: string;
  /** Best available human label. Never the empty string. */
  name: string;
  /** The inventory entry, absent when only the MFA status knows this device. */
  device?: NativeDevice;
  /** True when this device is currently allowed to approve sign-ins. */
  approver: boolean;
  /** False only when the server said so explicitly. */
  canApprove: boolean;
  cannotApproveReason?: string;
  /**
   * True when the MFA status knows this device but the inventory does not.
   *
   * Surfaced rather than swallowed: an approver the list does not show is an
   * approver the user cannot revoke.
   */
  missingFromInventory: boolean;
  /** True when the device is paired but the MFA status did not mention it. */
  approvalUnavailable: boolean;
};

export function deviceLabel(device: NativeDevice): string {
  return device.deviceName?.trim() || device.platform?.trim() || device.deviceId;
}

function approverLabel(device: ApproverDevice): string {
  return device.deviceName?.trim() || device.platform?.trim() || device.deviceId;
}

/**
 * Joins the inventory with the approver list on `deviceId`.
 *
 * The inventory is the spine — it is the actual list of what is paired — but a
 * left join alone would drop an approver the inventory has not heard of, which
 * is the one direction that must not fail silently. Those are appended instead,
 * flagged, so the row still carries the control that turns approval back off.
 *
 * An inventory device the MFA status omits gets `approvalUnavailable`, which the
 * UI renders the same way it renders an ineligible transport: a disabled control
 * with a reason, never a control that looks live and does nothing.
 */
export function joinDeviceRows(
  devices: NativeDevice[],
  approvers: ApproverDevice[]
): DeviceRow[] {
  const byId = new Map<string, ApproverDevice>();
  for (const approver of approvers) {
    const id = approver.deviceId?.trim();
    if (!id) continue;
    // The server keys approvers by deviceId, so a duplicate should not reach
    // here. If one does, let the entry that reports approving win: plain
    // last-write-wins could render an active approver as switched off, and a
    // control the user never thinks to touch is a capability they never revoke.
    const seen = byId.get(id);
    if (seen?.approver && !approver.approver) continue;
    byId.set(id, approver);
  }

  const rows: DeviceRow[] = devices.map((device) => {
    const approver = byId.get(device.deviceId);
    byId.delete(device.deviceId);
    return {
      deviceId: device.deviceId,
      name: deviceLabel(device),
      device,
      // No approver entry means the server never offered this device as one, so
      // it cannot be on. Reporting `true` here would show a checked box for a
      // capability the server does not believe in.
      approver: approver ? approver.approver : false,
      canApprove: approver ? approver.canApprove !== false : false,
      cannotApproveReason: approver?.cannotApproveReason,
      missingFromInventory: false,
      approvalUnavailable: !approver
    };
  });

  // Whatever is left knows how to approve sign-ins but is not in the inventory.
  for (const approver of byId.values()) {
    rows.push({
      deviceId: approver.deviceId,
      name: approverLabel(approver),
      approver: approver.approver,
      canApprove: approver.canApprove !== false,
      cannotApproveReason: approver.cannotApproveReason,
      missingFromInventory: true,
      approvalUnavailable: false
    });
  }

  return rows;
}

/**
 * How many devices are actually approving sign-ins right now.
 *
 * Counts eligibility as well as the flag, because a device whose transport
 * cannot carry an approval is not an approver however its checkbox reads.
 */
export function countApprovers(rows: DeviceRow[]): number {
  return rows.filter((row) => row.approver && row.canApprove).length;
}
