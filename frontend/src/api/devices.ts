import { getJSON } from "./client";

/**
 * A paired native device, as GET /api/notifications/native/devices serves it.
 *
 * Mirrors state.NativeDevice's JSON tags (backend/internal/state/store.go:67)
 * after Redacted() strips the secret hash.
 *
 * This type lives here rather than on a page because more than one caller needs
 * it and they drifted: a page-private copy predated the enrollment fields, so
 * every device read as never having published a key.
 *
 * Two of the three renderings have since merged. Now that the inventory and the
 * approver toggles are rows in one table on Security's Devices tab, showing the
 * same hardware twice was the defect, not the separation — see
 * `pages/security/deviceJoin.ts` for how the two sources are reconciled.
 *
 * "Which device can read my mail" is still rendered apart, in
 * `components/DeviceEnrollmentCard.tsx`, and that is deliberate rather than
 * leftover: it applies only to a client-protected account, so as a column it
 * would be blank for everyone else, and the card owns the enrollment ceremony
 * whose security rests on refetching when the identity changes.
 */
export type NativeDevice = {
  deviceId: string;
  platform: string;
  pushToken: string;
  deviceName?: string;
  appVersion?: string;
  userAgent?: string;
  registeredAt?: string;
  updatedAt?: string;
  transport?: string;
  /**
   * The device's EC P-256 public key for encrypted mail: base64 of the
   * uncompressed SEC1 point. Absent until the device publishes one, which is
   * what makes the enrollment UI self-gating before the mobile half ships.
   */
  enrollmentPublicKey?: string;
  enrollmentKeyAt?: string;
  /**
   * DEVICE-REPORTED: whether it can still open its local envelope. Not the
   * server's opinion — reinstalling the app destroys the key that answers this,
   * so the device re-reports it on every registration.
   */
  encryptionEnrolled: boolean;
};

/** How pushes reach paired native devices. Account-wide, not per-device. */
export type NativeDeliveryMode = "push" | "pull";

/**
 * The paired-device inventory, plus the account's delivery mode.
 *
 * `deliveryMode` is served here rather than read from
 * `GET /api/notifications/pairing` on purpose: that endpoint mints a live
 * 90-second pairing token as a side effect, so reading a setting from it would
 * hand out a credential every time the tab opened. Absent on older servers.
 */
export function listNativeDevices(): Promise<{
  devices: NativeDevice[];
  deliveryMode?: NativeDeliveryMode;
}> {
  return getJSON<{ devices: NativeDevice[]; deliveryMode?: NativeDeliveryMode }>(
    "/api/notifications/native/devices"
  );
}
