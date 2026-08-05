import { getJSON } from "./client";

/**
 * A paired native device, as GET /api/notifications/native/devices serves it.
 *
 * Mirrors state.NativeDevice's JSON tags (backend/internal/state/store.go:67)
 * after Redacted() strips the secret hash.
 *
 * This type lives here rather than on a page because two pages now need it and
 * they drifted: NotificationsPage's private copy predates the enrollment
 * fields, so every device read as never having published a key. The fetch is
 * shared; the RENDERING deliberately is not, because "which device can approve
 * a sign-in" and "which device can read my mail" are different questions that
 * have no reason to change together.
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

export function listNativeDevices(): Promise<{ devices: NativeDevice[] }> {
  return getJSON<{ devices: NativeDevice[] }>("/api/notifications/native/devices");
}
