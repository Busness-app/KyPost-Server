// Display formatting for the Devices tab. Pure — no React.

import type { NativeDevice } from "../../api/devices";

export const QR_CODE_WIDTH_PX = 220;
export const DEFAULT_PAIRING_TTL_SECONDS = 90;
const PAIRING_RED_ZONE_SECONDS = 15;

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

export function maskToken(token: string): string {
  const trimmed = token.trim();
  if (trimmed.length <= 14) {
    return trimmed;
  }
  return `${trimmed.slice(0, 8)}...${trimmed.slice(-6)}`;
}

export function formatDeviceTime(value?: string): string {
  const clean = (value ?? "").trim();
  if (!clean) {
    return "unknown";
  }
  const parsed = Date.parse(clean);
  if (!Number.isFinite(parsed)) {
    return clean;
  }
  return new Date(parsed).toLocaleString();
}

export function deviceAppVersion(device: NativeDevice): string {
  // Show exactly what the client reports as its app version, with no derived
  // platform/"v" prefix.
  return (device.appVersion || "").trim();
}

// Mirrors the backend's normalizeNativeTransport: legacy devices with no
// explicit transport are derived from platform (ios/macos -> APNs, else Firebase).
export function deviceTransport(device: NativeDevice): { key: string; label: string } {
  const raw = (device.transport || "").trim().toLowerCase();
  if (raw === "fcm") return { key: "fcm", label: "Firebase" };
  if (raw === "apns") return { key: "apns", label: "APNs" };
  if (raw === "unifiedpush") return { key: "unifiedpush", label: "UnifiedPush" };
  const platform = (device.platform || "").trim().toLowerCase();
  if (platform === "ios" || platform === "macos") return { key: "apns", label: "APNs" };
  return { key: "fcm", label: "Firebase" };
}

export function pairingBarColor(remainingMs: number, ttlMs: number): string {
  const redZoneMs = PAIRING_RED_ZONE_SECONDS * 1000;
  if (remainingMs <= redZoneMs) {
    return "hsl(0 88% 46%)";
  }
  const activeMs = Math.max(ttlMs - redZoneMs, 1);
  const elapsedMs = clamp(activeMs - (remainingMs - redZoneMs), 0, activeMs);
  const ratio = elapsedMs / activeMs;
  const hue = Math.round(120 - ratio * 120);
  return `hsl(${hue} 88% 44%)`;
}
