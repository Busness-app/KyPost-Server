import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { deleteJSON, getJSON, postJSON, putJSON, toErrorMessage } from "../api/client";
import { normalizeConfig, uniqueLabels, type AppConfig } from "../api/config";
import { listNativeDevices, type NativeDevice } from "../api/devices";
import { ContentPreviewWarningDialog } from "../components/ContentPreviewWarningDialog";

type LabelsResponse = {
  configured: string[];
  imap: string[];
};

type NotificationVapidResponse = {
  publicKey: string;
};

type NotificationTestResponse = {
  ok: boolean;
  subscriptions: number;
  sent: number;
  failed: number;
  removedStale?: number;
  activeSubscriptions?: number;
  nativeDevices?: number;
  nativeSent?: number;
  nativeFailed?: number;
  nativeRemovedStale?: number;
  nativeError?: string;
};

type NativeDeliveryMode = "push" | "pull";

type PairingStatusResponse = {
  subscriberId: string;
  serverBaseUrl?: string;
  registerEndpoint?: string;
  pullEndpoint?: string;
  deliveryMode?: NativeDeliveryMode;
  subscriberHash?: string;
  pairingToken?: string;
  pairingExpiresAt?: string;
  pairingTtlSeconds?: number;
  configurationError?: string;
  configured: boolean;
};

// Per-user delivery preferences, stored server-side per account (the global
// config no longer carries notification mode/keywords).
type NotificationPrefs = {
  mode: "all" | "keywords" | "none";
  keywords: string[];
  // Off by default. See the copy rendered next to this toggle, and
  // UserNotificationSettings.ContentPreview on the server, for why.
  contentPreview: boolean;
};

function normalizePrefs(input: unknown): NotificationPrefs {
  const source = (input ?? {}) as Record<string, unknown>;
  const mode = source.mode === "all" || source.mode === "keywords" ? source.mode : "none";
  const keywords = Array.isArray(source.keywords) ? source.keywords.map(String) : [];
  // Anything other than an explicit true is off: an older settings file with
  // no such field must read as private, not as opted in.
  const contentPreview = source.contentPreview === true;
  return { mode, keywords, contentPreview };
}

const QR_CODE_WIDTH_PX = 220;
const DEFAULT_PAIRING_TTL_SECONDS = 90;
const PAIRING_RED_ZONE_SECONDS = 15;

function collectNotificationKeywordOptions(cfg: AppConfig, labelsData: LabelsResponse, selected: string[]): string[] {
  const configured = cfg.labels.allowlist ?? [];
  const mapped = Object.values(cfg.labels.keywordMappings ?? {}).flat();
  const imap = labelsData.imap ?? [];
  return uniqueLabels([...configured, ...mapped, ...imap, ...selected]);
}

function buildNativePairingLink(pairing: PairingStatusResponse): string {
  const params = new URLSearchParams();
  params.set("sub", pairing.subscriberId);
  if (pairing.subscriberHash) {
    params.set("hash", pairing.subscriberHash);
  }
  if (pairing.serverBaseUrl) {
    params.set("srv", pairing.serverBaseUrl);
  }
  if (pairing.registerEndpoint) {
    params.set("reg", pairing.registerEndpoint);
  }
  if (pairing.pairingToken) {
    params.set("pt", pairing.pairingToken);
  }
  return `kypost://native-pair?${params.toString()}`;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function maskToken(token: string): string {
  const trimmed = token.trim();
  if (trimmed.length <= 14) {
    return trimmed;
  }
  return `${trimmed.slice(0, 8)}...${trimmed.slice(-6)}`;
}

function formatDeviceTime(value?: string): string {
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

function summarizeDevice(device: NativeDevice): string {
  // Show exactly what the client reports as its app version, with no derived
  // platform/"v" prefix.
  return (device.appVersion || "").trim();
}

// Mirrors the backend's normalizeNativeTransport: legacy devices with no
// explicit transport are derived from platform (ios/macos -> APNs, else Firebase).
function deviceTransport(device: NativeDevice): { key: string; label: string } {
  const raw = (device.transport || "").trim().toLowerCase();
  if (raw === "fcm") return { key: "fcm", label: "Firebase" };
  if (raw === "apns") return { key: "apns", label: "APNs" };
  if (raw === "unifiedpush") return { key: "unifiedpush", label: "UnifiedPush" };
  const platform = (device.platform || "").trim().toLowerCase();
  if (platform === "ios" || platform === "macos") return { key: "apns", label: "APNs" };
  return { key: "fcm", label: "Firebase" };
}

function pairingBarColor(remainingMs: number, ttlMs: number): string {
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

export function NotificationsPage() {
  const [cfg, setCfg] = useState<AppConfig | null>(null);
  const [prefs, setPrefs] = useState<NotificationPrefs | null>(null);
  const [availableKeywords, setAvailableKeywords] = useState<string[]>([]);
  const [settingsTab, setSettingsTab] = useState<"delivery" | "keywords">("delivery");
  const [status, setStatus] = useState("");
  const [testBusy, setTestBusy] = useState(false);
  const [unsubscribeBusy, setUnsubscribeBusy] = useState(false);
  const [pairingStatus, setPairingStatus] = useState<PairingStatusResponse | null>(null);
  const [pairingQrDataUrl, setPairingQrDataUrl] = useState("");
  const [unpairBusy, setUnpairBusy] = useState(false);
  const [nativeDevices, setNativeDevices] = useState<NativeDevice[]>([]);
  const [nativeDevicesBusy, setNativeDevicesBusy] = useState(false);
  const [nativeRemoveBusyId, setNativeRemoveBusyId] = useState("");
  const [pairingExpiresAtMs, setPairingExpiresAtMs] = useState<number | null>(null);
  const [pairingTtlMs, setPairingTtlMs] = useState(DEFAULT_PAIRING_TTL_SECONDS * 1000);
  const [pairingClockMs, setPairingClockMs] = useState<number>(() => Date.now());
  const [pairingRefreshBusy, setPairingRefreshBusy] = useState(false);
  const [deliveryMode, setDeliveryMode] = useState<NativeDeliveryMode>("push");
  const [deliveryModeBusy, setDeliveryModeBusy] = useState(false);
  const [desktopPairingBusy, setDesktopPairingBusy] = useState(false);
  // Turning previews on is gated behind a warning the user has to sit through;
  // turning them back off is not.
  const [previewWarningOpen, setPreviewWarningOpen] = useState(false);

  const statusTone = status.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

  function applyPairingStatus(next: PairingStatusResponse | null) {
    setPairingStatus(next);
    if (!next) {
      setPairingExpiresAtMs(null);
      return;
    }
    setDeliveryMode(next.deliveryMode === "pull" ? "pull" : "push");

    const ttlSeconds = typeof next.pairingTtlSeconds === "number" && next.pairingTtlSeconds > 0
      ? next.pairingTtlSeconds
      : DEFAULT_PAIRING_TTL_SECONDS;
    setPairingTtlMs(ttlSeconds * 1000);

    if (next.pairingExpiresAt) {
      const expiresMs = Date.parse(next.pairingExpiresAt);
      setPairingExpiresAtMs(Number.isFinite(expiresMs) ? expiresMs : Date.now() + ttlSeconds * 1000);
    } else if (next.pairingToken) {
      setPairingExpiresAtMs(Date.now() + ttlSeconds * 1000);
    } else {
      setPairingExpiresAtMs(null);
    }
    setPairingClockMs(Date.now());
  }

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [nextConfig, labelsData, rawPrefs] = await Promise.all([
          getJSON<unknown>("/api/config"),
          getJSON<LabelsResponse>("/api/labels"),
          getJSON<unknown>("/api/notifications/preferences")
        ]);
        if (cancelled) {
          return;
        }
        const normalized = normalizeConfig(nextConfig);
        const nextPrefs = normalizePrefs(rawPrefs);
        setCfg(normalized);
        setPrefs(nextPrefs);
        setAvailableKeywords(collectNotificationKeywordOptions(normalized, labelsData, nextPrefs.keywords));
        try {
          const status = await getJSON<PairingStatusResponse>("/api/notifications/pairing");
          if (!cancelled) {
            applyPairingStatus(status);
          }
        } catch {
          if (!cancelled) {
            applyPairingStatus(null);
          }
        }
        if (!cancelled) {
          await refreshNativeDevices();
        }
      } catch {
        if (!cancelled) {
          setStatus("Failed to load notification settings.");
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!pairingExpiresAtMs) {
      return;
    }
    let cancelled = false;
    let refreshTriggered = false;

    const tick = () => {
      if (cancelled) {
        return;
      }
      const now = Date.now();
      setPairingClockMs(now);
      if (now >= pairingExpiresAtMs && !refreshTriggered) {
        refreshTriggered = true;
        setPairingRefreshBusy(true);
        void refreshPairingStatus().finally(() => {
          // Always clear the busy flag, even if effect was cleaned up
          setPairingRefreshBusy(false);
        });
      }
    };

    tick();
    const timer = window.setInterval(tick, 250);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [pairingExpiresAtMs]);

  useEffect(() => {
    let cancelled = false;
    if (!pairingStatus?.configured || !pairingStatus.subscriberId) {
      setPairingQrDataUrl("");
      return;
    }
    QRCode.toDataURL(buildNativePairingLink(pairingStatus), { errorCorrectionLevel: "M", margin: 2, width: 220 })
      .then((dataUrl) => {
        if (!cancelled) {
          setPairingQrDataUrl(dataUrl);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setPairingQrDataUrl("");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [pairingStatus]);

  async function save() {
    if (!prefs) {
      return;
    }

    const next: NotificationPrefs = {
      mode: prefs.mode,
      keywords: uniqueLabels(prefs.keywords),
      contentPreview: prefs.contentPreview
    };

    try {
      await putJSON<{ ok: boolean }>("/api/notifications/preferences", next);
      setPrefs(next);
      setStatus("Notification settings saved.");
    } catch {
      setStatus("Failed to save notification settings.");
    }
  }

  function base64URLToUint8Array(base64URL: string): Uint8Array<ArrayBuffer> {
    const normalized = base64URL.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    return Uint8Array.from(window.atob(padded), (c) => c.charCodeAt(0));
  }

  async function registerDeviceForPush(): Promise<void> {
    if (!("Notification" in window)) {
      throw new Error("Notifications are not supported by this browser.");
    }
    if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
      throw new Error("Push notifications are not supported by this browser.");
    }

    let permission = Notification.permission;
    if (permission === "default") {
      permission = await Notification.requestPermission();
    }
    if (permission !== "granted") {
      throw new Error("Notification permission was not granted.");
    }

    const vapid = await getJSON<NotificationVapidResponse>("/api/notifications/vapid-public-key");
    const registration = await navigator.serviceWorker.register("/sw.js");
    const readyRegistration = await navigator.serviceWorker.ready;
    const target = readyRegistration ?? registration;

    let subscription = await target.pushManager.getSubscription();
    if (!subscription) {
      subscription = await target.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: base64URLToUint8Array(vapid.publicKey)
      });
    }

    await postJSON<{ ok: boolean; subscriptions: number }>("/api/notifications/subscriptions", subscription.toJSON());
  }

  async function sendTestNotification() {
    setTestBusy(true);
    try {
      await registerDeviceForPush();
      const result = await postJSON<NotificationTestResponse>("/api/notifications/test", {
        title: "KyPost Test Notification",
        body: "This test notification was sent to all of your subscribed devices."
      });
      const nativeDevices = result.nativeDevices ?? 0;
      const nativeSent = result.nativeSent ?? 0;
      const webSummary = `${result.sent}/${result.subscriptions} web`;
      const nativeSummary = nativeDevices > 0 ? `, ${nativeSent}/${nativeDevices} mobile` : "";
      const nativeErrorSuffix = result.nativeError ? ` Mobile failed: ${result.nativeError}.` : "";
      setStatus(`Test sent: ${webSummary}${nativeSummary} device(s) delivered.${nativeErrorSuffix}`);
    } catch (error: unknown) {
      const detail = toErrorMessage(error, "unknown error");
      setStatus(`Failed to send test notification: ${detail}`);
    } finally {
      setTestBusy(false);
    }
  }

  async function unsubscribeThisDevice() {
    if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
      setStatus("Failed to unsubscribe this device: push notifications are not supported by this browser.");
      return;
    }

    setUnsubscribeBusy(true);
    try {
      const readyRegistration = await navigator.serviceWorker.ready;
      const subscription = await readyRegistration.pushManager.getSubscription();
      if (!subscription) {
        setStatus("This device is not currently subscribed.");
        return;
      }

      await deleteJSON<{ ok: boolean; removed: boolean; subscriptions: number }>("/api/notifications/subscriptions", {
        endpoint: subscription.endpoint
      });
      await subscription.unsubscribe();
      setStatus("Unsubscribed this device from push notifications.");
    } catch (error: unknown) {
      const detail = toErrorMessage(error, "unknown error");
      setStatus(`Failed to unsubscribe this device: ${detail}`);
    } finally {
      setUnsubscribeBusy(false);
    }
  }

  async function refreshPairingStatus() {
    try {
      const next = await getJSON<PairingStatusResponse>("/api/notifications/pairing");
      applyPairingStatus(next);
    } catch {
      applyPairingStatus(null);
    }
    await refreshNativeDevices();
  }

  async function refreshNativeDevices() {
    try {
      const next = await listNativeDevices();
      setNativeDevices(Array.isArray(next.devices) ? next.devices : []);
    } catch {
      setNativeDevices([]);
    }
  }

  async function changeDeliveryMode(mode: NativeDeliveryMode) {
    if (mode === deliveryMode || deliveryModeBusy) {
      return;
    }
    const previous = deliveryMode;
    setDeliveryMode(mode); // optimistic
    setDeliveryModeBusy(true);
    try {
      const res = await putJSON<{ ok: boolean; deliveryMode: NativeDeliveryMode }>("/api/notifications/native/mode", { mode });
      const applied = res.deliveryMode === "pull" ? "pull" : "push";
      setDeliveryMode(applied);
      setPairingStatus((prev) => (prev ? { ...prev, deliveryMode: applied } : prev));
      setStatus(applied === "pull"
        ? "Switched to App Pull notifications (bypasses Cloudflare and Firebase)."
        : "Switched to relay push notifications.");
    } catch (error: unknown) {
      setDeliveryMode(previous); // roll back
      setStatus(`Failed to change notification delivery: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setDeliveryModeBusy(false);
    }
  }

  async function removeNativeDevice(deviceId: string) {
    const cleaned = deviceId.trim();
    if (!cleaned) {
      return;
    }

    setNativeRemoveBusyId(cleaned);
    setNativeDevicesBusy(true);
    try {
      await deleteJSON<{ ok: boolean; removed: boolean; devices: number }>("/api/notifications/native/devices", { deviceId: cleaned });
      await refreshNativeDevices();
      setStatus("Removed paired native device.");
    } catch (error: unknown) {
      const detail = toErrorMessage(error, "unknown error");
      setStatus(`Failed to remove paired native device: ${detail}`);
    } finally {
      setNativeRemoveBusyId("");
      setNativeDevicesBusy(false);
    }
  }

  const pairingRemainingMs = pairingExpiresAtMs ? Math.max(0, pairingExpiresAtMs - pairingClockMs) : 0;
  const pairingBarWidth = Math.round(QR_CODE_WIDTH_PX * clamp(pairingRemainingMs / Math.max(pairingTtlMs, 1), 0, 1));
  const showPairingBar = pairingRemainingMs > 0 && pairingStatus?.configured;
  const pairingBarBg = pairingBarColor(pairingRemainingMs, pairingTtlMs);

  async function revokePairedDevices() {
    setUnpairBusy(true);
    try {
      await postJSON<{ ok: boolean }>("/api/notifications/native/unpair", {});
      await refreshNativeDevices();
      setStatus("Revoked paired native devices.");
    } catch (error: unknown) {
      const detail = toErrorMessage(error, "unknown error");
      setStatus(`Failed to revoke paired devices: ${detail}`);
    } finally {
      setUnpairBusy(false);
    }
  }

  async function pairDesktopApp() {
    // Desktop apps pair over the same native flow as mobile (sub/hash relay
    // auth) — the desktop-pair code exchange has no server-side register
    // endpoint yet, and the desktop app doesn't need a web session.
    setDesktopPairingBusy(true);
    try {
      // Fetch a fresh pairing token — they expire quickly, so a stale
      // pairingStatus from page load may already be dead.
      const next = await getJSON<PairingStatusResponse>("/api/notifications/pairing");
      applyPairingStatus(next);

      if (!next.configured || !next.pairingToken) {
        setStatus(`Failed to initiate desktop pairing: ${next.configurationError || "pairing is not configured"}`);
        return;
      }

      const deepLink = buildNativePairingLink(next);
      const ttlSeconds = typeof next.pairingTtlSeconds === "number" && next.pairingTtlSeconds > 0
        ? next.pairingTtlSeconds
        : DEFAULT_PAIRING_TTL_SECONDS;

      // Attempt to launch the desktop app via deep link
      try {
        window.location.href = deepLink;
        setStatus(`Launching desktop app with pairing link (valid for ${ttlSeconds} seconds)...`);

        // Fallback: if the desktop app didn't take focus, offer the link for
        // manual pasting into the app's pairing screen.
        setTimeout(() => {
          if (document.hasFocus()) {
            setStatus(`Desktop app not detected. Paste this link into the app's pairing screen: ${deepLink}`);
          }
        }, 2000);
      } catch {
        // Fallback if deep link launch fails
        setStatus(`Desktop app not installed. Pairing link: ${deepLink}`);
      }
    } catch (error: unknown) {
      const detail = toErrorMessage(error, "unknown error");
      setStatus(`Failed to initiate desktop pairing: ${detail}`);
    } finally {
      setDesktopPairingBusy(false);
    }
  }

  function setMode(mode: NotificationPrefs["mode"]) {
    setPrefs((prev) => {
      if (!prev) {
        return prev;
      }

      const isMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent);
      if (prev.mode === "none" && mode !== "none" && isMobile) {
        window.alert("To help insure notifications work, please remove your browser from sleep state.");
      }

      if (mode === "keywords") {
        setSettingsTab("keywords");
      }

      return { ...prev, mode };
    });
  }

  function setAllKeywords() {
    setPrefs((prev) => (prev ? { ...prev, keywords: uniqueLabels(availableKeywords) } : prev));
  }

  function clearKeywords() {
    setPrefs((prev) => (prev ? { ...prev, keywords: [] } : prev));
  }

  function toggleKeyword(keyword: string, checked: boolean) {
    setPrefs((prev) => {
      if (!prev) return prev;
      const nextKeywords = checked
        ? uniqueLabels([...prev.keywords, keyword])
        : prev.keywords.filter((item) => item !== keyword);
      return { ...prev, keywords: nextKeywords };
    });
  }

  if (!cfg || !prefs) {
    return (
      <section className="panel">
        <h2>Notifications</h2>
        <p>{status || "Loading notification settings..."}</p>
      </section>
    );
  }

  return (
    <section className="panel notifications-page">
      <div className="notifications-hero">
        <h2>Notifications and Pairing</h2>
        <p>Choose how alerts are delivered and preselect IMAP keywords any time.</p>
      </div>

      <div className="notifications-layout">
        <section className="notifications-card">
          <div className="notifications-settings-tabs" role="tablist" aria-label="Notification settings tabs">
            <button
              type="button"
              role="tab"
              className={`notifications-settings-tab${settingsTab === "delivery" ? " active" : ""}`}
              aria-selected={settingsTab === "delivery"}
              onClick={() => setSettingsTab("delivery")}
            >
              Delivery Mode
            </button>
            <button
              type="button"
              role="tab"
              className={`notifications-settings-tab${settingsTab === "keywords" ? " active" : ""}`}
              aria-selected={settingsTab === "keywords"}
              onClick={() => setSettingsTab("keywords")}
            >
              IMAP Keywords
            </button>
          </div>

          {settingsTab === "delivery" ? (
            <div role="tabpanel" className="notifications-settings-panel">
              <h3>Delivery Mode</h3>
              <p className="notifications-muted">Switch between disabled alerts, all-email alerts, or keyword-only alerts.</p>

              <div className="notifications-mode-grid">
                <label className={`notifications-mode-option${prefs.mode === "none" ? " active" : ""}`}>
                  <input
                    className="notifications-mode-input"
                    type="radio"
                    checked={prefs.mode === "none"}
                    onChange={() => setMode("none")}
                  />
                  <span className="notifications-mode-title">No email</span>
                  <span className="notifications-mode-copy">Pause browser notifications.</span>
                </label>

                <label className={`notifications-mode-option${prefs.mode === "all" ? " active" : ""}`}>
                  <input
                    className="notifications-mode-input"
                    type="radio"
                    checked={prefs.mode === "all"}
                    onChange={() => setMode("all")}
                  />
                  <span className="notifications-mode-title">All emails</span>
                  <span className="notifications-mode-copy">Notify for every new message.</span>
                </label>

                <label className={`notifications-mode-option${prefs.mode === "keywords" ? " active" : ""}`}>
                  <input
                    className="notifications-mode-input"
                    type="radio"
                    checked={prefs.mode === "keywords"}
                    onChange={() => setMode("keywords")}
                  />
                  <span className="notifications-mode-title">IMAP keywords</span>
                  <span className="notifications-mode-copy">Notify only for selected keywords.</span>
                </label>
              </div>

              <h3 style={{ marginTop: "1.5rem" }}>Notification Content</h3>
              <label className="notifications-preview-toggle" style={{ display: "flex", gap: "0.6rem", alignItems: "flex-start" }}>
                <input
                  type="checkbox"
                  checked={prefs.contentPreview}
                  onChange={(event) => {
                    if (event.target.checked) {
                      setPreviewWarningOpen(true);
                      return;
                    }
                    setPrefs({ ...prefs, contentPreview: false });
                  }}
                  style={{ marginTop: "0.25rem" }}
                />
                <span>
                  <span className="notifications-mode-title">Show sender and subject in notifications</span>
                  <span className="notifications-mode-copy" style={{ display: "block" }}>
                    Off by default. When off, notifications read &ldquo;You have a new email.&rdquo; and carry no
                    sender, subject, or keyword.
                  </span>
                </span>
              </label>
              {deliveryMode === "pull" ? (
                <p className="notifications-muted" style={{ marginTop: "0.5rem" }}>
                  You are on <strong>App Pull</strong>: your phone fetches notifications directly from this
                  server, so turning this on keeps sender and subject between your device and your own server.
                </p>
              ) : null}
            </div>
          ) : (
            <div role="tabpanel" className="notifications-settings-panel">
              <div className="notifications-keywords-head">
                <div>
                  <h3>IMAP Keywords</h3>
                  <p className="notifications-muted">Select which IMAP keywords can trigger notifications.</p>
                </div>
                <span className="notifications-count">{prefs.keywords.length} selected</span>
              </div>

              <div className="notifications-keywords-tools">
                <button type="button" className="notifications-secondary" onClick={setAllKeywords} disabled={availableKeywords.length === 0}>
                  Select All
                </button>
                <button type="button" className="notifications-ghost" onClick={clearKeywords} disabled={prefs.keywords.length === 0}>
                  Clear
                </button>
              </div>

              {availableKeywords.length === 0 ? (
                <p className="notifications-empty">No IMAP keywords found yet. Configure labels in Configuration or sync labels from IMAP first.</p>
              ) : (
                <div className="notifications-keywords-grid">
                  {availableKeywords.map((keyword) => (
                    <label key={keyword} className={`notifications-keyword-option${prefs.keywords.includes(keyword) ? " selected" : ""}`}>
                      <input
                        type="checkbox"
                        checked={prefs.keywords.includes(keyword)}
                        onChange={(event) => toggleKeyword(keyword, event.target.checked)}
                      />
                      <span>{keyword}</span>
                    </label>
                  ))}
                </div>
              )}

              {prefs.mode !== "keywords" ? (
                <p className="notifications-hint">Selections are saved now and will be used when Delivery Mode is set to IMAP keywords.</p>
              ) : null}
            </div>
          )}
        </section>

        <section className="notifications-card notifications-android-card">
          <div className="notifications-android-head">
            <div>
              <h3>Mobile App Pairing</h3>
              <p className="notifications-muted">Scan this QR code from the KyPost app to pair your device. The app receives the server URL automatically.</p>
            </div>
            <button type="button" className="notifications-ghost" onClick={() => void refreshPairingStatus()}>
              Refresh
            </button>
          </div>

          {!pairingStatus?.configured ? (
            <p className="notifications-empty">{pairingStatus?.configurationError ?? "Pairing is not configured on the server yet. Set PAIRING_SECRET first."}</p>
          ) : (
            <div className="notifications-pairing">
              <div className="notifications-pairing-scan">
                {pairingQrDataUrl ? (
                  <div className="notifications-qr">
                    <img className="notifications-qr-image" src={pairingQrDataUrl} alt="Native mobile pairing QR code" width={220} height={220} />
                    {showPairingBar ? (
                      <div className="notifications-qr-timer-track" style={{ width: `${QR_CODE_WIDTH_PX}px` }} aria-hidden="true">
                        <div
                          className="notifications-qr-timer-bar"
                          style={{ width: `${pairingBarWidth}px`, background: pairingBarBg }}
                        />
                      </div>
                    ) : null}
                  </div>
                ) : (
                  <p className="notifications-empty">Preparing pairing code…</p>
                )}

                {pairingRefreshBusy ? <p className="notifications-qr-hint">Refreshing pairing code...</p> : null}

                <div className="notifications-android-meta">
                  <span>Subscriber ID</span>
                  <strong>{pairingStatus.subscriberId || "Not available"}</strong>
                </div>

                <button type="button" className="notifications-ghost" onClick={() => void pairDesktopApp()} disabled={desktopPairingBusy}>
                  {desktopPairingBusy ? "Pairing..." : "Pair Desktop App"}
                </button>
              </div>

              <div className="notifications-native-list">
                <h4>Paired Native Devices</h4>
                {nativeDevices.length === 0 ? (
                  <p className="notifications-native-empty">No native devices registered yet.</p>
                ) : (
                  <div className="notifications-native-items">
                    {nativeDevices.map((device) => {
                      const transport = deviceTransport(device);
                      return (
                      <div key={device.deviceId} className="notifications-native-item">
                        <div className="notifications-native-main">
                          <div className="notifications-native-name-row">
                            <strong>{device.deviceName?.trim() || device.platform || "device"}</strong>
                            <span
                              className={`notifications-transport-badge notifications-transport-badge-${transport.key}`}
                              title="Current notification delivery method for this device"
                            >
                              {transport.label}
                            </span>
                          </div>
                          <span>{maskToken(device.pushToken || "")}</span>
                          {summarizeDevice(device) ? <span className="notifications-native-detail">{summarizeDevice(device)}</span> : null}
                          <span className="notifications-native-detail">Updated: {formatDeviceTime(device.updatedAt || device.registeredAt)}</span>
                          {device.userAgent?.trim() ? <span className="notifications-native-detail">UA: {device.userAgent.trim()}</span> : null}
                        </div>
                        <button
                          type="button"
                          className="notifications-ghost"
                          onClick={() => void removeNativeDevice(device.deviceId)}
                          disabled={nativeDevicesBusy || nativeRemoveBusyId === device.deviceId}
                        >
                          {nativeRemoveBusyId === device.deviceId ? "Removing..." : "Remove"}
                        </button>
                      </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="notifications-store-links">
                <div
                  className="notifications-delivery-toggle"
                  role="group"
                  aria-label="Notification delivery method"
                  title="App Pull fetches notifications directly from this server over HTTP, bypassing Cloudflare and Firebase."
                >
                  <button
                    type="button"
                    className={`notifications-delivery-option${deliveryMode === "push" ? " active" : ""}`}
                    aria-pressed={deliveryMode === "push"}
                    onClick={() => void changeDeliveryMode("push")}
                    disabled={deliveryModeBusy}
                  >
                    Relay Push
                  </button>
                  <button
                    type="button"
                    className={`notifications-delivery-option${deliveryMode === "pull" ? " active" : ""}`}
                    aria-pressed={deliveryMode === "pull"}
                    onClick={() => void changeDeliveryMode("pull")}
                    disabled={deliveryModeBusy}
                  >
                    App Pull
                  </button>
                </div>
                <span className="notifications-store-disabled" title="Store link coming soon">Google Play (coming soon)</span>
                <span className="notifications-store-disabled" title="Store link coming soon">App Store (coming soon)</span>
              </div>
            </div>
          )}
        </section>

      </div>

      <div className="notifications-footer">
        <button type="button" className="notifications-ghost" onClick={() => void revokePairedDevices()} disabled={unpairBusy || testBusy}>
          {unpairBusy ? "Revoking..." : "Revoke Paired Devices"}
        </button>
        <button type="button" className="notifications-ghost" onClick={() => void unsubscribeThisDevice()} disabled={unsubscribeBusy || testBusy}>
          {unsubscribeBusy ? "Unsubscribing..." : "Unsubscribe This Device"}
        </button>
        <button type="button" className="notifications-ghost" onClick={() => void sendTestNotification()} disabled={testBusy}>
          {testBusy ? "Sending Test..." : "Send Test Notification"}
        </button>
        <button type="button" className="notifications-save" onClick={() => void save()}>Save Notifications</button>
      </div>

      {status ? <p className={statusTone}>{status}</p> : null}

      <ContentPreviewWarningDialog
        open={previewWarningOpen}
        onConfirm={() => {
          setPreviewWarningOpen(false);
          setPrefs((prev) => (prev ? { ...prev, contentPreview: true } : prev));
        }}
        onCancel={() => setPreviewWarningOpen(false)}
      />
    </section>
  );
}