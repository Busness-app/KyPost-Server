import { useEffect, useMemo, useState } from "react";
import { deleteJSON, getJSON, postJSON, putJSON, toErrorMessage } from "../../api/client";
import { uniqueLabels, type AppConfig } from "../../api/config";
import {
  collectNotificationKeywordOptions,
  normalizePrefs,
  shouldWarnAboutSleepState,
  type NotificationPrefs as NotificationPrefsData,
  type NotificationTestResponse,
  type NotificationVapidResponse
} from "../../pages/config/notifications";
import { ContentPreviewWarningDialog } from "../../components/ContentPreviewWarningDialog";

type NotificationPrefsProps = {
  // cfg and labelsFromImap are also read by the (admin-only) Labels tab and
  // by EmailServer's post-save refresh, so both stay owned by ConfigPage
  // rather than being fetched a second time here.
  cfg: AppConfig;
  labelsFromImap: string[];
};

export function NotificationPrefs({ cfg, labelsFromImap }: NotificationPrefsProps) {
  const [prefs, setPrefs] = useState<NotificationPrefsData | null>(null);
  const [notifyStatus, setNotifyStatus] = useState("");
  const [notifyTestBusy, setNotifyTestBusy] = useState(false);
  const [notifyUnsubscribeBusy, setNotifyUnsubscribeBusy] = useState(false);
  // Turning previews on is gated behind a warning the user has to sit through;
  // turning them back off is not.
  const [previewWarningOpen, setPreviewWarningOpen] = useState(false);
  const notifyStatusTone = notifyStatus.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

  // Derived, not stored: the saved config and the IMAP labels this page already
  // holds are the whole input, so a second copy in state could only go stale.
  const availableKeywords = useMemo(
    () => (cfg && prefs ? collectNotificationKeywordOptions(cfg, labelsFromImap, prefs.keywords) : []),
    [cfg, labelsFromImap, prefs]
  );

  async function refreshNotificationPrefs() {
    const raw = await getJSON<unknown>("/api/notifications/preferences");
    setPrefs(normalizePrefs(raw));
  }

  useEffect(() => {
    refreshNotificationPrefs().catch(() => {
      setNotifyStatus("Failed to load notification settings.");
    });
  }, []);

  async function saveNotificationPrefs() {
    if (!prefs) {
      return;
    }

    const next: NotificationPrefsData = {
      mode: prefs.mode,
      keywords: uniqueLabels(prefs.keywords),
      contentPreview: prefs.contentPreview
    };

    try {
      await putJSON<{ ok: boolean }>("/api/notifications/preferences", next);
      setPrefs(next);
      setNotifyStatus("Notification settings saved.");
    } catch {
      setNotifyStatus("Failed to save notification settings.");
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
    setNotifyTestBusy(true);
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
      setNotifyStatus(`Test sent: ${webSummary}${nativeSummary} device(s) delivered.${nativeErrorSuffix}`);
    } catch (error: unknown) {
      const detail = toErrorMessage(error, "unknown error");
      setNotifyStatus(`Failed to send test notification: ${detail}`);
    } finally {
      setNotifyTestBusy(false);
    }
  }

  async function unsubscribeThisDevice() {
    if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
      setNotifyStatus("Failed to unsubscribe this device: push notifications are not supported by this browser.");
      return;
    }

    setNotifyUnsubscribeBusy(true);
    try {
      const readyRegistration = await navigator.serviceWorker.ready;
      const subscription = await readyRegistration.pushManager.getSubscription();
      if (!subscription) {
        setNotifyStatus("This device is not currently subscribed.");
        return;
      }

      await deleteJSON<{ ok: boolean; removed: boolean; subscriptions: number }>("/api/notifications/subscriptions", {
        endpoint: subscription.endpoint
      });
      await subscription.unsubscribe();
      setNotifyStatus("Unsubscribed this device from push notifications.");
    } catch (error: unknown) {
      const detail = toErrorMessage(error, "unknown error");
      setNotifyStatus(`Failed to unsubscribe this device: ${detail}`);
    } finally {
      setNotifyUnsubscribeBusy(false);
    }
  }

  function setNotifyMode(mode: NotificationPrefsData["mode"]) {
    setPrefs((prev) => {
      if (!prev) {
        return prev;
      }
      if (shouldWarnAboutSleepState(prev.mode, mode, navigator.userAgent)) {
        window.alert("To help insure notifications work, please remove your browser from sleep state.");
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

  return (
    <div className="config-card" role="tabpanel">
      <h3>Notifications</h3>
      <p className="config-muted">Choose how alerts are delivered to this account and which IMAP keywords trigger them.</p>

      {!prefs ? (
        <p className="config-muted">{notifyStatus || "Loading notification settings..."}</p>
      ) : (
        <>
          <h4>Delivery Mode</h4>
          <p className="config-muted">Switch between disabled alerts, all-email alerts, or keyword-only alerts.</p>

          <div className="config-notify-mode-grid">
            <label className={`config-notify-mode-option${prefs.mode === "none" ? " active" : ""}`}>
              <input
                className="config-notify-mode-input"
                type="radio"
                checked={prefs.mode === "none"}
                onChange={() => setNotifyMode("none")}
              />
              <span className="config-notify-mode-title">No email</span>
              <span className="config-notify-mode-copy">Pause browser notifications.</span>
            </label>

            <label className={`config-notify-mode-option${prefs.mode === "all" ? " active" : ""}`}>
              <input
                className="config-notify-mode-input"
                type="radio"
                checked={prefs.mode === "all"}
                onChange={() => setNotifyMode("all")}
              />
              <span className="config-notify-mode-title">All emails</span>
              <span className="config-notify-mode-copy">Notify for every new message.</span>
            </label>

            <label className={`config-notify-mode-option${prefs.mode === "keywords" ? " active" : ""}`}>
              <input
                className="config-notify-mode-input"
                type="radio"
                checked={prefs.mode === "keywords"}
                onChange={() => setNotifyMode("keywords")}
              />
              <span className="config-notify-mode-title">IMAP keywords</span>
              <span className="config-notify-mode-copy">Notify only for selected keywords.</span>
            </label>
          </div>

          <h4>Notification Content</h4>
          <label className="config-notify-preview-toggle">
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
            />
            <span>
              <span className="config-notify-mode-title">Show sender and subject in notifications</span>
              <span className="config-notify-mode-copy">
                Off by default. When off, notifications read &ldquo;You have a new email.&rdquo; and carry no
                sender, subject, or keyword.
              </span>
            </span>
          </label>

          <h4>IMAP Keywords</h4>
          <div className="config-notify-keywords-head">
            <p className="config-muted">Select which IMAP keywords can trigger notifications.</p>
            <span className="config-notify-count">{prefs.keywords.length} selected</span>
          </div>

          <div className="config-notify-keywords-tools">
            <button type="button" onClick={setAllKeywords} disabled={availableKeywords.length === 0}>
              Select All
            </button>
            <button type="button" onClick={clearKeywords} disabled={prefs.keywords.length === 0}>
              Clear
            </button>
          </div>

          {availableKeywords.length === 0 ? (
            <p className="config-muted">
              No IMAP keywords found yet. Configure labels in the Labels tab or sync labels from IMAP first.
            </p>
          ) : (
            <div className="config-notify-keywords-grid">
              {availableKeywords.map((keyword) => (
                <label key={keyword} className={`config-notify-keyword-option${prefs.keywords.includes(keyword) ? " selected" : ""}`}>
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
            <p className="config-muted">Selections are saved now and will be used when Delivery Mode is set to IMAP keywords.</p>
          ) : null}

          <div className="config-actions">
            <button type="button" onClick={() => void saveNotificationPrefs()}>Save Notifications</button>
            <button type="button" onClick={() => void sendTestNotification()} disabled={notifyTestBusy}>
              {notifyTestBusy ? "Sending Test..." : "Send Test Notification"}
            </button>
            <button type="button" onClick={() => void unsubscribeThisDevice()} disabled={notifyUnsubscribeBusy || notifyTestBusy}>
              {notifyUnsubscribeBusy ? "Unsubscribing..." : "Unsubscribe This Device"}
            </button>
          </div>
        </>
      )}

      {notifyStatus && prefs ? <p className={notifyStatusTone}>{notifyStatus}</p> : null}

      <ContentPreviewWarningDialog
        open={previewWarningOpen}
        onConfirm={() => {
          setPreviewWarningOpen(false);
          setPrefs((prev) => (prev ? { ...prev, contentPreview: true } : prev));
        }}
        onCancel={() => setPreviewWarningOpen(false)}
      />
    </div>
  );
}
