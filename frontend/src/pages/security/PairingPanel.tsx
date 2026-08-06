import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { getJSON, toErrorMessage } from "../../api/client";
import {
  DEFAULT_PAIRING_TTL_SECONDS,
  QR_CODE_WIDTH_PX,
  clamp,
  pairingBarColor
} from "./format";

/**
 * "Pair a new device" — the QR code, its expiry bar, and the desktop deep link.
 *
 * A REAL CHILD COMPONENT, mounted only while the panel is open, and that is the
 * point rather than tidiness. `GET /api/notifications/pairing` mints a live
 * 90-second pairing token on every call and this panel re-mints one every time
 * the bar runs out, so an always-mounted version would turn any open Security
 * tab into a self-refreshing walk-up pairing credential. Unmounting stops the
 * cycle; nothing here fetches until the user asks to pair something.
 *
 * (React tracks hook order per component instance, so a conditionally *rendered*
 * child is fine — see the hook rule in frontend/AGENTS.md.)
 */

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

export type PairingPanelProps = {
  /** Called after a pairing attempt, so the device list can pick up a new one. */
  onDevicesMayHaveChanged: () => void;
  /** Surfaces a message on the page's shared status line. */
  onStatus: (message: string) => void;
};

export function PairingPanel({ onDevicesMayHaveChanged, onStatus }: PairingPanelProps) {
  const [pairingStatus, setPairingStatus] = useState<PairingStatusResponse | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [expiresAtMs, setExpiresAtMs] = useState<number | null>(null);
  const [ttlMs, setTtlMs] = useState(DEFAULT_PAIRING_TTL_SECONDS * 1000);
  const [clockMs, setClockMs] = useState<number>(() => Date.now());
  const [refreshBusy, setRefreshBusy] = useState(false);
  const [desktopBusy, setDesktopBusy] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);

  function applyPairingStatus(next: PairingStatusResponse | null) {
    setPairingStatus(next);
    setLoadFailed(next === null);
    if (!next) {
      setExpiresAtMs(null);
      return;
    }

    const ttlSeconds = typeof next.pairingTtlSeconds === "number" && next.pairingTtlSeconds > 0
      ? next.pairingTtlSeconds
      : DEFAULT_PAIRING_TTL_SECONDS;
    setTtlMs(ttlSeconds * 1000);

    if (next.pairingExpiresAt) {
      const parsed = Date.parse(next.pairingExpiresAt);
      setExpiresAtMs(Number.isFinite(parsed) ? parsed : Date.now() + ttlSeconds * 1000);
    } else if (next.pairingToken) {
      setExpiresAtMs(Date.now() + ttlSeconds * 1000);
    } else {
      setExpiresAtMs(null);
    }
    setClockMs(Date.now());
  }

  async function refreshPairingStatus() {
    try {
      applyPairingStatus(await getJSON<PairingStatusResponse>("/api/notifications/pairing"));
    } catch {
      applyPairingStatus(null);
    }
    onDevicesMayHaveChanged();
  }

  // The first mint happens on mount, which only happens when the panel opens.
  useEffect(() => {
    let cancelled = false;
    getJSON<PairingStatusResponse>("/api/notifications/pairing")
      .then((next) => {
        if (!cancelled) applyPairingStatus(next);
      })
      .catch(() => {
        if (!cancelled) applyPairingStatus(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!expiresAtMs) {
      return;
    }
    let cancelled = false;
    let refreshTriggered = false;

    const tick = () => {
      if (cancelled) {
        return;
      }
      const now = Date.now();
      setClockMs(now);
      if (now >= expiresAtMs && !refreshTriggered) {
        refreshTriggered = true;
        setRefreshBusy(true);
        void refreshPairingStatus().finally(() => {
          setRefreshBusy(false);
        });
      }
    };

    tick();
    const timer = window.setInterval(tick, 250);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [expiresAtMs]);

  useEffect(() => {
    let cancelled = false;
    if (!pairingStatus?.configured || !pairingStatus.subscriberId) {
      setQrDataUrl("");
      return;
    }
    QRCode.toDataURL(buildNativePairingLink(pairingStatus), {
      errorCorrectionLevel: "M",
      margin: 2,
      width: QR_CODE_WIDTH_PX
    })
      .then((dataUrl) => {
        if (!cancelled) setQrDataUrl(dataUrl);
      })
      .catch(() => {
        if (!cancelled) setQrDataUrl("");
      });
    return () => {
      cancelled = true;
    };
  }, [pairingStatus]);

  async function pairDesktopApp() {
    // Desktop apps pair over the same native flow as mobile (sub/hash relay
    // auth) — the desktop-pair code exchange has no server-side register
    // endpoint yet, and the desktop app doesn't need a web session.
    setDesktopBusy(true);
    try {
      // Fetch a fresh pairing token — they expire quickly, so a stale
      // pairingStatus from panel open may already be dead.
      const next = await getJSON<PairingStatusResponse>("/api/notifications/pairing");
      applyPairingStatus(next);

      if (!next.configured || !next.pairingToken) {
        onStatus(`Failed to initiate desktop pairing: ${next.configurationError || "pairing is not configured"}`);
        return;
      }

      const deepLink = buildNativePairingLink(next);
      const ttlSeconds = typeof next.pairingTtlSeconds === "number" && next.pairingTtlSeconds > 0
        ? next.pairingTtlSeconds
        : DEFAULT_PAIRING_TTL_SECONDS;

      try {
        window.location.href = deepLink;
        onStatus(`Launching desktop app with pairing link (valid for ${ttlSeconds} seconds)...`);

        // Fallback: if the desktop app didn't take focus, offer the link for
        // manual pasting into the app's pairing screen.
        setTimeout(() => {
          if (document.hasFocus()) {
            onStatus(`Desktop app not detected. Paste this link into the app's pairing screen: ${deepLink}`);
          }
        }, 2000);
      } catch {
        onStatus(`Desktop app not installed. Pairing link: ${deepLink}`);
      }
    } catch (error: unknown) {
      onStatus(`Failed to initiate desktop pairing: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setDesktopBusy(false);
    }
  }

  const remainingMs = expiresAtMs ? Math.max(0, expiresAtMs - clockMs) : 0;
  const barWidth = Math.round(QR_CODE_WIDTH_PX * clamp(remainingMs / Math.max(ttlMs, 1), 0, 1));
  const showBar = remainingMs > 0 && pairingStatus?.configured;

  if (loadFailed) {
    return <p className="sec-muted">Could not reach the pairing service. Close this and try again.</p>;
  }

  if (!pairingStatus) {
    return <p className="sec-muted">Preparing pairing code…</p>;
  }

  if (!pairingStatus.configured) {
    return (
      <p className="sec-muted">
        {pairingStatus.configurationError ?? "Pairing is not configured on the server yet. Set PAIRING_SECRET first."}
      </p>
    );
  }

  return (
    <div className="sec-pairing">
      <p className="sec-muted">
        Scan this from the KyPost app to pair a device. The app receives the server URL automatically.
        Each code is good for {Math.round(ttlMs / 1000)} seconds and replaces itself.
      </p>

      <div className="sec-pairing-scan">
        {qrDataUrl ? (
          <div className="sec-qr">
            <img
              src={qrDataUrl}
              alt="Native mobile pairing QR code"
              width={QR_CODE_WIDTH_PX}
              height={QR_CODE_WIDTH_PX}
            />
            {showBar ? (
              <div
                className="sec-qr-timer-track"
                style={{ width: `${QR_CODE_WIDTH_PX}px` }}
                aria-hidden="true"
              >
                <div
                  className="sec-qr-timer-bar"
                  style={{ width: `${barWidth}px`, background: pairingBarColor(remainingMs, ttlMs) }}
                />
              </div>
            ) : null}
          </div>
        ) : (
          <p className="sec-muted">Preparing pairing code…</p>
        )}

        {refreshBusy ? <p className="sec-muted">Refreshing pairing code...</p> : null}

        <div className="sec-pairing-meta">
          <span className="sec-eyebrow">Subscriber ID</span>
          <strong>{pairingStatus.subscriberId || "Not available"}</strong>
        </div>

        <div className="sec-actions">
          <button type="button" className="sec-action-quiet" onClick={() => void refreshPairingStatus()}>
            New code
          </button>
          <button type="button" onClick={() => void pairDesktopApp()} disabled={desktopBusy}>
            {desktopBusy ? "Pairing..." : "Pair Desktop App"}
          </button>
        </div>
      </div>
    </div>
  );
}
