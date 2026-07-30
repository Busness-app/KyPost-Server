/**
 * FCM HTTP v1 delivery for the Cloudflare Worker relay.
 *
 * Ports the Go backend's SDK-free FCM sender (manual RS256 JWT -> OAuth token
 * -> HTTP v1 send) to WebCrypto. The service account credentials live in Worker
 * secrets; the short-lived Google access token is cached in KV.
 */

import { base64UrlEncode, base64UrlEncodeString, pemToDer } from "../../push-relay-shared/base64url";

const FCM_OAUTH_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const OAUTH_CACHE_KEY = "google_access_token";

export interface FcmConfig {
  clientEmail: string;
  privateKeyPem: string;
  projectId: string;
}

export interface FcmMessage {
  token: string;
  title: string;
  body: string;
  data?: Record<string, string>;
}

export type FcmResult =
  | { ok: true }
  | { ok: false; stale: true; status: number; detail: string }
  | { ok: false; stale: false; status: number; detail: string };

/**
 * Import a PKCS8 PEM RSA private key for RS256 signing.
 */
async function importPrivateKey(pem: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    pemToDer(pem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function signServiceAccountAssertion(config: FcmConfig, nowSeconds: number): Promise<string> {
  const header = base64UrlEncodeString(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64UrlEncodeString(
    JSON.stringify({
      iss: config.clientEmail,
      scope: FCM_OAUTH_SCOPE,
      aud: GOOGLE_TOKEN_URL,
      iat: nowSeconds,
      exp: nowSeconds + 3600,
    }),
  );
  const signingInput = `${header}.${claims}`;
  const key = await importPrivateKey(config.privateKeyPem);
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

/**
 * Return a valid Google OAuth access token, using the KV cache when possible.
 */
async function getAccessToken(config: FcmConfig, cache: KVNamespace): Promise<string> {
  const cached = await cache.get(OAUTH_CACHE_KEY);
  if (cached) {
    return cached;
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  const assertion = await signServiceAccountAssertion(config, nowSeconds);

  const form = new URLSearchParams();
  form.set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
  form.set("assertion", assertion);

  const resp = await fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`fcm oauth failed: status=${resp.status} response=${text}`);
  }
  const parsed = JSON.parse(text) as { access_token?: string; expires_in?: number };
  const token = (parsed.access_token ?? "").trim();
  if (!token) {
    throw new Error("fcm oauth token missing");
  }
  const expiresIn = parsed.expires_in && parsed.expires_in > 0 ? parsed.expires_in : 3600;
  // Refresh a minute early, and respect KV's 60s minimum TTL.
  const ttl = Math.max(60, expiresIn - 60);
  await cache.put(OAUTH_CACHE_KEY, token, { expirationTtl: ttl });
  return token;
}

/**
 * Detect FCM's "token no longer registered" signal. Mirrors the Go backend's
 * isFCMStaleResponse logic.
 */
function isStaleResponse(status: number, response: string): boolean {
  const lower = response.toLowerCase();
  if (
    lower.includes("unregistered") ||
    lower.includes("notregistered") ||
    lower.includes("registration-token-not-registered")
  ) {
    return true;
  }
  if (status === 404 && lower.includes("requested entity was not found")) {
    return true;
  }
  return false;
}

/**
 * Send a single push via FCM HTTP v1.
 *
 * **Deliberately carries no top-level `notification` block.** It used to, and
 * that one field was the cause of three separate user-visible bugs on Android.
 *
 * FCM's rule: a message carrying a `notification` payload, delivered to an app
 * that is backgrounded or killed, is rendered by the **system tray** and
 * `FirebaseMessagingService.onMessageReceived` is never called. For kypost-android
 * that meant:
 *
 *  1. Tapping an "Approve sign-in" notification opened the **inbox**. The system
 *     tray's default tap target is the launcher activity (MainActivity), not the
 *     app's own PendingIntent — which is the only thing that points at
 *     MfaApprovalActivity. MainActivity's MFA routing was removed on the
 *     reasoning that "the MFA notification's PendingIntent targets
 *     MfaApprovalActivity directly", and that is true only in the foreground.
 *  2. The challenge was never tracked. MfaChallengeTracker.markDelivered is only
 *     reached from PushNotificationDispatcher.showMfaChallenge, i.e. only from
 *     onMessageReceived — so a background-delivered challenge was rejected by
 *     MfaApprovalActivity.adoptChallenge even when it was reached.
 *  3. Notifications landed on a channel nobody configured. With no
 *     `default_notification_channel_id` in the manifest, Play Services picks its
 *     own fallback channel, bypassing the app's kypost_push/kypost_mfa channels,
 *     their IMPORTANCE_HIGH, and any per-channel choice the user has made. Easy
 *     to end up silenced with the relay still reporting every send as a success.
 *
 * Data-only, so onMessageReceived always runs and the app builds the notification
 * with the right channel, the right tap target, and the tracker entry. That is
 * what `android.priority: "HIGH"` is for: it is what lets a data-only message
 * wake a Doze'd app.
 *
 * This relay is Android-only, and the envelope no longer pretends otherwise. It
 * used to carry an `apns` override, which could not fire: the Go backend's
 * selectSender maps platform ios/macos to the "apns" transport and its separate
 * APNS_RELAY worker, and returns an error rather than falling back to FCM when
 * that relay is unconfigured (see native_sender.go). No Apple device can reach
 * this code path.
 *
 * `message.title`/`message.body` are consequently not forwarded anywhere — that
 * is deliberate, not an oversight. They remain on FcmMessage because the Go
 * backend still posts them, and Android does not need them: buildNativePushData
 * duplicates the same values into `data` when content previews are on, and
 * PushPayloadParser falls back to its own strings when they are off.
 */
export async function sendFcmMessage(
  config: FcmConfig,
  cache: KVNamespace,
  message: FcmMessage,
): Promise<FcmResult> {
  const accessToken = await getAccessToken(config, cache);

  const payload = {
    message: {
      token: message.token,
      data: message.data ?? {},
      android: {
        priority: "HIGH",
      },
    },
  };

  const sendURL = `https://fcm.googleapis.com/v1/projects/${config.projectId}/messages:send`;
  const resp = await fetch(sendURL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (resp.ok) {
    return { ok: true };
  }

  const detail = (await resp.text()).trim();
  if (isStaleResponse(resp.status, detail)) {
    return { ok: false, stale: true, status: resp.status, detail };
  }
  return { ok: false, stale: false, status: resp.status, detail };
}
