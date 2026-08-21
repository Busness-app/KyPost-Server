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

/**
 * `reachedProvider` is required on every failure so each construction site has
 * to answer it. False means no FCM request was made, and the caller refunds the
 * daily budget draw on the strength of it — a wrong answer either leaks the
 * operator's quota or spends their whole day on nothing, so it is not a field to
 * default. True is the conservative answer whenever a request may have gone out.
 */
export type FcmResult =
  | { ok: true }
  | { ok: false; stale: true; reachedProvider: boolean; status: number; detail: string }
  | { ok: false; stale: false; reachedProvider: boolean; status: number; detail: string };

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
 * Google's OAuth error code for a failed token exchange, reduced to something
 * safe to put in a log line.
 *
 * The token endpoint answers a failure with `{"error":"invalid_grant",
 * "error_description":"..."}`. The code is an RFC 6749 enum — `invalid_grant`,
 * `invalid_client`, `unauthorized_client` — and it is the whole diagnostic an
 * operator needs: `invalid_client` is a wrong `FCM_CLIENT_EMAIL`,
 * `invalid_grant` is a bad `FCM_PRIVATE_KEY` or a clock that has drifted.
 * `error_description` is free text from Google and is deliberately dropped.
 *
 * The returned value is checked against a narrow pattern rather than trusted,
 * so this can never become a hole the response body fits through: anything
 * that is not a short lowercase identifier is reported as a placeholder. That
 * is a stronger guarantee than the send path's 200-character clip, and it is
 * cheap here because — unlike FCM's send errors — the useful part of this
 * response really is one enum.
 */
export function oauthErrorCode(body: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return "unparsable";
  }
  const code = (parsed as { error?: unknown } | null)?.error;
  if (typeof code !== "string" || !/^[a-z_]{1,40}$/.test(code)) {
    return "unrecognised";
  }
  return code;
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
    // Status and the reason enum, never the body. This error is caught in
    // index.ts and logged as `send.error`, and the relay's logging rule is
    // that upstream response bodies do not go there (see
    // push-relay-shared/AGENTS.md). The narrow exception recorded for
    // `send.fcm_failed` covers FCM's own send errors, not this — the OAuth
    // exchange is where the service-account credentials are in play, and it
    // is the one response where "just log what they said" is least defensible.
    throw new Error(`fcm oauth failed: status=${resp.status} error=${oauthErrorCode(text)}`);
  }

  // Parsed inside a try for the same reason. On a 200 this body carries the
  // access token, and V8's JSON.parse quotes the first ten characters of its
  // input back in the SyntaxError message ("Unexpected token 'y', \"ya29.SUPER\"
  // ... is not valid JSON"). An unparsable success response — Google serving an
  // HTML error page through a proxy, a truncated body — would therefore have
  // put a prefix of the token itself into `send.error` via an exception nobody
  // wrote or reviewed. Ten characters is not a usable credential; it is also
  // not something that needs to be in a log to find out.
  let parsed: { access_token?: string; expires_in?: number };
  try {
    parsed = JSON.parse(text) as { access_token?: string; expires_in?: number };
  } catch {
    throw new Error(`fcm oauth response was not json: status=${resp.status}`);
  }

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
 * Whether FCM said this device token is gone.
 *
 * A true here leaves the relay as HTTP 410 and the backend DELETES the device
 * registration (processor/push_dispatch.go). A device row carries that device's
 * authentication secret, not just a push token, so the account loses push 2FA
 * and has to pair again by hand. Nothing on the server side undoes it.
 *
 * The rule is therefore status AND the STRUCTURED reason, never a substring on
 * its own: FCM v1 reports a retired token as HTTP 404 with a
 * `google.firebase.fcm.v1.FcmError` detail whose errorCode is `UNREGISTERED`.
 * Anything else — `INVALID_ARGUMENT` from a token belonging to another Firebase
 * project, `SENDER_ID_MISMATCH`, an auth failure, a proxy's HTML error page
 * that happens to contain the word — is a delivery failure, which costs a retry
 * and a red relay health status instead of a fleet of unpaired devices.
 *
 * An unparseable body at the right status is likewise NOT a verdict. Failing
 * that way means a genuinely dead token goes unpruned and wastes sends until
 * the device is removed some other way, which is the recoverable direction.
 *
 * This mirrors isRelayStaleResponse in processor/native_sender.go, which was
 * narrowed for exactly this reason: matching "four substrings anywhere in an
 * 8 KiB body at any non-2xx status, with nothing tying the response to the token
 * that was sent" handed the upstream far more authority than delivering a
 * notification requires. The same argument applies one hop earlier, here.
 */
export function isStaleResponse(status: number, response: string): boolean {
  if (status !== 404) {
    return false;
  }
  // The structured errorCode, not a substring of the body. "404 and the word
  // appears somewhere" would still let a proxy's error page or a message
  // quoting the request retire a live device, which is the whole shape being
  // avoided — a body we cannot parse is not a verdict about anything.
  let parsed: unknown;
  try {
    parsed = JSON.parse(response);
  } catch {
    return false;
  }
  const details = (parsed as { error?: { details?: unknown } })?.error?.details;
  if (!Array.isArray(details)) {
    return false;
  }
  return details.some(
    (detail) => (detail as { errorCode?: unknown } | null)?.errorCode === "UNREGISTERED",
  );
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
  // Throws on a bad service account / drifted clock, before any request to FCM
  // is made. handleSend catches it and refunds the budget draw on that basis —
  // see the catch there. Nothing below this line may be moved above it.
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
    return { ok: false, stale: true, reachedProvider: true, status: resp.status, detail };
  }
  return { ok: false, stale: false, reachedProvider: true, status: resp.status, detail };
}
