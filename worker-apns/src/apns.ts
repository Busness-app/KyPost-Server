/**
 * APNs HTTP/2 push delivery for the Cloudflare Worker relay.
 *
 * Generates ES256 provider tokens and sends to Apple's push service.
 */

import { base64UrlEncode, base64UrlEncodeString, pemToDer } from "../../push-relay-shared/base64url";
import { errorMessage } from "../../push-relay-shared/push-relay-common";

const APNS_PRODUCTION_HOST = "api.push.apple.com";
const APNS_SANDBOX_HOST = "api.sandbox.push.apple.com";

/**
 * Which APNs host a send goes to. Only ever produced by parseApnsEnvironment,
 * which is a parser rather than a cast: the two hosts do not accept each
 * other's device tokens, and picking the wrong one is silent (see the
 * host selection in sendApnsMessage).
 */
export type ApnsEnvironment = "production" | "sandbox";

export interface ApnsConfig {
  authKey: string; // .p8 PEM contents
  keyId: string; // from Apple Developer portal
  teamId: string; // Team ID from Apple Developer portal
  topic: string; // bundle ID, e.g. "com.urlxl.mail"
  environment: ApnsEnvironment;
}

export interface PushMessage {
  token: string;
  title: string;
  body: string;
  data?: Record<string, string>;
}

/**
 * `reachedProvider` is required on every failure so each construction site has
 * to answer it. False means no APNs request was made, and the caller refunds the
 * daily budget draw on the strength of it — a wrong answer either leaks the
 * operator's quota or spends their whole day on nothing, so it is not a field to
 * default. True is the conservative answer whenever a request may have gone out.
 */
export type ApnsResult =
  | { ok: true }
  | { ok: false; stale: true; reachedProvider: boolean; status: number; detail: string } // device token is dead
  | { ok: false; stale: false; reachedProvider: boolean; status: number; detail: string }; // transient/server error

/**
 * Import a PKCS#8 PEM ES256 private key for APNs provider-token signing.
 */
async function importApnsPrivateKey(pem: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    pemToDer(pem),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
}

/**
 * Generate an ES256 provider token for APNs. Valid for up to ~60 minutes.
 * Note: Apple asks that you not regenerate more than roughly once per 20 minutes.
 */
async function generateProviderToken(config: ApnsConfig, nowSeconds: number): Promise<string> {
  const header = base64UrlEncodeString(JSON.stringify({
    alg: "ES256",
    kid: config.keyId,
    typ: "JWT",
  }));

  const claims = base64UrlEncodeString(JSON.stringify({
    iss: config.teamId,
    iat: nowSeconds,
    // Note: no 'exp' claim — Apple honors up to ~60 min
  }));

  const signingInput = `${header}.${claims}`;
  const key = await importApnsPrivateKey(config.authKey);

  // WebCrypto ECDSA produces raw r‖s (IEEE P1363), which is exactly what JWS ES256 needs.
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(signingInput),
  );

  return `${signingInput}.${base64UrlEncode(signature)}`;
}

/**
 * Retrieve a cached APNs provider token, or generate a new one.
 * Token is cached for ~29 minutes (refresh before 30-min expiry).
 */
async function getProviderToken(config: ApnsConfig, cache: KVNamespace): Promise<string> {
  const cacheKey = "apns_provider_token";
  const cached = await cache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  const token = await generateProviderToken(config, nowSeconds);

  // Cache for 29 minutes (refresh before 30-min expiry)
  await cache.put(cacheKey, token, { expirationTtl: 29 * 60 });
  return token;
}

/**
 * Whether Apple said this device token is gone.
 *
 * This is not a severity judgement, it is a destructive one: a true here becomes
 * HTTP 410 to the backend, which deletes the device registration outright
 * (processor/push_dispatch.go). The device must then be re-paired by hand, and
 * until it is, that account has no push 2FA. Nothing recovers it from this side.
 *
 * So the rule is Apple's own contract and nothing looser: **410, and only 410**.
 * Apple returns 410 for `Unregistered` and for no other reason.
 *
 * This deliberately does NOT include the 400 reasons that carry "DeviceToken" in
 * their names. Those describe a token Apple declined to accept from *us*, which
 * is usually our configuration rather than their device:
 *
 *   - `BadDeviceToken` — most often a well-formed token sent to the wrong host.
 *     Every production token looks like this when APNS_ENVIRONMENT is sandbox.
 *   - `DeviceTokenNotForTopic` — the token does not match APNS_TOPIC. Ours.
 *   - `TopicDisallowed` / `BadTopic` — unambiguously ours.
 *
 * Treating those as staleness is how one wrong environment variable unpairs an
 * entire fleet on the first notification after deploy — see the header of
 * apns-config.test.mts, which is the same incident caught one layer earlier.
 * Classified as ordinary failures they cost a retry and a red relay health
 * status, which is the correct way for a misconfigured relay to present.
 */
export function isStaleResponse(status: number, _response: string): boolean {
  return status === 410;
}

/**
 * Send a single push via APNs HTTP/2. Body shape mirrors FCM's for consistency.
 */
export async function sendApnsMessage(
  config: ApnsConfig,
  cache: KVNamespace,
  message: PushMessage,
): Promise<ApnsResult> {
  const token = (message.token ?? "").trim();
  if (!token) {
    return { ok: false, stale: false, reachedProvider: false, status: 400, detail: "missing token" };
  }

  let providerToken: string;
  try {
    providerToken = await getProviderToken(config, cache);
  } catch (err) {
    return {
      ok: false,
      stale: false,
      // Signing/fetching the provider token failed, so nothing was sent to
      // Apple. This is the shape a wrong APNS_KEY_ID or APNS_AUTH_KEY takes.
      reachedProvider: false,
      status: 500,
      detail: `provider token generation failed: ${errorMessage(err)}`,
    };
  }

  // APNs HTTP/2 request to /3/device/{token}. config.environment is an
  // ApnsEnvironment, so "not production" really does mean sandbox here — when
  // this read a raw string, any typo in APNS_ENVIRONMENT landed in this branch.
  const host = config.environment === "production" ? APNS_PRODUCTION_HOST : APNS_SANDBOX_HOST;
  const url = `https://${host}/3/device/${token}`;

  // Build the APS payload (matching FCM's structure for consistency)
  const data = message.data ?? {};
  const payload = {
    // Caller data spreads FIRST so `aps` below always wins. `data` is a
    // caller-supplied string map and `aps` is Apple's reserved dictionary, so
    // spreading last let any key holder send `"aps": "..."` and replace the
    // alert, the sound and the category with a string — a push that passed
    // validation, spent a rate-limit slot and a unit of the daily budget, and
    // then could not be delivered. See apns-payload.test.mts.
    ...data,
    aps: {
      alert: {
        title: message.title,
        body: message.body,
      },
      sound: "default",
      "mutable-content": 1,
      // The category binds the client's registered notification actions
      // (Approve/Deny for MFA challenges); without it the buttons never show.
      category: data.type === "mfa_challenge" ? "MFA_CHALLENGE" : "MAIL_NOTIFICATION",
    },
  };

  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `bearer ${providerToken}`,
        "apns-topic": config.topic,
        "apns-push-type": "alert",
        "apns-priority": "10",
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (resp.ok) {
      return { ok: true };
    }

    const detail = (await resp.text()).trim();

    // Distinguish device-token errors (stale) from provider/server errors (retriable)
    if (isStaleResponse(resp.status, detail)) {
      return { ok: false, stale: true, reachedProvider: true, status: resp.status, detail };
    }

    // Provider-token errors: refresh the token cache and return 502 so backend retries
    const detailLower = detail.toLowerCase();
    if (
      resp.status === 403 &&
      (detailLower.includes("expiredtoken") || detailLower.includes("invalidtoken"))
    ) {
      await cache.delete("apns_provider_token");
      return {
        ok: false,
        stale: false,
        reachedProvider: true,
        status: 502,
        detail: "provider token expired; backend should retry",
      };
    }

    return { ok: false, stale: false, reachedProvider: true, status: resp.status, detail };
  } catch (err) {
    const msg = errorMessage(err);
    // A throw out of fetch() usually means the request never completed, but it
    // cannot be told apart from a failure reading a response Apple did send.
    // Unproven means not refunded.
    return { ok: false, stale: false, reachedProvider: true, status: 502, detail: `apns fetch error: ${msg}` };
  }
}
