/**
 * KyPost push relay — a Cloudflare Worker that delivers APNs push notifications.
 *
 * This Worker delivers native push notifications to iOS devices via Apple Push
 * Notification service (APNs), holding the APNs auth key (.p8) and issuing provider
 * tokens on behalf of many self-hosted KyPost servers, each authenticated with
 * its own API key. Self-hosters therefore never need an Apple Developer account at
 * the server level and never recompile the app (only update its APNs device token).
 *
 * Endpoints:
 *   GET    /health          (public)                       -> liveness + config
 *   POST   /register        (public)                       -> self-issue a key
 *   POST   /send            (Bearer <per-server API key>)  -> deliver one push
 *   POST   /admin/keys      (Bearer ADMIN_SECRET)          -> mint an API key
 *   GET    /admin/keys      (Bearer ADMIN_SECRET)          -> list key metadata
 *   DELETE /admin/keys/{id} (Bearer ADMIN_SECRET)          -> revoke a key
 *
 * Per-key controls:
 *   - Expiry:        keys may carry an expiresAt; expired keys are rejected.
 *   - Rate limiting: per-minute cap via the native rate-limiting binding (no KV writes).
 *   - Usage:         per-send data points in Analytics Engine (off the KV path).
 *
 * Observability: every request gets a UUID request id, echoed in the X-Request-Id
 * response header and in error bodies, plus one structured JSON access log line.
 *
 * The API-key admin/registration endpoints, rate limiting, usage analytics,
 * and small crypto/HTTP helpers are shared with the FCM relay (worker/) — see
 * ../../push-relay-shared/push-relay-common.ts.
 */

import { ApnsConfig, PushMessage, sendApnsMessage } from "./apns";
import {
  ApiKeyRecord,
  CommonEnv,
  DEFAULT_LIMIT_PER_MINUTE,
  KEY_PREFIX,
  RequestContext,
  bearer,
  checkMinuteLimit,
  claimTokenForSend,
  createRelayFetchHandler,
  fail,
  failDelivery,
  isExpired,
  json,
  readSendPayload,
  recordUsageAnalytics,
  resolveLimit,
  settleToken,
  sha256Hex,
} from "../../push-relay-shared/push-relay-common";

export interface Env extends CommonEnv {
  APNS_TOKEN_CACHE: KVNamespace;
  APNS_AUTH_KEY: string;
  APNS_KEY_ID: string;
  APNS_TEAM_ID: string;
  APNS_TOPIC: string;
  APNS_ENVIRONMENT: string;
}

function apnsConfig(env: Env): ApnsConfig {
  return {
    authKey: env.APNS_AUTH_KEY ?? "",
    keyId: (env.APNS_KEY_ID ?? "").trim(),
    teamId: (env.APNS_TEAM_ID ?? "").trim(),
    topic: (env.APNS_TOPIC ?? "").trim(),
    environment: ((env.APNS_ENVIRONMENT ?? "").trim().toLowerCase() as "production" | "sandbox") || "production",
  };
}

function apnsConfigured(env: Env): boolean {
  return Boolean(
    (env.APNS_AUTH_KEY ?? "").trim() &&
    (env.APNS_KEY_ID ?? "").trim() &&
    (env.APNS_TEAM_ID ?? "").trim() &&
    (env.APNS_TOPIC ?? "").trim(),
  );
}

// ---- /send -----------------------------------------------------------------

async function handleSend(request: Request, rc: RequestContext<Env>): Promise<Response> {
  const { env } = rc;
  const presented = bearer(request);
  if (!presented) {
    return fail(rc, 401, "missing api key");
  }
  const hash = await sha256Hex(presented);
  const record = await env.API_KEYS.get<ApiKeyRecord>(KEY_PREFIX + hash, "json");
  if (!record || !record.enabled) {
    rc.log({ level: "warn", event: "send.denied", reason: "invalid_key" });
    return fail(rc, 401, "invalid api key");
  }
  if (isExpired(record, Date.now())) {
    rc.log({ level: "warn", event: "send.denied", reason: "expired", keyId: record.id });
    return fail(rc, 401, "api key expired", { expiresAt: record.expiresAt });
  }

  // Validate the request before it counts against the rolling quota. Bounded and
  // type-checked in the shared reader (see readSendPayload): the body is refused
  // at MAX_SEND_BODY_BYTES before it is parsed, so an authenticated key cannot
  // spend its per-minute quota on multi-megabyte allocations here.
  const parsed = await readSendPayload(request);
  if (!parsed.ok) {
    return fail(rc, parsed.status, parsed.error);
  }
  const payload = parsed.value;
  const token = payload.token;

  const config = apnsConfig(env);
  if (!apnsConfigured(env)) {
    rc.log({ level: "error", event: "send.misconfigured", keyId: record.id });
    return fail(rc, 500, "relay not configured");
  }

  // Minute tier before the token claim below: claiming is a durable write, so a
  // request that is about to be refused must not leave a device token pinned to
  // the refusing key. Claiming first also let a caller pin unlimited tokens at
  // any rate, since only delivery — not the claim — was behind the limiter.
  if (!(await checkMinuteLimit(env.PUSH_RATE_LIMITER, rc, hash))) {
    rc.log({ level: "warn", event: "send.denied", reason: "rate_limited", keyId: record.id, window: "minute" });
    const response = fail(rc, 429, "rate limit exceeded", {
      window: "minute",
      limit: resolveLimit(env.RATE_LIMIT_PER_MINUTE, DEFAULT_LIMIT_PER_MINUTE),
      retryAfterSeconds: 60,
    });
    response.headers.set("Retry-After", "60");
    return response;
  }

  const claim = await claimTokenForSend(rc, token, record.id);
  if (!claim.allowed) {
    rc.log({ level: "warn", event: "send.denied", reason: claim.logReason, keyId: record.id });
    return fail(rc, claim.status, claim.reason);
  }
  // Every path below settles the claim exactly once: the coordinator counts this
  // send out again and releases the claim only if nothing ever delivered under
  // it. Deferred, because none of it is on the caller's answer — and safe to
  // defer, because an unsettled send still counts as in flight and so blocks a
  // concurrent rollback either way.
  const settle = (delivered: boolean) => rc.ctx.waitUntil(settleToken(rc, token, record.id, delivered));

  // Count the accepted send in Analytics Engine (off the KV write path).
  recordUsageAnalytics(env, record);

  const message: PushMessage = payload;

  let result;
  try {
    result = await sendApnsMessage(config, env.APNS_TOKEN_CACHE, message);
  } catch (err) {
    // A thrown exception (e.g. a transient APNs auth failure) means delivery
    // never happened, same as the result.stale/failure branches below — so the
    // claim must not be confirmed by it.
    settle(false);
    rc.log({ level: "error", event: "send.error", keyId: record.id, error: String((err as Error).message ?? err) });
    return failDelivery(rc);
  }

  if (result.ok) {
    // Delivery under this claim: confirms it, so a concurrent send from this key
    // that fails can no longer release the ownership this one just earned.
    settle(true);
    rc.log({ level: "info", event: "send.ok", keyId: record.id });
    return json({ ok: true });
  }
  if (result.stale) {
    // Dead token: nothing delivered, so a claim made this request goes back.
    settle(false);
    rc.log({ level: "info", event: "send.stale", keyId: record.id, apnsStatus: result.status });
    return json({ stale: true, requestId: rc.requestId }, 410);
  }
  settle(false);
  rc.log({ level: "error", event: "send.apns_failed", keyId: record.id, apnsStatus: result.status });
  return failDelivery(rc);
}

// ---- router ------------------------------------------------------------
//
// Route dispatch and the fetch() wrapper (request-id, access logging,
// unhandled-error catch) are identical across both relay workers — see
// createRelayFetchHandler in push-relay-common.ts.

// Re-exported so the runtime can find the class named by the RELAY_COORDINATOR
// binding in wrangler.toml. It holds device-token ownership and the one-active-
// key-per-IP rule, which KV cannot hold atomically — see relay-coordinator.ts.
export { RelayCoordinator } from "../../push-relay-shared/relay-coordinator";

export default {
  fetch: createRelayFetchHandler<Env>({
    configured: apnsConfigured,
    handleSend,
  }),
};
