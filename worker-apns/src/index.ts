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
 *
 * That is the whole surface. There is no admin API: listing and revoking keys
 * is `wrangler kv key` against the API_KEYS namespace (see README), because an
 * always-on bearer-secret endpoint on the public internet is a worse trade than
 * a CLI command the maintainer runs a few times a year.
 *
 * Per-key controls:
 *   - Expiry:        keys may carry an expiresAt; expired keys are rejected.
 *   - Rate limiting: per-minute cap via the native rate-limiting binding (no KV writes).
 *   - Usage:         per-send data points in Analytics Engine (off the KV path).
 *
 * Observability: every request gets a UUID request id, echoed in the X-Request-Id
 * response header and in error bodies, plus one structured JSON access log line.
 *
 * Self-registration, rate limiting, usage analytics, and small crypto/HTTP
 * helpers are shared with the FCM relay (worker/) — see
 * ../../push-relay-shared/push-relay-common.ts.
 */

// Types are imported with `import type` throughout this file so the module
// links under a plain type-stripping loader (node --test, which is what runs
// apns-config.test.mts) and not only under wrangler's bundler, which infers
// which named imports were types and elides them.
import type { ApnsConfig, ApnsEnvironment, PushMessage } from "./apns";
import { sendApnsMessage } from "./apns";
import type { ApiKeyRecord, CommonEnv, RequestContext } from "../../push-relay-shared/push-relay-common";
import {
  DEFAULT_LIMIT_PER_MINUTE,
  KEY_PREFIX,
  bearer,
  checkMinuteLimit,
  checkDailyBudget,
  secondsUntilUTCMidnight,
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

/**
 * Parse APNS_ENVIRONMENT, or return null if it names neither host.
 *
 * A parser rather than the `as "production" | "sandbox"` cast this used to be.
 * The cast asserted a validation that never ran, and the `|| "production"`
 * after it only caught the empty string — so `APNS_ENVIRONMENT=prodution`
 * stayed "prodution", failed the `=== "production"` test in sendApnsMessage,
 * and quietly sent every production device token to the sandbox. Apple answers
 * those with 400 BadDeviceToken, isStaleResponse reads that as a dead token,
 * and the backend unregisters the device: one typo silently unregistered every
 * iOS device the relay served, with /health still reporting "configured".
 *
 * Unset means production, which is the deployment a self-hoster who never sets
 * the variable wants. Anything else is a configuration failure, not a default —
 * a relay that cannot tell which Apple host it is for must not guess.
 */
export function parseApnsEnvironment(raw: string | undefined): ApnsEnvironment | null {
  const value = (raw ?? "").trim().toLowerCase();
  if (value === "") {
    return "production";
  }
  return value === "production" || value === "sandbox" ? value : null;
}

/**
 * The relay's APNs configuration, or null if it is unusable. Null covers a
 * missing credential AND an unparseable APNS_ENVIRONMENT, so both reach
 * /health's `configured` flag and /send's refusal by the same route — the
 * environment check used to sit outside apnsConfigured entirely, which is what
 * let a misconfigured relay report itself healthy.
 */
function apnsConfig(env: Env): ApnsConfig | null {
  const environment = parseApnsEnvironment(env.APNS_ENVIRONMENT);
  const keyId = (env.APNS_KEY_ID ?? "").trim();
  const teamId = (env.APNS_TEAM_ID ?? "").trim();
  const topic = (env.APNS_TOPIC ?? "").trim();
  // Presence is checked on the trimmed value; the key itself is passed through
  // untrimmed, since pemToDer does its own normalization.
  const authKey = env.APNS_AUTH_KEY ?? "";
  if (environment === null || !authKey.trim() || !keyId || !teamId || !topic) {
    return null;
  }
  return { authKey, keyId, teamId, topic, environment };
}

function apnsConfigured(env: Env): boolean {
  return apnsConfig(env) !== null;
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
  if (!config) {
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

  // Relay-wide day tier, in the same window and for the same reason as the
  // minute tier above: before the claim, because the claim is a durable write.
  // The minute limiter buckets per key, so it bounds how fast one key sends and
  // nothing about how much the relay spends in total — which, with self-issued
  // keys, is the number an operator's APNs quota actually cares about.
  const budget = await checkDailyBudget(rc);
  if (!budget.allowed) {
    rc.log({ level: "warn", event: "send.denied", reason: "daily_budget", keyId: record.id, window: "day" });
    // Computed once: the body hint and the header must name the same instant,
    // and two calls can straddle a second boundary.
    const retryAfter = secondsUntilUTCMidnight();
    const response = fail(rc, 429, "relay daily budget exhausted", {
      window: "day",
      limit: budget.limit,
      retryAfterSeconds: retryAfter,
    });
    response.headers.set("Retry-After", String(retryAfter));
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
  // Carry Apple's reason, not just the status. The 400s that name a device token
  // (BadDeviceToken, DeviceTokenNotForTopic) are relay misconfiguration and no
  // longer retire the device (see isStaleResponse) — which means this log line is
  // now the only place an operator learns that APNS_TOPIC or APNS_ENVIRONMENT is
  // wrong, rather than finding out from a fleet of unpaired phones. The reason is
  // Apple's own short enum, so it carries no device or account data.
  rc.log({
    level: "error",
    event: "send.apns_failed",
    keyId: record.id,
    apnsStatus: result.status,
    apnsDetail: result.detail.slice(0, 200),
  });
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
