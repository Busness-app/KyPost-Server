/**
 * KyPost push relay — a Cloudflare Worker that centralizes FCM delivery.
 *
 * The published mobile app is bound at build time to a single Firebase project.
 * This Worker holds that project's service account (as secrets) and delivers
 * push notifications on behalf of many self-hosted KyPost servers, each
 * authenticated with its own API key. Self-hosters therefore never need a
 * Firebase account and never recompile the app.
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
 *   - Rate limiting: per-minute cap via the native rate-limiting binding (no KV
 *                    writes). Hour/day rolling caps are deferred to the paid tier.
 *   - Usage:         per-send data points in Analytics Engine (off the KV path).
 *
 * Observability: every request gets a UUID request id, echoed in the
 * X-Request-Id response header and in error bodies, plus one structured JSON
 * access log line (visible via `wrangler tail` / Workers Logs / Logpush).
 *
 * Self-registration, rate limiting, usage analytics, and small crypto/HTTP
 * helpers are shared with the APNs relay (worker-apns/) — see
 * ../../push-relay-shared/push-relay-common.ts.
 */

import { FcmConfig, FcmMessage, sendFcmMessage } from "./fcm";
import {
  ApiKeyRecord,
  CommonEnv,
  DEFAULT_LIMIT_PER_MINUTE,
  KEY_PREFIX,
  RequestContext,
  bearer,
  checkMinuteLimit,
  checkDailyBudget,
  refundDailyBudget,
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
  OAUTH_CACHE: KVNamespace;
  FCM_CLIENT_EMAIL: string;
  FCM_PRIVATE_KEY: string;
  FCM_PROJECT_ID: string;
}

function fcmConfig(env: Env): FcmConfig {
  return {
    clientEmail: (env.FCM_CLIENT_EMAIL ?? "").trim(),
    privateKeyPem: env.FCM_PRIVATE_KEY ?? "",
    projectId: (env.FCM_PROJECT_ID ?? "").trim(),
  };
}

function isConfigured(config: FcmConfig): boolean {
  return Boolean(config.clientEmail && config.privateKeyPem && config.projectId);
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

  // Validate the request before it counts against the rolling quota, so
  // malformed (400) or misconfigured (500) calls don't consume a self-hoster's
  // message budget. Bounded and type-checked in the shared reader (see
  // readSendPayload): the body is refused at MAX_SEND_BODY_BYTES before it is
  // parsed, so an authenticated key cannot spend its per-minute quota on
  // multi-megabyte allocations here.
  const parsed = await readSendPayload(request);
  if (!parsed.ok) {
    return fail(rc, parsed.status, parsed.error);
  }
  const payload = parsed.value;
  const token = payload.token;

  const config = fcmConfig(env);
  if (!isConfigured(config)) {
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
  // The budget's other half: the draw below is taken before dispatch (it has to
  // be — the outcome is not known yet), so a send that provably never reached
  // FCM gives it back. Otherwise one wrong credential fails every send and
  // spends the whole day's ceiling on traffic that never left Cloudflare, and
  // the relay stays refused until UTC midnight after the credential is fixed.
  // An answer from FCM of any kind, including a rejected device token, keeps
  // its draw: that request spent the quota this budget exists to bound.
  const refund = () => rc.ctx.waitUntil(refundDailyBudget(rc));

  // Relay-wide day tier, AFTER the claim rather than before it.
  //
  // The budget bounds what this relay spends against the operator's FCM
  // quota, so only a request that is going to reach FCM may draw from it. A
  // request refused at the claim above never does — and charging it was an
  // amplification, not a conservative rounding: any holder of any valid key
  // could spend the entire day on tokens they do not own, deliver nothing, and
  // leave every legitimate self-hoster refused until UTC midnight. That turns a
  // cost ceiling into a cheap outage, which is the reverse of the trade it is
  // here to make.
  //
  // Settled as undelivered on refusal, which releases the claim this request
  // just took — the same close-out every other post-claim failure path uses, and
  // the reason taking the claim first costs nothing.
  const budget = await checkDailyBudget(rc);
  if (!budget.allowed) {
    settle(false);
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

  // Count the accepted send in Analytics Engine (off the KV write path). No KV
  // write happens on the send path — see the single-tier note in
  // push-relay-common.ts, which is what that constraint comes from.
  recordUsageAnalytics(env, record);

  const message: FcmMessage = payload;

  let result;
  try {
    result = await sendFcmMessage(config, env.OAUTH_CACHE, message);
  } catch (err) {
    // A thrown exception (e.g. a transient Google OAuth failure) means
    // delivery never happened, same as the result.stale/failure branches
    // below — so the claim must not be confirmed by it.
    settle(false);
    // Thrown rather than answered: the provider request was never completed, so
    // the draw goes back.
    refund();
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
    rc.log({ level: "info", event: "send.stale", keyId: record.id, fcmStatus: result.status });
    return json({ stale: true, requestId: rc.requestId }, 410);
  }
  settle(false);
  // Refunded only when FCM was never asked — a wrong credential, not a token
  // FCM rejected. See refundDailyBudget.
  if (!result.reachedProvider) {
    refund();
  }
  // Carry FCM's reason, not just the status. INVALID_ARGUMENT and
  // SENDER_ID_MISMATCH are relay misconfiguration and no longer retire the
  // device (see isStaleResponse), so this log line is now where an operator
  // learns FCM_PROJECT_ID is wrong. The reason is Google's own short enum and
  // carries no device or account data.
  rc.log({
    level: "error",
    event: "send.fcm_failed",
    keyId: record.id,
    fcmStatus: result.status,
    fcmDetail: result.detail.slice(0, 200),
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
    configured: (env) => isConfigured(fcmConfig(env)),
    handleSend,
  }),
};
