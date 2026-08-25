/**
 * Shared push-relay logic used by both Cloudflare Workers: the FCM relay
 * (worker/) and the APNs relay (worker-apns/). Everything below is identical
 * between them — self-registration, per-minute rate limiting,
 * usage analytics, and small crypto/HTTP helpers.
 *
 * Each worker keeps its own `Env` (extending CommonEnv with its
 * provider-specific secrets) and its own `handleSend()`/`configured` pieces,
 * which createRelayFetchHandler below assembles into each worker's `fetch`.
 */

import type { RelayCoordinator } from "./relay-coordinator";

/** Cloudflare native rate-limiting binding (configured in wrangler.toml). */
export interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/** Cloudflare Workers Analytics Engine binding (subset we use). */
export interface AnalyticsEngineDatasetLike {
  writeDataPoint(event: { indexes?: string[]; blobs?: (string | null)[]; doubles?: number[] }): void;
}

/**
 * Minimal structural Env shared by both workers. Each worker's own `Env`
 * extends this with its provider-specific secrets (FCM_* / APNS_*) and its
 * own KV cache binding (OAUTH_CACHE / APNS_TOKEN_CACHE).
 */
export interface CommonEnv {
  API_KEYS: KVNamespace;
  /**
   * Minute limit is ENFORCED by the PUSH_RATE_LIMITER binding (simple.limit in
   * wrangler.toml). This var is display-only (/health + 429 body) and must be kept
   * equal to that binding's limit.
   *
   * Hour/day rolling tiers are deliberately absent — see the single-tier note
   * above checkMinuteLimit, whose fail-closed behaviour depends on it.
   */
  RATE_LIMIT_PER_MINUTE?: string; // display only; default 10
  /**
   * Relay-wide ceiling on sends per UTC day, ENFORCED via the coordinator's
   * spendDailyBudget. Unset means unmetered, which is what a deployment that
   * never configures it keeps getting; "0" is a real limit of zero.
   *
   * This is the aggregate tier the single-tier note above says is missing. It
   * is not per-key on purpose — see checkDailyBudget.
   */
  RELAY_DAILY_BUDGET?: string;
  /** Public self-registration (`POST /register`). "true" opens it; default closed. */
  REGISTRATION_ENABLED?: string;
  /**
   * Opt out of fail-closed rate limiting when the limiter bindings are
   * unavailable — local dev only. Never set this in a deployed Worker.
   */
  RATELIMIT_FAIL_OPEN?: string;
  /** Minute-tier rate limiter (native binding, no KV writes). */
  PUSH_RATE_LIMITER?: RateLimitBinding;
  /**
   * Per-IP minute-tier limiter for POST /register (native binding, no KV writes).
   * The "one active key per IP" dedup in handleRegister limits only *concurrent*
   * keys per IP, not how fast an IP can churn through new ones, so this bounds
   * minting many short-lived permanent keys from one address before rotating IPs.
   */
  REGISTER_RATE_LIMITER?: RateLimitBinding;
  /** Per-key usage counters, offloaded off the KV write path. */
  USAGE_ANALYTICS?: AnalyticsEngineDatasetLike;
  /**
   * Strongly-consistent owner of the two check-then-write invariants KV cannot
   * hold: device-token pinning and one-active-key-per-IP. See RelayCoordinator.
   * Optional in the type only so the binding can be reported missing rather than
   * crashing; both call sites fail CLOSED without it.
   */
  RELAY_COORDINATOR?: DurableObjectNamespace<RelayCoordinator>;
}

export interface ApiKeyRecord {
  id: string;
  label: string;
  enabled: boolean;
  createdAt: string;
  /** ISO timestamp after which the key is rejected; null/absent = never expires. */
  expiresAt?: string | null;
  /**
   * How the key was issued. Every key minted now is "self" (via /register);
   * "admin" only appears on records left by the admin API that used to exist.
   */
  source?: "admin" | "self";
  /** Client IP captured at self-registration, for auditing abuse. */
  registeredIp?: string | null;
}

export const KEY_PREFIX = "key:"; // key:<sha256(key)>      -> ApiKeyRecord (durable)
export const KEY_INDEX_PREFIX = "keyid:"; // keyid:<id>     -> <sha256(key)> for revoke-by-id
// The two ownership indexes below are no longer authoritative — RelayCoordinator
// is (KV cannot make check-then-write atomic). They are kept as the one-time
// seed for a coordinator instance that has never been touched, so claims made
// before that change survive it, plus a little operator-facing bookkeeping.
export const IP_INDEX_PREFIX = "ipkey:"; // ipkey:<ip>      -> keyId (one active key per IP)
export const BOUND_TOKEN_PREFIX = "boundtoken:"; // boundtoken:<sha256(deviceToken)> -> keyId (first sender owns it)

export const DEFAULT_LIMIT_PER_MINUTE = 10;

/**
 * Max stored label length. A label is an operator-facing name for one server,
 * not a payload; without a bound, public /register lets anyone persist
 * megabyte-sized strings into KV and into every operator's key listing.
 */
export const MAX_LABEL_LENGTH = 64;

// ---- request body bounds ----------------------------------------------------
//
// Both endpoints that take a body parse attacker-supplied JSON: /register takes
// one short label, /send takes one notification. Without a ceiling read
// BEFORE the parse, `await request.json()` allocates whatever was sent — the
// per-minute limiter caps how many requests a key may make, not how large each
// one is, so one key at its quota could still make the relay materialize
// hundreds of megabytes a minute and forward them upstream.
//
// The field bounds below are the second half: a body that fits still must not
// carry a 12 KB "device token" into a provider request.

/** Ceiling on a POST /send body. */
export const MAX_SEND_BODY_BYTES = 16 * 1024;
/** Ceiling on a POST /register body (one label). */
export const MAX_JSON_BODY_BYTES = 4 * 1024;

/**
 * Field bounds for /send. Real device tokens are ~64 (APNs) to ~255 (FCM)
 * characters, so a longer one is not a token that got clipped, it is not a
 * token — hence rejected rather than clamped. Text fields are clamped instead:
 * a title is a sender and a body is a subject, both of which arrive from
 * whoever emailed the self-hoster, and refusing to deliver a notification
 * because a stranger sent a long subject line is a worse failure than
 * delivering a clipped one. Same reasoning as MAX_LABEL_LENGTH.
 */
export const MAX_TOKEN_LENGTH = 512;
export const MAX_TITLE_LENGTH = 256;
export const MAX_NOTIFICATION_BODY_LENGTH = 1024;
export const MAX_DATA_ENTRIES = 16;
export const MAX_DATA_KEY_LENGTH = 64;
export const MAX_DATA_VALUE_LENGTH = 1024;

// ---- small helpers ---------------------------------------------------------

export interface RequestContext<TEnv extends CommonEnv = CommonEnv> {
  env: TEnv;
  ctx: ExecutionContext;
  requestId: string;
  log: (fields: Record<string, unknown>) => void;
}

/**
 * The one way a caught value becomes log text.
 *
 * A `catch` binding is `unknown` and JavaScript lets anything be thrown, so
 * `(err as Error).message` is a lie the compiler accepts: on `throw null` it
 * throws a TypeError of its own, out of the handler that exists to keep the
 * failure contained. Every one of these sits on a fail-closed path — the 502
 * for a dead provider, the 429 for a throwing rate limiter — so the replacement
 * failure is the generic 500 from the outer router, and the log line records
 * the logging bug instead of the outage.
 *
 * Total by construction: `String()` accepts every value, including symbols.
 */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Error response carrying the request id so callers can correlate with logs. */
export function fail(
  rc: RequestContext,
  status: number,
  message: string,
  extra?: Record<string, unknown>,
): Response {
  return json({ error: message, requestId: rc.requestId, ...(extra ?? {}) }, status);
}

/**
 * The one answer every failed delivery gets, whatever the provider said.
 *
 * FCM and APNs error bodies describe OUR project: the Firebase project id, the
 * APNs topic, the service account, quota and routing state, and whatever
 * diagnostic Google or Apple adds next. That text used to be interpolated
 * straight into the 502 body, so any holder of any per-server API key — which,
 * with public registration open, is anyone — could read the relay's upstream
 * configuration by sending deliberately broken sends and reading the errors.
 *
 * The caller gets a stable, coarse failure plus the request id, which is what
 * they can act on (retry, or quote the id to the operator).
 *
 * The provider's status and its reason clipped to 200 characters DO go to the
 * structured log, at each worker's `send.fcm_failed` / `send.apns_failed`. That
 * is a deliberate, bounded exception to "no upstream bodies in logs" — since
 * isStaleResponse stopped retiring devices on the 400s that name a token, that
 * log line is the only place an operator learns the relay is misconfigured
 * rather than the phones being dead. Its terms are written down in
 * push-relay-shared/AGENTS.md; the distinction this function enforces is
 * caller-facing versus operator-facing, not logged versus unlogged.
 */
export function failDelivery(rc: RequestContext): Response {
  return fail(rc, 502, "push delivery failed");
}

export function bearer(request: Request): string {
  const header = request.headers.get("Authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : "";
}

/**
 * Buckets a client IP for anti-abuse keying: IPv4 unchanged, IPv6 collapsed to
 * its /64 prefix. A single IPv6 allocation is typically a /64 (2^64 addresses),
 * so keying on the full 128-bit address lets an attacker mint unlimited keys by
 * sourcing each request from a fresh address in their own allocation.
 *
 * Returns "" for anything that is not a syntactically valid address — including
 * an empty string, a placeholder like "unknown", and the IPv4-mapped `::ffff:`
 * form, whose /64 is 0:0:0:0 for every client on the internet and so is not a
 * bucket at all. handleRegister treats "" as "no client address" and refuses to
 * mint, which is the only safe answer for controls that are keyed on this.
 */
export function ipBucket(ip: string): string {
  const trimmed = ip.trim();
  if (!trimmed.includes(":")) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed) && trimmed.split(".").every((o) => Number(o) <= 255)
      ? trimmed
      : "";
  }
  // Strip any zone id and expand "::" to reconstruct the first four hextets.
  const addr = trimmed.split("%")[0];
  const [head, tail, extra] = addr.split("::");
  const headGroups = head ? head.split(":").filter((g) => g !== "") : [];
  const tailGroups = tail ? tail.split(":").filter((g) => g !== "") : [];
  const compressed = tail !== undefined;
  const written = headGroups.length + tailGroups.length;
  const groups = compressed
    ? [...headGroups, ...Array(Math.max(0, 8 - written)).fill("0"), ...tailGroups]
    : headGroups;
  // Three checks, and all three have let something through on their own:
  //
  //   - one "::" at most ("1::2::3" is not an address);
  //   - the right number of written hextets — exactly 8 uncompressed, at most 7
  //     when "::" is present, since it stands for one or more omitted groups.
  //     Without this, "2001:db8:1" zero-padded into a perfectly plausible
  //     bucket despite being three hextets and no compression marker;
  //   - every group is hex, not just the four that make the prefix. Checking
  //     only the prefix let "::ffff:garbage" through as a bucket it then shared
  //     with everything else that pads to zeros.
  if (extra !== undefined || (compressed ? written > 7 : written !== 8)) {
    return "";
  }
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) {
    return "";
  }
  return [0, 1, 2, 3].map((i) => (groups[i] ?? "0").toLowerCase()).join(":") + "::/64";
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function isExpired(record: ApiKeyRecord, now: number): boolean {
  if (!record.expiresAt) {
    return false;
  }
  const at = Date.parse(record.expiresAt);
  return Number.isFinite(at) && at <= now;
}

// ---- device-token pinning ---------------------------------------------------
//
// Closes the open-relay gap left by public self-registration (handleRegister):
// without it, any key holder could /send to any device token, spoofing push
// notifications at strangers. The first key to successfully deliver to a token
// claims it, and every later /send to that token must come from the same key. A
// claim is released for reclaiming once the owning key is revoked/expired/
// deleted, so key rotation never permanently orphans a legitimate device.
//
// The claim itself lives in RelayCoordinator, a Durable Object, because "is this
// token free?" followed by "take it" against eventually consistent KV is not one
// decision — two keys racing the first send to a token both read "free" and both
// were let through, which is the spoofing this section exists to prevent.

/**
 * Resolves the coordinator instance that owns one claim. Naming the instance
 * after the thing being claimed is what serializes the racers: every request for
 * one token, or one registering IP, lands on the same object.
 */
function coordinatorFor(env: CommonEnv, name: string): DurableObjectStub<RelayCoordinator> | null {
  const ns = env.RELAY_COORDINATOR;
  if (!ns) {
    return null;
  }
  return ns.get(ns.idFromName(name));
}

export function tokenCoordinator(env: CommonEnv, tokenHash: string): DurableObjectStub<RelayCoordinator> | null {
  return coordinatorFor(env, "token:" + tokenHash);
}

export function registrationCoordinator(env: CommonEnv, ipBucketKey: string): DurableObjectStub<RelayCoordinator> | null {
  return coordinatorFor(env, "ip:" + ipBucketKey);
}

/** Whether keyId still names a key that may hold a claim. */
async function keyIsActive(env: CommonEnv, keyId: string): Promise<boolean> {
  const hash = await env.API_KEYS.get(KEY_INDEX_PREFIX + keyId);
  if (!hash) {
    return false; // fully deleted
  }
  const record = await env.API_KEYS.get<ApiKeyRecord>(KEY_PREFIX + hash, "json");
  return Boolean(record && record.enabled && !isExpired(record, Date.now()));
}

/**
 * How long a claim is protected from takeover. keyIsActive answers "is the
 * current owner's key still active?" out of KV, and KV converges globally in
 * about a minute: a key minted seconds ago reads as ABSENT at a PoP that has not
 * seen the write yet, which is indistinguishable from "deleted" and would hand
 * that key's freshly claimed token to whoever asked next. The owner had to
 * authenticate against KV to make the claim at all, so waiting out one
 * convergence window is enough for the record that proves it to be visible
 * everywhere. Only delays a legitimate takeover of a token whose owning key was
 * revoked within the last minute.
 */
const CLAIM_TAKEOVER_GRACE_MS = 60_000;

/**
 * Ends one send's use of a token claim: `delivered` true after the push was
 * actually accepted by the provider, false on every failure path. Mandatory
 * after any allowed claimTokenForSend — the coordinator counts sends in and out,
 * and a claim under which nothing ever delivered is released when the last one
 * settles. See RelayCoordinator.settleToken for why the decision cannot be made
 * out here.
 */
export async function settleToken(
  rc: RequestContext,
  token: string,
  keyId: string,
  delivered: boolean,
): Promise<void> {
  const tokenHash = await sha256Hex(token);
  const stub = tokenCoordinator(rc.env, tokenHash);
  if (!stub) {
    return;
  }
  await stub.settleToken(keyId, delivered);
}

export type ClaimResult =
  | { allowed: true }
  // `status`/`logReason` travel with the denial so a misconfigured relay is not
  // reported to the caller as "that token belongs to someone else" — a 403 tells
  // a self-hoster their device is spoken for and to stop retrying, which is the
  // wrong answer to an outage on our side.
  | { allowed: false; reason: string; status: number; logReason: string };

/**
 * Claims token for keyId BEFORE delivery — claiming afterwards would let a
 * first-sender deliver a spoofed push ahead of the legitimate owner's claim.
 * Every allowed claim MUST be closed out with settleToken, which is what
 * releases a claim whose send turned out never to deliver.
 *
 * The claim is a single serialized turn inside the token's RelayCoordinator, so
 * two keys racing the first send to one token can no longer both be told the
 * token is free. The one KV question left — is the current owner's key still
 * active, which decides whether a rotated key's tokens can be re-claimed — is
 * answered out here and applied back as a compare-and-swap, so a re-claim by the
 * legitimate owner in the meantime beats the takeover rather than being
 * overwritten by it.
 *
 * Fails CLOSED when the binding is missing, for the same reason checkMinuteLimit
 * does: "the coordinator is misconfigured" and "there is no coordinator" are
 * indistinguishable from outside, and falling back to the KV path would restore
 * the exact race this exists to remove, silently.
 */
export async function claimTokenForSend(rc: RequestContext, token: string, keyId: string): Promise<ClaimResult> {
  const { env } = rc;
  const tokenHash = await sha256Hex(token);
  const stub = tokenCoordinator(env, tokenHash);
  if (!stub) {
    rc.log({ level: "error", event: "tokenclaim.binding_missing" });
    return {
      allowed: false,
      reason: "token ownership coordinator unavailable",
      status: 503,
      logReason: "coordinator_binding_missing",
    };
  }

  // Pre-Durable-Object claims live in KV; hand the recorded owner over so this
  // token's instance adopts it the first time it is touched, instead of treating
  // every already-owned token as free. Ignored on every later call.
  const legacyOwner = await env.API_KEYS.get(BOUND_TOKEN_PREFIX + tokenHash);

  const first = await stub.claimToken({ keyId, legacyOwner });
  if (first.owner === keyId) {
    return { allowed: true };
  }

  const denied = (logReason: string): ClaimResult => ({
    allowed: false,
    reason: "token is already bound to a different active api key",
    status: 403,
    logReason,
  });
  // Ask the eventually consistent question only about a claim old enough for the
  // answer to be trustworthy — see CLAIM_TAKEOVER_GRACE_MS.
  if (Date.now() - first.claimedAt < CLAIM_TAKEOVER_GRACE_MS) {
    return denied("token_claim_too_recent");
  }
  if (await keyIsActive(env, first.owner)) {
    return denied("token_bound_to_other_key");
  }

  const takeover = await stub.claimToken({ keyId, takeoverFrom: first.owner });
  if (takeover.owner !== keyId) {
    return denied("token_bound_to_other_key"); // re-claimed between the two calls
  }
  return { allowed: true };
}

// ---- per-key rate limits ---------------------------------------------------

/**
 * Resolve a limit var:
 *
 *   unset / blank   -> fallback
 *   "0" or negative -> 0 (negatives clamp up, they are not a smaller limit)
 *   unparseable     -> fallback
 *
 * Unparseable resolves to the FALLBACK, not to 0: a typo in a deployment
 * variable must not read as "no limit configured", which is the
 * fail-open-on-misconfiguration checkMinuteLimit below exists to refuse.
 */
export function resolveLimit(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw.trim() === "") {
    return fallback;
  }
  const parsed = Number.parseInt(raw.trim(), 10);
  return Number.isFinite(parsed) ? Math.max(0, parsed) : fallback;
}

// Single-tier PER-KEY rate limiting: a decision, not a gap. Stated here rather
// than as a TODO because checkMinuteLimit's fail-closed behaviour depends on
// the minute tier being the only PER-KEY tier.
//
// Enforced per key: a per-minute cap via the native rate-limiting bindings
// (PUSH_RATE_LIMITER per key, REGISTER_RATE_LIMITER per IP). No KV writes on an
// accepted send.
//
// Not enforced per key: rolling hour and day caps. They required a KV
// read-modify-write per send, which capped the free tier at ~1,000 pushes/day —
// the limiter became the outage. They are not coming back in that form.
//
// The cost: a caller who stays under the per-minute cap can sustain it
// indefinitely, so the minute limit bounds burst rate but not daily volume
// against someone else's infrastructure — the relay operator's Cloudflare
// account first, and their provider's send-rate quota after it. That residual
// is why the fail-closed behaviour below is not negotiable.
//
// The daily half of that residual is now covered — by checkDailyBudget, built
// the way this note prescribed (a Durable Object counter, no KV write
// pressure) and AGGREGATE rather than per-key, since a per-key day cap is
// worth nothing when registration mints keys on demand. It is opt-in via
// RELAY_DAILY_BUDGET and unset by default, so the paragraph above still
// describes an unconfigured relay exactly. What has NOT changed is the
// reasoning at this function's call sites: the minute tier is still the only
// per-key tier, so failing it closed is still not negotiable.

/**
 * Minute-tier check via a native rate-limiting binding (no KV writes). Returns
 * true when allowed, and fails closed on both a missing binding and a throwing
 * one. Shared by the per-key send limiter (PUSH_RATE_LIMITER) and the per-IP
 * registration limiter (REGISTER_RATE_LIMITER); key is whatever the caller wants
 * to bucket on. Local dev without binding support opts out explicitly via
 * RATELIMIT_FAIL_OPEN.
 */
export async function checkMinuteLimit(
  limiter: RateLimitBinding | undefined,
  rc: RequestContext,
  key: string,
): Promise<boolean> {
  if (!limiter || typeof limiter.limit !== "function") {
    // Fail CLOSED on a missing binding. "The limiter is misconfigured" and
    // "there is no limiter" are indistinguishable from outside, and the minute
    // tier is the only tier enforced (see the note above) — so failing
    // open here removed rate limiting entirely, silently, from a deployment
    // whose wrangler.toml had drifted. Local dev without binding support opts
    // out explicitly via RATELIMIT_FAIL_OPEN.
    if ((rc.env.RATELIMIT_FAIL_OPEN ?? "").trim().toLowerCase() === "true") {
      return true;
    }
    rc.log({ level: "error", event: "ratelimit.binding_missing", key });
    return false;
  }
  try {
    const { success } = await limiter.limit({ key });
    return success;
  } catch (err) {
    // Fail closed, same as a missing binding. Returning true would treat a throwing
    // binding as an outage that should not take delivery down with it, but the
    // minute tier is the only tier enforced (see the note above), so this branch is
    // the difference between a rate-limited relay and an unbounded send primitive
    // pointed at someone else's infrastructure, traced only by this log line.
    //
    // Callers surface it as 429 with a Retry-After: the request is refused not
    // because the caller misbehaved but because the relay cannot currently tell
    // whether they did.
    rc.log({ level: "error", event: "ratelimit.binding_error", error: errorMessage(err) });
    return false;
  }
}

/**
 * The Durable Object instance holding the relay-wide daily budget. One fixed
 * name, because the budget is one shared pool — see spendDailyBudget.
 */
const BUDGET_INSTANCE = "relay-daily-budget";

/**
 * Seconds until the budget resets, for Retry-After. The counter rolls at the
 * UTC day boundary, so this is a real time at which the caller's next attempt
 * can succeed rather than a guess — which is what makes it worth sending
 * instead of a fixed 60.
 */
export function secondsUntilUTCMidnight(now: number = Date.now()): number {
  const midnight = Date.UTC(
    new Date(now).getUTCFullYear(),
    new Date(now).getUTCMonth(),
    new Date(now).getUTCDate() + 1,
  );
  return Math.max(1, Math.ceil((midnight - now) / 1000));
}

/**
 * Draw one send from the relay-wide daily budget.
 *
 * This is the upper tier the single-tier note above asks for, built the way
 * that note specifies: a Durable Object counter rather than a KV
 * read-modify-write, so it does not reintroduce the write pressure that made
 * the previous rolling limits the outage.
 *
 * It is AGGREGATE, not per-key. The per-minute limiters bucket per key and per
 * registering IP, and with public registration open neither is a scarce
 * resource: an actor who wants a second bucket registers a second key from a
 * second address. So the ceiling has to be counted together, or extra keys buy
 * extra headroom and the limit means nothing.
 *
 * What that ceiling protects is worth naming precisely, because it is easy to
 * assume it is a bill and it is not. FCM and APNs are free: there is no
 * provider invoice, and the send quotas they do impose are per-project RATE
 * limits rather than a daily cap. The resources actually being spent are the
 * operator's — the Cloudflare account underneath, where free-plan daily limits
 * on KV and Durable Object operations refuse further operations outright until
 * 00:00 UTC, and on a paid plan become the invoice — plus the provider's
 * goodwill, since an open relay driven hard is indistinguishable from an abuse
 * source.
 *
 * This counter is blind to every one of those Cloudflare limits. It bounds what
 * the relay chooses to send; it cannot see what Cloudflare is willing to serve.
 * Sizing it below the plan's own ceilings is the operator's job.
 *
 * Unset RELAY_DAILY_BUDGET means unmetered, which is what every existing
 * deployment gets. An operator opts into the ceiling; nobody wakes up to find
 * their working relay capped. "0" is a real limit of zero (a closed relay),
 * not an unset value — the inversion resolveLimit already refuses elsewhere.
 *
 * Fails CLOSED when configured but uncountable, for the same reason
 * checkMinuteLimit does: once a budget exists it is the only thing bounding
 * daily volume, and "the binding drifted" is indistinguishable from "there is
 * no binding" from out here.
 */
export async function checkDailyBudget(
  rc: RequestContext,
  now: number = Date.now(),
): Promise<{ allowed: boolean; used: number; limit: number }> {
  const raw = (rc.env.RELAY_DAILY_BUDGET ?? "").trim();
  if (raw === "") {
    return { allowed: true, used: 0, limit: 0 };
  }
  const limit = resolveLimit(raw, 0);

  const binding = rc.env.RELAY_COORDINATOR;
  if (!binding || typeof binding.idFromName !== "function") {
    rc.log({ level: "error", event: "budget.binding_missing" });
    return { allowed: false, used: 0, limit };
  }

  try {
    const stub = binding.get(binding.idFromName(BUDGET_INSTANCE));
    const result = await stub.spendDailyBudget(limit, now);
    if (!result.allowed) {
      rc.log({ level: "warn", event: "budget.exhausted", used: result.used, limit, day: result.day });
    }
    return { allowed: result.allowed, used: result.used, limit };
  } catch (err) {
    rc.log({ level: "error", event: "budget.error", error: errorMessage(err) });
    return { allowed: false, used: 0, limit };
  }
}

/**
 * Give back a draw taken by a send that never reached the provider.
 *
 * checkDailyBudget draws before dispatch, because the counter has to be taken in
 * the coordinator's serialized turn and the outcome is not known until after.
 * That is right for the common case and wrong for the case where no provider
 * request is ever made: a bad APNS_KEY_ID or FCM service account fails every
 * send before it leaves Cloudflare, and un-refunded those failures spend the
 * whole day's budget on zero delivery — so the relay stays refused until UTC
 * midnight even after the credential is fixed.
 *
 * Callers refund ONLY on a result that proves no provider request was made
 * (`reachedProvider: false`) or on a thrown send. A provider that answered — a
 * dead token, a rejected token, a 5xx — spent the quota this budget bounds, and
 * refunding those would make invented device tokens free.
 *
 * Best-effort and never throws: a failed refund overcounts the day by one, which
 * is the safe direction, and the request it belongs to has already failed.
 */
export async function refundDailyBudget(rc: RequestContext, now: number = Date.now()): Promise<void> {
  if ((rc.env.RELAY_DAILY_BUDGET ?? "").trim() === "") {
    return;
  }
  const binding = rc.env.RELAY_COORDINATOR;
  if (!binding || typeof binding.idFromName !== "function") {
    return;
  }
  try {
    await binding.get(binding.idFromName(BUDGET_INSTANCE)).refundDailyBudget(now);
  } catch (err) {
    rc.log({ level: "error", event: "budget.refund_failed", error: errorMessage(err) });
  }
}

/**
 * Record one accepted send to Analytics Engine (off the KV write path). Query
 * lifetime totals per key later via the WAE SQL API. Best-effort: never throws.
 */
export function recordUsageAnalytics(env: CommonEnv, record: ApiKeyRecord): void {
  const wae = env.USAGE_ANALYTICS;
  if (!wae) {
    return;
  }
  try {
    wae.writeDataPoint({
      indexes: [record.id],
      blobs: [record.id, record.label, record.source ?? "self"],
      doubles: [1],
    });
  } catch {
    // analytics is best-effort; a send must never fail on it.
  }
}

// ---- key minting ------------------------------------------------------------

/**
 * Mint an API key, persist only its hash, and return the record plus the raw
 * key (which the caller returns to the client exactly once).
 *
 * `/register` is the only caller: there is no admin API. Keys are therefore
 * always self-issued and never expire, so neither is a parameter. `expiresAt`
 * stays on the record (and `isExpired` stays on the read path) because keys
 * minted by the admin endpoint that used to exist may still carry one.
 */
export async function mintKey(
  env: CommonEnv,
  rc: RequestContext,
  opts: {
    label: string;
    registeredIp?: string | null;
    /**
     * Pre-generated key id. handleRegister needs the id BEFORE the record
     * exists, so it can reserve the IP first and persist nothing until that
     * reservation succeeds.
     */
    id: string;
  },
): Promise<{ record: ApiKeyRecord; key: string }> {
  const key = randomToken();
  const record: ApiKeyRecord = {
    id: opts.id,
    // Clamped here rather than at the call site so no minting path can store an
    // unbounded label (see MAX_LABEL_LENGTH).
    label: opts.label.slice(0, MAX_LABEL_LENGTH),
    enabled: true,
    createdAt: new Date().toISOString(),
    expiresAt: null,
    source: "self",
    registeredIp: opts.registeredIp ?? null,
  };
  const hash = await sha256Hex(key);
  await env.API_KEYS.put(KEY_PREFIX + hash, JSON.stringify(record));
  await env.API_KEYS.put(KEY_INDEX_PREFIX + opts.id, hash);
  rc.log({ level: "info", event: "key.created", keyId: opts.id, label: record.label, source: "self" });
  return { record, key };
}

/** A refusal that a handler returns as-is; `ok: true` carries the parsed value. */
export type BodyResult<T> = { ok: true; value: T } | { ok: false; status: number; error: string };

const TOO_LARGE: BodyResult<never> = { ok: false, status: 413, error: "request body too large" };

/**
 * Read a request body with a hard byte ceiling, never holding more than that.
 *
 * Content-Length is checked first because it is free, but it is not trusted as
 * the bound: it is absent on a chunked body and it is a claim by the sender
 * either way. The stream is therefore counted as it arrives and cancelled the
 * moment it goes over, so the refusal costs `maxBytes`, not the body's size.
 */
export async function readBoundedBody(request: Request, maxBytes: number): Promise<BodyResult<string>> {
  const declared = Number(request.headers.get("Content-Length") ?? "");
  if (Number.isFinite(declared) && declared > maxBytes) {
    return TOO_LARGE;
  }
  const stream = request.body;
  if (!stream) {
    return { ok: true, value: "" };
  }
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return TOO_LARGE;
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, status: 400, error: "could not read request body" };
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, value: new TextDecoder().decode(merged) };
}

/**
 * Parse a bounded JSON object body, tolerating anything else. JSON.parse accepts
 * valid-but-non-object JSON (`null`, arrays, scalars), and reading a property off
 * `null` throws — a body of literal `null` turned these handlers into a 500. An
 * oversized body is NOT tolerated: it is refused before it is parsed, which is
 * the whole point of the ceiling.
 */
async function jsonObjectBody<T extends object>(
  request: Request,
  maxBytes = MAX_JSON_BODY_BYTES,
): Promise<BodyResult<Partial<T>>> {
  const body = await readBoundedBody(request, maxBytes);
  if (!body.ok) {
    return body;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.value || "{}");
  } catch {
    return { ok: true, value: {} };
  }
  return {
    ok: true,
    value: parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Partial<T>) : {},
  };
}

/** Clamp to `max` characters without splitting a surrogate pair in half. */
function clampString(value: string, max: number): string {
  if (value.length <= max) {
    return value;
  }
  const clipped = value.slice(0, max);
  const last = clipped.charCodeAt(max - 1);
  return last >= 0xd800 && last <= 0xdbff ? clipped.slice(0, max - 1) : clipped;
}

/**
 * The validated /send body, shaped for both providers: worker/'s FcmMessage and
 * worker-apns/'s PushMessage are the same four fields.
 */
export interface SendPayload {
  token: string;
  title: string;
  body: string;
  data: Record<string, string>;
}

/**
 * Read and validate a POST /send body against MAX_SEND_BODY_BYTES and the field
 * bounds above, returning a payload that is safe to hand to a provider.
 *
 * Types are checked, not coerced: `{"title": {...}}` used to become the string
 * "[object Object]" in a delivered notification, and `data` was forwarded to the
 * provider unexamined, so any JSON value at all could ride into an FCM/APNs
 * request under a key holder's quota. Unknown fields are ignored rather than
 * refused — the Go sender already sends a `platform` field this relay has never
 * read, and a new one must not become a delivery outage on the older worker.
 */
export async function readSendPayload(request: Request): Promise<BodyResult<SendPayload>> {
  const body = await readBoundedBody(request, MAX_SEND_BODY_BYTES);
  if (!body.ok) {
    return body;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.value);
  } catch {
    return { ok: false, status: 400, error: "invalid json body" };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, status: 400, error: "invalid json body" };
  }
  const raw = parsed as Record<string, unknown>;

  if (raw.token !== undefined && typeof raw.token !== "string") {
    return { ok: false, status: 400, error: "invalid token" };
  }
  const token = ((raw.token as string | undefined) ?? "").trim();
  if (!token) {
    return { ok: false, status: 400, error: "missing token" };
  }
  if (token.length > MAX_TOKEN_LENGTH) {
    return { ok: false, status: 400, error: "invalid token" };
  }

  for (const field of ["title", "body"] as const) {
    if (raw[field] !== undefined && typeof raw[field] !== "string") {
      return { ok: false, status: 400, error: `invalid ${field}` };
    }
  }

  const data: Record<string, string> = {};
  if (raw.data !== undefined && raw.data !== null) {
    if (typeof raw.data !== "object" || Array.isArray(raw.data)) {
      return { ok: false, status: 400, error: "invalid data" };
    }
    const entries = Object.entries(raw.data as Record<string, unknown>);
    if (entries.length > MAX_DATA_ENTRIES) {
      return { ok: false, status: 400, error: "too many data entries" };
    }
    for (const [key, value] of entries) {
      if (key.length > MAX_DATA_KEY_LENGTH) {
        return { ok: false, status: 400, error: "invalid data key" };
      }
      if (typeof value !== "string") {
        return { ok: false, status: 400, error: "invalid data value" };
      }
      data[key] = clampString(value, MAX_DATA_VALUE_LENGTH);
    }
  }

  return {
    ok: true,
    value: {
      token,
      title: clampString((raw.title as string | undefined) ?? "", MAX_TITLE_LENGTH),
      body: clampString((raw.body as string | undefined) ?? "", MAX_NOTIFICATION_BODY_LENGTH),
      data,
    },
  };
}

// ---- /register (public self-service) ---------------------------------------

/**
 * Whether public self-registration is open. Closed unless explicitly opened.
 *
 * Defaulting to OPEN meant every deployment of this Worker that had not read the
 * docs ran an unauthenticated key-minting endpoint on the public internet. The
 * failure is asymmetric: an operator who wants open registration flips one var
 * and finds out immediately when they try to register; one who did not want it
 * finds out when someone else is using their relay.
 */
export function registrationEnabled(env: CommonEnv): boolean {
  return (env.REGISTRATION_ENABLED ?? "").trim().toLowerCase() === "true";
}

/**
 * Public, unauthenticated self-registration: a self-hosted server obtains its
 * own per-server key with no maintainer involvement.
 *
 * One active key per IP: registering from an IP that already holds a key
 * invalidates the previous one, so a server that loses its key file can simply
 * re-register. That bounds only *concurrent* keys per IP, so it is paired with a
 * per-IP minute-tier rate limit (REGISTER_RATE_LIMITER) on top of the per-key
 * rolling limits and the REGISTRATION_ENABLED kill-switch.
 *
 * KNOWN LIMIT, stated rather than implied: an IP is not an identity. Two
 * self-hosters behind one CGNAT address take each other's key away by
 * registering, and one actor with many addresses accumulates many permanent
 * keys. Neither is fixed here, because both need a durable identity this
 * endpoint does not have — an invite code, an operator approval step, or a
 * credential that survives an address change — and inventing one silently
 * inside the registration path would be worse than the gap.
 *
 * What IS bounded, as of RELAY_DAILY_BUDGET (see checkDailyBudget), is the thing
 * the accumulation was worth doing: the relay's total daily sends are now one
 * shared counter, so extra keys no longer buy extra budget. The remaining
 * exposure from key accumulation is denial-of-service against that shared pool,
 * rather than unbounded sending. Note what that does NOT cover — registration
 * itself spends Cloudflare KV writes per call, and no counter here can see that
 * limit approaching.
 *
 * The CGNAT collision has no mitigation here at all. An operator running a relay
 * for users who may share an address should keep REGISTRATION_ENABLED off and
 * issue keys out of band.
 *
 * "One" is enforced by the IP's RelayCoordinator, not by a KV read followed by a
 * KV write. As four separate KV operations — look up the prior key, revoke it,
 * mint, index — concurrent registrations from one address interleaved into
 * several permanent active keys, which is the quota abuse the invariant exists
 * to prevent. The coordinator swaps the IP's current key and returns the one it
 * displaced in a single serialized turn, so racing registrations form a chain
 * where each revokes its predecessor.
 *
 * That chain is claim-then-COMMIT, not claim alone. Minting happens outside the
 * coordinator's turn, and the swap by itself left this hole:
 *
 *   1. A claims the IP and stalls before minting.
 *   2. B claims it, is handed A as its predecessor, mints, and revokes A —
 *      which does nothing, because A's key record does not exist yet.
 *   3. A resumes and mints. Two permanently active keys for one IP, and the
 *      revoke that was supposed to prevent it has already run.
 *
 * So after minting, every registration asks the coordinator whether it is still
 * the IP's current registration (confirmRegistrationIp). A registration that was
 * displaced while minting deletes the key it just made and hands out nothing —
 * it is the only party that still can, since its successor already looked and
 * found nothing there. Exactly one key survives any interleaving.
 */
export async function handleRegister(request: Request, rc: RequestContext): Promise<Response> {
  const { env } = rc;
  if (!registrationEnabled(env)) {
    return fail(rc, 403, "self-registration is disabled");
  }
  // Bucket on the /64 for IPv6 so a single allocation can't defeat the per-IP
  // registration limit and one-key-per-IP rule by rotating source addresses.
  const registeredIp = ipBucket(request.headers.get("CF-Connecting-IP") ?? "");
  // No usable client address means no rate limit and no one-key-per-IP
  // invariant, and both of those are the entire containment around an
  // unauthenticated endpoint that mints permanent credentials. Minting anyway —
  // which is what the previous `registeredIp && ...` guards did — turned a
  // missing or unparseable header (a service binding, a preview environment, a
  // platform change) into uncapped key minting. Same fail-closed reasoning as
  // checkMinuteLimit and claimTokenForSend.
  if (!registeredIp) {
    rc.log({ level: "error", event: "register.denied", reason: "no_client_ip" });
    return fail(rc, 503, "registration is temporarily unavailable");
  }
  if (!(await checkMinuteLimit(env.REGISTER_RATE_LIMITER, rc, registeredIp))) {
    rc.log({ level: "warn", event: "register.denied", reason: "rate_limited", ip: registeredIp });
    const response = fail(rc, 429, "too many registration attempts, try again later", {
      window: "minute",
      retryAfterSeconds: 60,
    });
    response.headers.set("Retry-After", "60");
    return response;
  }
  const parsed = await jsonObjectBody<{ label?: string }>(request);
  if (!parsed.ok) {
    return fail(rc, parsed.status, parsed.error);
  }
  const label = (typeof parsed.value.label === "string" ? parsed.value.label : "").trim() || "self-registered";

  // Refuse rather than mint an unconstrained key: without the coordinator the
  // one-active-key-per-IP invariant is unenforceable, and an unconstrained
  // permanent key on a public endpoint is the thing that invariant guards. Same
  // fail-closed reasoning as checkMinuteLimit and claimTokenForSend.
  const ipStub = registrationCoordinator(env, registeredIp);
  if (!ipStub) {
    rc.log({ level: "error", event: "register.denied", reason: "coordinator_binding_missing", ip: registeredIp });
    return fail(rc, 503, "registration is temporarily unavailable");
  }

  // Reserve the id and the IP BEFORE persisting anything. Minting first meant a
  // throwing coordinator (or a KV error) left an enabled key record behind that
  // the 500 response never handed to anyone — unusable, since the raw key only
  // ever travels in the response body, but still an orphan in KV and in every
  // KV listing, mintable on repeat.
  //
  // Reordering beats minting-then-rolling-back: a compensating revoke is another
  // write on the path that just failed, so it is exactly the write least likely
  // to succeed. A failed mint instead leaves the coordinator pointing at an id
  // that has no record, and the previous key is never revoked and keeps working
  // — which is only harmless because the claim below hands the obligation to
  // revoke that previous key on to the next registration. This comment used to
  // say a failed mint "costs nothing" while the coordinator returned the
  // immediate predecessor only, and that was false: it dropped the sole
  // reference to the live key, and the address kept two permanent keys forever.
  const keyId = crypto.randomUUID();
  // Swap first, then revoke what the swap displaced. The other order is the
  // race: two registrations can both read the same prior key and both believe
  // they superseded it, leaving both of their own keys active. Here each
  // registration is handed its predecessor PLUS whatever its predecessor never
  // got round to revoking, so N racers form a chain of revocations that no
  // failed or superseded link can break and exactly one key is left standing.
  const legacyKeyId = await env.API_KEYS.get(IP_INDEX_PREFIX + registeredIp);
  const priorIds = await ipStub.claimRegistrationIp(keyId, legacyKeyId);

  // Self-registered keys don't expire — they back long-lived servers.
  const { record, key } = await mintKey(env, rc, { label, registeredIp, id: keyId });

  // Commit. Until this returns true the minted key has been handed to nobody,
  // so deleting it costs nothing; after it, the key is this IP's registration.
  if (!(await ipStub.confirmRegistrationIp(keyId))) {
    // Displaced while minting. The successor's revoke ran against an id that
    // had no record yet and did nothing, so this is the only place this key can
    // still be cleaned up. Deleting it is a compensating write, but unlike the
    // mint-then-rollback ordering rejected above it is on a path where nothing
    // has failed — and if it somehow does fail, what is left behind is an
    // orphan record that was never returned to anyone rather than a second
    // usable key.
    await revokeKeyById(env, keyId);
    rc.log({ level: "warn", event: "register.superseded_while_minting", keyId, ip: registeredIp });
    const response = fail(rc, 503, "registration is temporarily unavailable");
    response.headers.set("Retry-After", "5");
    return response;
  }

  // The KV index is no longer the authority — it only seeds a coordinator
  // instance that has never been touched, and gives revokeKeyById something to
  // tidy up. It is written after the swap and may lose a race with
  // revokeKeyById's cleanup below; that costs nothing, because the coordinator
  // holds the real answer and ignores the seed once set.
  await env.API_KEYS.put(IP_INDEX_PREFIX + registeredIp, record.id);
  // Every id the claim handed over, not just the immediate predecessor: an
  // uncommitted registration's debt is inherited, so this list is the whole
  // backlog for this address. Most of it is usually dangling ids from mints that
  // failed, which revokeKeyById reports as already gone.
  for (const priorId of priorIds) {
    if (await revokeKeyById(env, priorId)) {
      rc.log({ level: "info", event: "key.superseded", keyId: priorId, ip: registeredIp });
    }
  }
  return json({ id: record.id, label: record.label, key, expiresAt: record.expiresAt }, 201);
}

/**
 * Delete a key and all its indexes by id. Also clears the per-IP index, but only
 * if it still points at this key (so superseding a key doesn't drop a newer
 * registration's mapping). Returns false if the id was unknown.
 */
export async function revokeKeyById(env: CommonEnv, id: string): Promise<boolean> {
  const hash = await env.API_KEYS.get(KEY_INDEX_PREFIX + id);
  if (!hash) {
    return false;
  }
  const record = await env.API_KEYS.get<ApiKeyRecord>(KEY_PREFIX + hash, "json");
  await env.API_KEYS.delete(KEY_PREFIX + hash);
  await env.API_KEYS.delete(KEY_INDEX_PREFIX + id);
  const ip = record?.registeredIp;
  if (ip) {
    const current = await env.API_KEYS.get(IP_INDEX_PREFIX + ip);
    if (current === id) {
      await env.API_KEYS.delete(IP_INDEX_PREFIX + ip);
    }
  }
  return true;
}

// ---- router / fetch wrapper -------------------------------------------------
//
// The two workers' routing (health/send/register dispatch) and their
// `export default { fetch(...) }` wrapper (request-id minting, structured access
// logging, unhandled-error catch) are identical; only `/health`'s `configured`
// flag and `/send`'s delivery logic are provider-specific.
// createRelayFetchHandler takes those two pieces and returns each worker's
// `fetch`.

export interface RelayRouterOptions<TEnv extends CommonEnv> {
  /** Whether the provider (FCM/APNs) credentials are fully configured, surfaced on /health. */
  configured: (env: TEnv) => boolean;
  /** Provider-specific POST /send handler. */
  handleSend: (request: Request, rc: RequestContext<TEnv>) => Promise<Response>;
}

async function routeRelay<TEnv extends CommonEnv>(
  request: Request,
  path: string,
  rc: RequestContext<TEnv>,
  opts: RelayRouterOptions<TEnv>,
): Promise<Response> {
  const { env } = rc;

  if (path === "/health" && request.method === "GET") {
    return json({
      ok: true,
      configured: opts.configured(env),
      rateLimits: { perMinute: resolveLimit(env.RATE_LIMIT_PER_MINUTE, DEFAULT_LIMIT_PER_MINUTE) },
      registrationEnabled: registrationEnabled(env),
    });
  }

  if (path === "/send" && request.method === "POST") {
    return opts.handleSend(request, rc);
  }

  if (path === "/register" && request.method === "POST") {
    return handleRegister(request, rc);
  }

  // No admin surface, deliberately. There used to be `/admin/keys` (mint, list,
  // revoke) behind a bearer ADMIN_SECRET, and nothing called it: the Go server
  // uses /register and /send, the mobile apps never touch the relay, and the
  // endpoints existed only for the maintainer to curl. That made the highest
  // value credential in the deployment — one that mints and revokes every key
  // the relay honours — permanently guessable by anyone who found the hostname,
  // to save a `wrangler kv key delete`. Deleting the door beat guarding it. Key
  // management is now the CLI; see the READMEs.
  return fail(rc, 404, "not found");
}

/** Builds the `fetch` export for a relay worker from its provider-specific pieces. */
export function createRelayFetchHandler<TEnv extends CommonEnv>(opts: RelayRouterOptions<TEnv>) {
  return async function fetch(request: Request, env: TEnv, ctx: ExecutionContext): Promise<Response> {
    const requestId = crypto.randomUUID();
    const start = Date.now();
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const log = (fields: Record<string, unknown>) =>
      console.log(JSON.stringify({ ts: new Date().toISOString(), requestId, ...fields }));

    const rc: RequestContext<TEnv> = { env, ctx, requestId, log };

    let response: Response;
    try {
      response = await routeRelay(request, path, rc, opts);
    } catch (err) {
      log({ level: "error", event: "unhandled", method: request.method, path, error: errorMessage(err) });
      response = json({ error: "internal error", requestId }, 500);
    }

    response.headers.set("X-Request-Id", requestId);
    log({
      level: response.status >= 500 ? "error" : "info",
      event: "request",
      method: request.method,
      path,
      status: response.status,
      durationMs: Date.now() - start,
    });
    return response;
  };
}
