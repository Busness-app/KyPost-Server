/**
 * Shared push-relay logic used by both Cloudflare Workers: the FCM relay
 * (worker/) and the APNs relay (worker-apns/). Everything below is identical
 * between them — API-key admin/registration endpoints, per-minute rate limiting,
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
  ADMIN_SECRET: string;
  /**
   * Minute limit is ENFORCED by the PUSH_RATE_LIMITER binding (simple.limit in
   * wrangler.toml). This var is display-only (/health + 429 body) and must be kept
   * equal to that binding's limit.
   *
   * Hour/day rolling tiers are deliberately absent — see the single-tier note
   * above checkMinuteLimit, whose fail-closed behaviour depends on it.
   */
  RATE_LIMIT_PER_MINUTE?: string; // display only; default 10
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
  /** How the key was issued: "admin" (via ADMIN_SECRET) or "self" (via /register). */
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
 * megabyte-sized strings into KV and into every /admin/keys listing.
 */
export const MAX_LABEL_LENGTH = 64;

// ---- small helpers ---------------------------------------------------------

export interface RequestContext<TEnv extends CommonEnv = CommonEnv> {
  env: TEnv;
  ctx: ExecutionContext;
  requestId: string;
  log: (fields: Record<string, unknown>) => void;
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

export function bearer(request: Request): string {
  const header = request.headers.get("Authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : "";
}

/**
 * Constant-time comparison for the admin secret. Always walks the longer of
 * the two strings' length rather than returning early on a length mismatch,
 * so response timing doesn't leak how many characters of the presented
 * value happened to match the configured secret's length.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const maxLen = Math.max(a.length, b.length);
  let mismatch = a.length === b.length ? 0 : 1;
  for (let i = 0; i < maxLen; i++) {
    const ca = i < a.length ? a.charCodeAt(i) : 0;
    const cb = i < b.length ? b.charCodeAt(i) : 0;
    mismatch |= ca ^ cb;
  }
  return mismatch === 0;
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

export function requireAdmin(request: Request, env: CommonEnv): boolean {
  const secret = (env.ADMIN_SECRET ?? "").trim();
  if (!secret) {
    return false;
  }
  return timingSafeEqual(bearer(request), secret);
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

// Single-tier rate limiting: a decision, not a gap. Stated here rather than as a
// TODO because checkMinuteLimit's fail-closed behaviour depends on the minute
// tier being the only tier.
//
// Enforced: a per-minute cap via the native rate-limiting bindings
// (PUSH_RATE_LIMITER per key, REGISTER_RATE_LIMITER per IP). No KV writes on an
// accepted send.
//
// Not enforced: rolling hour and day caps. They required a KV read-modify-write
// per send, which capped the free tier at ~1,000 pushes/day — the limiter became
// the outage. They are not coming back in that form.
//
// The cost: a caller who stays under the per-minute cap can sustain it
// indefinitely, so the minute limit bounds burst rate but not daily volume
// against someone else's FCM quota. That residual is why the fail-closed
// behaviour below is not negotiable.
//
// To restore the upper tiers, use Durable Objects (exact atomic counters, no KV
// write pressure, Workers Paid) and revisit the fail-closed reasoning at both
// call sites, which is stated in terms of "the only tier".

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
    // against someone else's FCM quota, traced only by this log line.
    //
    // Callers surface it as 429 with a Retry-After: the request is refused not
    // because the caller misbehaved but because the relay cannot currently tell
    // whether they did.
    rc.log({ level: "error", event: "ratelimit.binding_error", error: String((err as Error).message ?? err) });
    return false;
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
      blobs: [record.id, record.label, record.source ?? "admin"],
      doubles: [1],
    });
  } catch {
    // analytics is best-effort; a send must never fail on it.
  }
}

// ---- /admin/keys -----------------------------------------------------------

export type ExpiryResult = { ok: true; expiresAt: string | null } | { ok: false; error: string };

/**
 * Resolve an optional expiry from the admin create body. An explicit ISO
 * `expiresAt` wins; otherwise `ttlDays` (a positive number) is added to now.
 * `expiresAt: null` means the key never expires.
 */
export function resolveExpiry(body: { expiresAt?: unknown; ttlDays?: unknown }): ExpiryResult {
  if (typeof body.expiresAt === "string" && body.expiresAt.trim()) {
    const at = Date.parse(body.expiresAt.trim());
    if (!Number.isFinite(at)) {
      return { ok: false, error: "invalid expiresAt (expected an ISO 8601 timestamp)" };
    }
    return { ok: true, expiresAt: new Date(at).toISOString() };
  }
  if (body.ttlDays !== undefined && body.ttlDays !== null) {
    const days = Number(body.ttlDays);
    if (!Number.isFinite(days) || days <= 0) {
      return { ok: false, error: "invalid ttlDays (expected a positive number)" };
    }
    return { ok: true, expiresAt: new Date(Date.now() + days * 86_400_000).toISOString() };
  }
  return { ok: true, expiresAt: null };
}

/**
 * Mint an API key, persist only its hash, and return the record plus the raw
 * key (which the caller returns to the client exactly once). Shared by the
 * admin endpoint and public self-registration.
 */
export async function mintKey(
  env: CommonEnv,
  rc: RequestContext,
  opts: {
    label: string;
    expiresAt: string | null;
    source: "admin" | "self";
    registeredIp?: string | null;
    /**
     * Pre-generated key id. handleRegister needs the id BEFORE the record
     * exists, so it can reserve the IP first and persist nothing until that
     * reservation succeeds. Defaults to a fresh uuid for every other caller.
     */
    id?: string;
  },
): Promise<{ record: ApiKeyRecord; key: string }> {
  const key = randomToken();
  const id = opts.id ?? crypto.randomUUID();
  const record: ApiKeyRecord = {
    id,
    // Clamped here rather than at each call site so no minting path can store an
    // unbounded label (see MAX_LABEL_LENGTH).
    label: opts.label.slice(0, MAX_LABEL_LENGTH),
    enabled: true,
    createdAt: new Date().toISOString(),
    expiresAt: opts.expiresAt,
    source: opts.source,
    registeredIp: opts.registeredIp ?? null,
  };
  const hash = await sha256Hex(key);
  await env.API_KEYS.put(KEY_PREFIX + hash, JSON.stringify(record));
  await env.API_KEYS.put(KEY_INDEX_PREFIX + id, hash);
  rc.log({ level: "info", event: "key.created", keyId: id, label: opts.label, source: opts.source, expiresAt: opts.expiresAt });
  return { record, key };
}

/**
 * Parse a JSON object body, tolerating anything else. `request.json()` accepts
 * valid-but-non-object JSON (`null`, arrays, scalars), and reading a property off
 * `null` throws — a body of literal `null` turned these handlers into a 500.
 */
async function jsonObjectBody<T extends object>(request: Request): Promise<Partial<T>> {
  let parsed: unknown;
  try {
    parsed = await request.json();
  } catch {
    return {};
  }
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Partial<T>) : {};
}

export async function handleAdminCreate(request: Request, rc: RequestContext): Promise<Response> {
  const { env } = rc;
  const body = await jsonObjectBody<{ label?: string; ttlDays?: unknown; expiresAt?: unknown }>(request);
  const label = (body.label ?? "").trim() || "unnamed";

  const expiry = resolveExpiry(body);
  if (!expiry.ok) {
    return fail(rc, 400, expiry.error);
  }

  const { record, key } = await mintKey(env, rc, { label, expiresAt: expiry.expiresAt, source: "admin" });
  // The raw key is returned exactly once; only its hash is stored.
  return json({ id: record.id, label: record.label, key, expiresAt: record.expiresAt }, 201);
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
 * "One" is enforced by the IP's RelayCoordinator, not by a KV read followed by a
 * KV write. As four separate KV operations — look up the prior key, revoke it,
 * mint, index — concurrent registrations from one address interleaved into
 * several permanent active keys, which is the quota abuse the invariant exists
 * to prevent. The coordinator swaps the IP's current key and returns the one it
 * displaced in a single serialized turn, so racing registrations form a chain
 * where each revokes its predecessor and exactly one key is left active.
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
  const body = await jsonObjectBody<{ label?: string }>(request);
  const label = (body.label ?? "").trim() || "self-registered";

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
  // /admin/keys listing, mintable on repeat.
  //
  // Reordering beats minting-then-rolling-back: a compensating revoke is another
  // write on the path that just failed, so it is exactly the write least likely
  // to succeed. Here a failed mint instead leaves the coordinator pointing at an
  // id that has no record, which costs nothing — revokeKeyById reports the
  // unknown id as "already gone", the previous key is never revoked and keeps
  // working, and the next registration displaces the dangling id.
  const keyId = crypto.randomUUID();
  // Swap first, then revoke what the swap displaced. The other order is the
  // race: two registrations can both read the same prior key and both believe
  // they superseded it, leaving both of their own keys active. Here each
  // registration is handed its own immediate predecessor, so N racers form a
  // chain of N-1 revocations and exactly one key is left standing.
  const legacyKeyId = await env.API_KEYS.get(IP_INDEX_PREFIX + registeredIp);
  const priorId = await ipStub.claimRegistrationIp(keyId, legacyKeyId);

  // Self-registered keys don't expire by default — they back long-lived servers.
  const { record, key } = await mintKey(env, rc, { label, expiresAt: null, source: "self", registeredIp, id: keyId });

  // The KV index is no longer the authority — it only seeds a coordinator
  // instance that has never been touched, and gives revokeKeyById something to
  // tidy up. It is written after the swap and may lose a race with
  // revokeKeyById's cleanup below; that costs nothing, because the coordinator
  // holds the real answer and ignores the seed once set.
  await env.API_KEYS.put(IP_INDEX_PREFIX + registeredIp, record.id);
  if (priorId && (await revokeKeyById(env, priorId))) {
    rc.log({ level: "info", event: "key.superseded", keyId: priorId, ip: registeredIp });
  }
  return json({ id: record.id, label: record.label, key, expiresAt: record.expiresAt }, 201);
}

export async function handleAdminList(rc: RequestContext): Promise<Response> {
  const { env } = rc;
  const now = Date.now();
  const keys = [];
  // KV list() returns one page (1,000 keys); follow the cursor to completion.
  // Stopping at the first page silently hid active credentials from the operator
  // doing the revoking, which is the one listing that has to be complete.
  let cursor: string | undefined;
  do {
    const listed = await env.API_KEYS.list({ prefix: KEY_PREFIX, cursor });
    cursor = listed.list_complete ? undefined : listed.cursor;
    for (const entry of listed.keys) {
      const record = await env.API_KEYS.get<ApiKeyRecord>(entry.name, "json");
      if (!record) {
        continue;
      }
      keys.push({
        id: record.id,
        label: record.label,
        enabled: record.enabled,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt ?? null,
        expired: isExpired(record, now),
        source: record.source ?? "admin",
        registeredIp: record.registeredIp ?? null,
        // Usage (send counts + last-seen) lives in Analytics Engine, not KV.
      });
    }
  } while (cursor);
  return json({ keys });
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

export async function handleAdminRevoke(id: string, rc: RequestContext): Promise<Response> {
  const revoked = await revokeKeyById(rc.env, id);
  if (!revoked) {
    return fail(rc, 404, "key not found");
  }
  rc.log({ level: "info", event: "key.revoked", keyId: id });
  return json({ ok: true });
}

// ---- router / fetch wrapper -------------------------------------------------
//
// The two workers' routing (health/send/register/admin-keys dispatch) and their
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

  if (path === "/admin/keys") {
    if (!requireAdmin(request, env)) {
      return fail(rc, 401, "unauthorized");
    }
    if (request.method === "POST") {
      return handleAdminCreate(request, rc);
    }
    if (request.method === "GET") {
      return handleAdminList(rc);
    }
    return fail(rc, 405, "method not allowed");
  }

  const revokeMatch = /^\/admin\/keys\/([^/]+)$/.exec(path);
  if (revokeMatch && request.method === "DELETE") {
    if (!requireAdmin(request, env)) {
      return fail(rc, 401, "unauthorized");
    }
    return handleAdminRevoke(decodeURIComponent(revokeMatch[1]), rc);
  }

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
      log({ level: "error", event: "unhandled", method: request.method, path, error: String((err as Error)?.message ?? err) });
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
