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
export const IP_INDEX_PREFIX = "ipkey:"; // ipkey:<ip>      -> keyId (one active key per IP)
export const BOUND_TOKEN_PREFIX = "boundtoken:"; // boundtoken:<sha256(deviceToken)> -> keyId (first sender owns it)

export const DEFAULT_LIMIT_PER_MINUTE = 10;

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
 */
export function ipBucket(ip: string): string {
  const trimmed = ip.trim();
  if (!trimmed.includes(":")) {
    return trimmed; // IPv4 (or empty) — use as-is
  }
  // Strip any zone id and expand "::" to reconstruct the first four hextets.
  const addr = trimmed.split("%")[0];
  const [head, tail] = addr.split("::");
  const headGroups = head ? head.split(":").filter((g) => g !== "") : [];
  const tailGroups = tail ? tail.split(":").filter((g) => g !== "") : [];
  const missing = 8 - (headGroups.length + tailGroups.length);
  const groups =
    tail === undefined
      ? headGroups
      : [...headGroups, ...Array(Math.max(0, missing)).fill("0"), ...tailGroups];
  const prefix = [0, 1, 2, 3].map((i) => (groups[i] ?? "0").toLowerCase());
  return prefix.join(":") + "::/64";
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

export type TokenBindingResult = { allowed: true } | { allowed: false; reason: string };

/**
 * Checks whether keyId may send to token: allowed if the token is unclaimed,
 * already claimed by this same key, or the claiming key is no longer active.
 */
export async function checkTokenBinding(env: CommonEnv, token: string, keyId: string): Promise<TokenBindingResult> {
  const tokenHash = await sha256Hex(token);
  const boundKeyId = await env.API_KEYS.get(BOUND_TOKEN_PREFIX + tokenHash);
  if (!boundKeyId || boundKeyId === keyId) {
    return { allowed: true };
  }
  const boundHash = await env.API_KEYS.get(KEY_INDEX_PREFIX + boundKeyId);
  if (!boundHash) {
    return { allowed: true }; // the claiming key was fully deleted
  }
  const boundRecord = await env.API_KEYS.get<ApiKeyRecord>(KEY_PREFIX + boundHash, "json");
  if (!boundRecord || !boundRecord.enabled || isExpired(boundRecord, Date.now())) {
    return { allowed: true }; // claiming key is revoked/disabled/expired: free to reclaim
  }
  return { allowed: false, reason: "token is already bound to a different active api key" };
}

/** Claims token for keyId. */
export async function bindToken(env: CommonEnv, token: string, keyId: string): Promise<void> {
  const tokenHash = await sha256Hex(token);
  await env.API_KEYS.put(BOUND_TOKEN_PREFIX + tokenHash, keyId);
}

/** Releases token's claim (used to roll back a pre-send claim on a dead token). */
export async function releaseToken(env: CommonEnv, token: string): Promise<void> {
  const tokenHash = await sha256Hex(token);
  await env.API_KEYS.delete(BOUND_TOKEN_PREFIX + tokenHash);
}

export type ClaimResult =
  | { allowed: true; newlyClaimed: boolean }
  | { allowed: false; reason: string };

/**
 * Checks the token binding and, when the token is unclaimed, claims it for keyId
 * BEFORE delivery — claiming afterwards would let a first-sender deliver a
 * spoofed push ahead of the legitimate owner's claim. KV is eventually
 * consistent, so this narrows but cannot eliminate a simultaneous-first-send
 * race; that needs a strongly-consistent store (Durable Object). `newlyClaimed`
 * lets the caller release the claim if delivery reveals the token is dead.
 */
export async function claimTokenForSend(env: CommonEnv, token: string, keyId: string): Promise<ClaimResult> {
  const result = await checkTokenBinding(env, token, keyId);
  if (!result.allowed) {
    return result;
  }
  const tokenHash = await sha256Hex(token);
  const existing = await env.API_KEYS.get(BOUND_TOKEN_PREFIX + tokenHash);
  if (existing === keyId) {
    return { allowed: true, newlyClaimed: false };
  }
  await bindToken(env, token, keyId);
  return { allowed: true, newlyClaimed: true };
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
  opts: { label: string; expiresAt: string | null; source: "admin" | "self"; registeredIp?: string | null },
): Promise<{ record: ApiKeyRecord; key: string }> {
  const key = randomToken();
  const id = crypto.randomUUID();
  const record: ApiKeyRecord = {
    id,
    label: opts.label,
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

export async function handleAdminCreate(request: Request, rc: RequestContext): Promise<Response> {
  const { env } = rc;
  let body: { label?: string; ttlDays?: unknown; expiresAt?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    body = {};
  }
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
 */
export async function handleRegister(request: Request, rc: RequestContext): Promise<Response> {
  const { env } = rc;
  if (!registrationEnabled(env)) {
    return fail(rc, 403, "self-registration is disabled");
  }
  const rawIp = request.headers.get("CF-Connecting-IP");
  // Bucket on the /64 for IPv6 so a single allocation can't defeat the per-IP
  // registration limit and one-key-per-IP rule by rotating source addresses.
  const registeredIp = rawIp ? ipBucket(rawIp) : rawIp;
  if (registeredIp && !(await checkMinuteLimit(env.REGISTER_RATE_LIMITER, rc, registeredIp))) {
    rc.log({ level: "warn", event: "register.denied", reason: "rate_limited", ip: registeredIp });
    const response = fail(rc, 429, "too many registration attempts, try again later", {
      window: "minute",
      retryAfterSeconds: 60,
    });
    response.headers.set("Retry-After", "60");
    return response;
  }
  let body: { label?: string };
  try {
    body = (await request.json()) as { label?: string };
  } catch {
    body = {};
  }
  const label = (body.label ?? "").trim() || "self-registered";

  // Enforce one active key per IP: invalidate any prior key for this IP first.
  if (registeredIp) {
    const priorId = await env.API_KEYS.get(IP_INDEX_PREFIX + registeredIp);
    if (priorId && (await revokeKeyById(env, priorId))) {
      rc.log({ level: "info", event: "key.superseded", keyId: priorId, ip: registeredIp });
    }
  }

  // Self-registered keys don't expire by default — they back long-lived servers.
  const { record, key } = await mintKey(env, rc, { label, expiresAt: null, source: "self", registeredIp });
  if (registeredIp) {
    await env.API_KEYS.put(IP_INDEX_PREFIX + registeredIp, record.id);
  }
  return json({ id: record.id, label: record.label, key, expiresAt: record.expiresAt }, 201);
}

export async function handleAdminList(rc: RequestContext): Promise<Response> {
  const { env } = rc;
  const now = Date.now();
  const listed = await env.API_KEYS.list({ prefix: KEY_PREFIX });
  const keys = [];
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
