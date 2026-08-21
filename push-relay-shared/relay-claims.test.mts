/**
 * The relay's claim rules, exercised as interleavings rather than as types.
 *
 * Both bugs this file was written for typechecked perfectly: a failing send
 * releasing ownership that a concurrent successful send from the same key had
 * just earned, and a takeover decided from an eventually consistent KV read
 * that cannot see a key minted seconds ago. Concurrency is what has to be
 * asserted here, so every case below is written as an explicit ordering.
 *
 * No test framework and no fixtures: `node --test` with the runtime's own type
 * stripping (Node >= 22.18). The one piece of machinery is the module hook
 * below, which stands in for `cloudflare:workers` so the Durable Object class
 * can be constructed outside workerd against a Map.
 *
 *   node --test push-relay-shared/
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";

const durableObjectStub =
  "data:text/javascript," +
  encodeURIComponent("export class DurableObject{constructor(ctx,env){this.ctx=ctx;this.env=env}}");

registerHooks({
  resolve(specifier, context, nextResolve) {
    return specifier === "cloudflare:workers"
      ? { url: durableObjectStub, shortCircuit: true }
      : nextResolve(specifier, context);
  },
});

const { RelayCoordinator } = await import("./relay-coordinator.ts");
const {
  claimTokenForSend,
  createRelayFetchHandler,
  settleToken,
  ipBucket,
  readSendPayload,
  MAX_SEND_BODY_BYTES,
  MAX_TOKEN_LENGTH,
  MAX_TITLE_LENGTH,
  MAX_DATA_ENTRIES,
  KEY_INDEX_PREFIX,
  KEY_PREFIX,
  BOUND_TOKEN_PREFIX,
  handleRegister,
} = await import("./push-relay-common.ts");

// ---- doubles ---------------------------------------------------------------

/** Durable Object storage: the get/put/delete shapes relay-coordinator uses. */
function storage() {
  const cells = new Map();
  return {
    cells,
    async get(key) {
      return cells.get(key);
    },
    async put(keyOrEntries, value) {
      if (typeof keyOrEntries === "string") {
        cells.set(keyOrEntries, value);
        return;
      }
      for (const [k, v] of Object.entries(keyOrEntries)) {
        cells.set(k, v);
      }
    },
    async delete(keys) {
      for (const key of Array.isArray(keys) ? keys : [keys]) {
        cells.delete(key);
      }
    },
  };
}

function coordinator() {
  return new RelayCoordinator({ storage: storage() }, {});
}

/**
 * An env whose RELAY_COORDINATOR hands out one coordinator per instance name —
 * the property the real binding provides and the whole reason claims serialize.
 */
function relayEnv(kv = new Map()) {
  const instances = new Map();
  return {
    instances,
    API_KEYS: {
      async get(key) {
        const value = kv.get(key);
        return value === undefined ? null : value;
      },
    },
    RELAY_COORDINATOR: {
      idFromName: (name) => name,
      get(name) {
        if (!instances.has(name)) {
          instances.set(name, coordinator());
        }
        return instances.get(name);
      },
    },
  };
}

function requestContext(env) {
  return { env, ctx: { waitUntil() {} }, requestId: "test", log() {} };
}

/** KV contents for one enabled, non-expiring key. */
function activeKeyKv(keyId, rawKey = "raw-" + keyId) {
  return [
    [KEY_INDEX_PREFIX + keyId, rawKey],
    [KEY_PREFIX + rawKey, { id: keyId, label: keyId, enabled: true, createdAt: "2026-01-01T00:00:00Z" }],
  ];
}

const owner = (c) => c.ctx.storage.cells.get("owner");

// ---- the rollback race -----------------------------------------------------

test("a failed send does not release ownership a concurrent successful send earned", async () => {
  for (const failFirst of [true, false]) {
    const c = coordinator();
    await c.claimToken({ keyId: "key-a" }); // send A takes the claim
    await c.claimToken({ keyId: "key-a" }); // send B rides it, concurrently

    if (failFirst) {
      await c.settleToken("key-a", false);
      await c.settleToken("key-a", true);
    } else {
      await c.settleToken("key-a", true);
      await c.settleToken("key-a", false);
    }
    assert.equal(owner(c), "key-a", `ownership lost when failFirst=${failFirst}`);
  }
});

test("a claim under which nothing delivered is released once the last send settles", async () => {
  const c = coordinator();
  await c.claimToken({ keyId: "key-a" });
  await c.claimToken({ keyId: "key-a" });

  await c.settleToken("key-a", false);
  assert.equal(owner(c), "key-a", "released while another send was still in flight");
  assert.equal(await c.settleToken("key-a", false), true);
  assert.equal(owner(c), undefined);

  // Released means reclaimable by someone else, which is the point of rolling
  // back a claim that never delivered.
  assert.equal((await c.claimToken({ keyId: "key-b" })).owner, "key-b");
});

test("a claim written before this schema existed survives a failed send", async () => {
  // What a coordinator instance looked like under the previous version: an
  // owner, no confirmed flag, no in-flight count. That owner delivered — it was
  // the only way to become one — so the first failed send after the deploy must
  // not unpin it.
  const c = coordinator();
  await c.ctx.storage.put({ seeded: true, owner: "key-a" });

  await c.claimToken({ keyId: "key-a" });
  await c.settleToken("key-a", false);
  assert.equal(owner(c), "key-a", "a deploy plus one failed send unpinned an existing claim");
});

test("a settle from a displaced key cannot disturb the current claim", async () => {
  const c = coordinator();
  await c.claimToken({ keyId: "key-a" });
  await c.claimToken({ keyId: "key-b", takeoverFrom: "key-a" });

  assert.equal(await c.settleToken("key-a", false), false);
  assert.equal(owner(c), "key-b");
});

test("a claim inherited from the legacy KV index survives a failed send", async () => {
  const c = coordinator();
  const first = await c.claimToken({ keyId: "key-b", legacyOwner: "key-a" });
  assert.equal(first.owner, "key-a");

  await c.claimToken({ keyId: "key-a" });
  await c.settleToken("key-a", false);
  assert.equal(owner(c), "key-a", "one failed send wiped a claim earned before the coordinator existed");
});

// A claim with no recorded age is stamped on first sight rather than read as
// ancient. The KV index carries no timestamp and the previous schema stored
// none, so "unknown" spans the deploy that introduces this field — during which
// a legacy claim really can be seconds old, made by a key KV has not converged
// on yet. That is the case the takeover guard exists for.
test("a claim of unknown age counts as fresh, once, and its stamp does not slide", async () => {
  for (const seed of [
    async (c) => {
      await c.claimToken({ keyId: "key-b", legacyOwner: "key-a" }); // adopted from KV
    },
    async (c) => {
      await c.ctx.storage.put({ seeded: true, owner: "key-a" }); // written by the older schema
    },
  ]) {
    const c = coordinator();
    await seed(c);

    const first = await c.claimToken({ keyId: "key-b" });
    assert.equal(first.owner, "key-a");
    assert.ok(Date.now() - first.claimedAt < 1_000, `unknown age read as ancient: ${first.claimedAt}`);

    // Persisted, not recomputed: a stamp that moved with every call would keep
    // the claim inside its own grace window forever.
    const again = await c.claimToken({ keyId: "key-b" });
    assert.equal(again.claimedAt, first.claimedAt, "the stamp slid on a second call");
  }
});

test("a legacy claim is not taken over on a KV read that may not have converged", async () => {
  const env = relayEnv(new Map([[BOUND_TOKEN_PREFIX + (await tokenHash()), "key-a"]]));
  const denied = await claimTokenForSend(requestContext(env), "device-token", "key-b");
  assert.equal(denied.allowed, false);
  assert.equal(denied.logReason, "token_claim_too_recent");
});

// ---- takeover --------------------------------------------------------------

test("takeover is refused while the owner's key record may not have converged in KV", async () => {
  const env = relayEnv(); // no key records at all: every key reads as deleted
  const rc = requestContext(env);

  assert.deepEqual(await claimTokenForSend(rc, "device-token", "key-a"), { allowed: true });

  const stolen = await claimTokenForSend(rc, "device-token", "key-b");
  assert.equal(stolen.allowed, false);
  assert.equal(stolen.logReason, "token_claim_too_recent");
  assert.equal(stolen.status, 403);
});

test("an aged claim whose key is gone is taken over, one whose key is active is not", async () => {
  const env = relayEnv(new Map(activeKeyKv("key-a")));
  const rc = requestContext(env);
  assert.deepEqual(await claimTokenForSend(rc, "device-token", "key-a"), { allowed: true });
  await settleToken(rc, "device-token", "key-a", true);

  // Age the claim past the KV convergence window the guard above enforces.
  const instance = env.instances.values().next().value;
  await instance.ctx.storage.put("claimedAt", Date.now() - 120_000);

  const whileActive = await claimTokenForSend(rc, "device-token", "key-b");
  assert.equal(whileActive.allowed, false);
  assert.equal(whileActive.logReason, "token_bound_to_other_key");

  env.API_KEYS.get = async () => null; // key-a revoked
  assert.deepEqual(await claimTokenForSend(rc, "device-token", "key-b"), { allowed: true });
  assert.equal(owner(instance), "key-b");
});

test("a pre-existing KV claim is adopted rather than treated as free", async () => {
  const env = relayEnv(new Map([...activeKeyKv("key-a"), [BOUND_TOKEN_PREFIX + (await tokenHash()), "key-a"]]));
  const denied = await claimTokenForSend(requestContext(env), "device-token", "key-b");
  assert.equal(denied.allowed, false);
});

async function tokenHash() {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("device-token"));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---- registration bucketing ------------------------------------------------

test("ipBucket returns a bucket only for something that is actually an address", async () => {
  assert.equal(ipBucket("203.0.113.7"), "203.0.113.7");
  assert.equal(ipBucket("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
  assert.equal(ipBucket("2001:db8::1%eth0"), "2001:db8:0:0::/64");
  assert.equal(ipBucket("::1"), "0:0:0:0::/64"); // what wrangler dev sends
  assert.equal(ipBucket("1:2:3:4:5:6:7::"), "1:2:3:4::/64"); // "::" for exactly one group
  // Anything unusable must bucket to "", which is what makes handleRegister
  // refuse rather than mint an unconstrained key. The IPv6 forms below are the
  // ones that look plausible enough to be padded into a bucket: too few hextets
  // with no "::" to justify them, too many, two compression markers, or a group
  // that is not hex at all.
  for (const bad of [
    "",
    "   ",
    "unknown",
    "203.0.113.999",
    "not:an:address",
    "2001:db8:1",
    "2001:db8:1:2:3:4:5:6:7",
    "1:2:3:4:5:6:7:8::",
    "1::2::3",
    "::ffff:garbage",
  ]) {
    assert.equal(ipBucket(bad), "", `expected no bucket for ${JSON.stringify(bad)}`);
  }
});

// ---- bounded request bodies -------------------------------------------------
//
// The bound has to be asserted on a real Request, not on a helper called with a
// string: what it exists to prevent is `await request.json()` allocating the
// whole body first, and only a Request can show that the ceiling is applied to
// the stream rather than to an already-materialized value.

function sendRequest(body, headers = {}) {
  return new Request("https://relay.example/send", { method: "POST", body, headers });
}

test("a /send body over the ceiling is refused before it is parsed", async () => {
  // Valid JSON, and a body that would be accepted if it were smaller — so the
  // refusal can only be the byte ceiling.
  const huge = JSON.stringify({ token: "device-token", title: "t", body: "x".repeat(MAX_SEND_BODY_BYTES) });
  const refused = await readSendPayload(sendRequest(huge));
  assert.equal(refused.ok, false);
  assert.equal(refused.status, 413);
});

test("an oversized Content-Length is refused without reading the body at all", async () => {
  // A declared length over the ceiling is refused up front; the stream counter
  // is what catches a body that lies about (or omits) its length.
  const lying = new Request("https://relay.example/send", {
    method: "POST",
    body: JSON.stringify({ token: "device-token" }),
    headers: { "Content-Length": String(MAX_SEND_BODY_BYTES + 1) },
  });
  const refused = await readSendPayload(lying);
  assert.equal(refused.ok, false);
  assert.equal(refused.status, 413);
});

test("/send fields are type-checked, not coerced", async () => {
  for (const [body, error] of [
    ["not json at all", "invalid json body"],
    ["null", "invalid json body"],
    ["[]", "invalid json body"],
    [JSON.stringify({}), "missing token"],
    [JSON.stringify({ token: "   " }), "missing token"],
    [JSON.stringify({ token: 42 }), "invalid token"],
    [JSON.stringify({ token: "x".repeat(MAX_TOKEN_LENGTH + 1) }), "invalid token"],
    // Coerced, these became the string "[object Object]" in a delivered push.
    [JSON.stringify({ token: "t", title: { a: 1 } }), "invalid title"],
    [JSON.stringify({ token: "t", body: ["x"] }), "invalid body"],
    [JSON.stringify({ token: "t", data: "x" }), "invalid data"],
    [JSON.stringify({ token: "t", data: [1, 2] }), "invalid data"],
    // data was forwarded to the provider unexamined: any JSON value at all
    // could ride into an FCM/APNs request under a key holder's quota.
    [JSON.stringify({ token: "t", data: { k: { nested: true } } }), "invalid data value"],
    [JSON.stringify({ token: "t", data: { ["k".repeat(65)]: "v" } }), "invalid data key"],
    [
      JSON.stringify({
        token: "t",
        data: Object.fromEntries(Array.from({ length: MAX_DATA_ENTRIES + 1 }, (_, i) => ["k" + i, "v"])),
      }),
      "too many data entries",
    ],
  ]) {
    const refused = await readSendPayload(sendRequest(body));
    assert.equal(refused.ok, false, `accepted ${body.slice(0, 40)}`);
    assert.equal(refused.status, 400);
    assert.equal(refused.error, error);
  }
});

test("/send text fields are clamped rather than refused, and unknown fields are ignored", async () => {
  // A title is a sender and a body is a subject: both arrive from whoever
  // emailed the self-hoster, so a long one must clip, not drop the push. The
  // `platform` field is one the Go sender already sends and this relay has
  // never read — refusing unknown fields would make the next one an outage.
  const accepted = await readSendPayload(
    sendRequest(
      JSON.stringify({
        token: "  device-token  ",
        title: "T".repeat(MAX_TITLE_LENGTH + 50),
        body: "B".repeat(5_000),
        data: { subject: "S".repeat(5_000) },
        platform: "android",
      }),
    ),
  );
  assert.equal(accepted.ok, true);
  assert.equal(accepted.value.token, "device-token");
  assert.equal(accepted.value.title.length, MAX_TITLE_LENGTH);
  assert.equal(accepted.value.body.length, 1024);
  assert.equal(accepted.value.data.subject.length, 1024);
  assert.equal("platform" in accepted.value, false);
});

test("clamping a text field never splits a surrogate pair", async () => {
  // "😀" is two code units, so clamping at an odd boundary would otherwise
  // leave a lone high surrogate — an unpaired surrogate is not valid text and
  // JSON.stringify of it produces a replacement character upstream.
  const accepted = await readSendPayload(
    sendRequest(JSON.stringify({ token: "t", title: "😀".repeat(MAX_TITLE_LENGTH) })),
  );
  assert.equal(accepted.ok, true);
  assert.equal(/[\ud800-\udbff]$/.test(accepted.value.title), false, "clamped mid-pair");
});

// ---- no admin surface -------------------------------------------------------

// The relay used to serve /admin/keys behind a bearer ADMIN_SECRET so the
// maintainer could curl it. Nothing else ever called it, which made an
// always-guessable credential that mints and revokes every key the relay
// honours the price of saving a `wrangler kv key delete`. The routes are gone;
// this is here so re-adding one is a deliberate act with a failing test in
// front of it, not a quiet convenience.
test("the admin routes are gone, for every method and with any credential", async () => {
  const handler = createRelayFetchHandler({ configured: () => true, handleSend: async () => new Response("sent") });
  const env = { API_KEYS: {}, ADMIN_SECRET: "s".repeat(64) };
  const ctx = { waitUntil() {} };

  for (const [method, path] of [
    ["GET", "/admin/keys"],
    ["POST", "/admin/keys"],
    ["DELETE", "/admin/keys/some-id"],
    ["PUT", "/admin/keys"],
  ]) {
    const request = new Request("https://relay.example" + path, {
      method,
      headers: { Authorization: "Bearer " + env.ADMIN_SECRET, "CF-Connecting-IP": "203.0.113.7" },
    });
    const response = await handler(request, env, ctx);
    assert.equal(response.status, 404, `${method} ${path} answered ${response.status}`);
  }
});

// ---- registration: claim, mint, commit --------------------------------------
//
// The one-active-key-per-IP rule is enforced across THREE steps that are not
// one atomic operation: the coordinator swaps the IP's owner, KV mints the key,
// and the coordinator is asked again whether the minted key is still the owner.
// Only the first and third are serialized. Everything below is written as an
// explicit interleaving of the second, because that is where the bug was.

/** KV double with a hook that can stall a specific put mid-flight. */
function registerKv() {
  const cells = new Map();
  const kv = {
    cells,
    /** Called before every put; return a promise to stall the caller there. */
    beforePut: async (_key) => {},
    async get(key, type) {
      const value = cells.get(key);
      if (value === undefined) return null;
      return type === "json" && typeof value === "string" ? JSON.parse(value) : value;
    },
    async put(key, value) {
      await kv.beforePut(key);
      cells.set(key, value);
    },
    async delete(key) {
      cells.delete(key);
    },
  };
  return kv;
}

function registerEnv(kv) {
  const instances = new Map();
  return {
    instances,
    REGISTRATION_ENABLED: "true",
    REGISTER_RATE_LIMITER: { async limit() { return { success: true }; } },
    API_KEYS: kv,
    RELAY_COORDINATOR: {
      idFromName: (name) => name,
      get(name) {
        if (!instances.has(name)) {
          instances.set(name, coordinator());
        }
        return instances.get(name);
      },
    },
  };
}

function registerRequest(ip = "203.0.113.7") {
  return new Request("https://relay.example/register", {
    method: "POST",
    body: JSON.stringify({ label: "server" }),
    headers: { "CF-Connecting-IP": ip, "Content-Type": "application/json" },
  });
}

/** Every key record currently in KV, by id. */
function activeKeyIds(kv) {
  const ids = [];
  for (const [cell, value] of kv.cells) {
    if (!cell.startsWith(KEY_PREFIX)) continue;
    const record = typeof value === "string" ? JSON.parse(value) : value;
    if (record.enabled) ids.push(record.id);
  }
  return ids.sort();
}

test("a registration displaced while minting leaves no second active key", async () => {
  const kv = registerKv();
  const env = registerEnv(kv);

  // Stall the FIRST key-record write — request A, inside mintKey — after it has
  // already claimed the IP from the coordinator. This is the exact window: A
  // owns the IP, and A's key does not exist in KV for anyone to revoke.
  let releaseA;
  const aIsMinting = new Promise((resolveReached) => {
    const held = new Promise((r) => { releaseA = r; });
    let stalled = false;
    kv.beforePut = async (cell) => {
      if (stalled || !cell.startsWith(KEY_PREFIX)) return;
      stalled = true;
      resolveReached();
      await held;
    };
  });

  const a = handleRegister(registerRequest(), requestContext(env));
  await aIsMinting;

  // B registers start to finish while A is parked. B is handed A as its
  // predecessor and revokes it — a no-op, because A has written nothing yet.
  const bResponse = await handleRegister(registerRequest(), requestContext(env));
  assert.equal(bResponse.status, 201);
  const b = await bResponse.json();

  releaseA();
  const aResponse = await a;

  // A must find out it lost and clean up after itself. Before the commit step
  // it answered 201 and left its key enabled in KV forever.
  assert.equal(aResponse.status, 503, "a superseded registration was handed a usable key");
  assert.deepEqual(
    activeKeyIds(kv),
    [b.id],
    "more than one active key survived a concurrent registration from one address",
  );
});

test("the surviving key is the last to claim, whichever order the mints finish in", async () => {
  // Same race with the stall moved: A mints fully, THEN B claims and mints. A's
  // record exists by the time B revokes it, so the cleanup happens on B's side.
  const kv = registerKv();
  const env = registerEnv(kv);

  const first = await handleRegister(registerRequest(), requestContext(env));
  const second = await handleRegister(registerRequest(), requestContext(env));
  assert.equal(first.status, 201);
  assert.equal(second.status, 201);

  const b = await second.json();
  assert.deepEqual(activeKeyIds(kv), [b.id], "the superseded key was left active");
});

test("three racing registrations from one address leave exactly one key", async () => {
  const kv = registerKv();
  const env = registerEnv(kv);

  // Stall every mint until all three have claimed, so all three are inside the
  // window at once and each one's predecessor is un-minted.
  let releaseAll;
  const held = new Promise((r) => { releaseAll = r; });
  let reached = 0;
  let resolveAllReached;
  const allReached = new Promise((r) => { resolveAllReached = r; });
  const seen = new Set();
  kv.beforePut = async (cell) => {
    if (!cell.startsWith(KEY_PREFIX) || seen.has(cell)) return;
    seen.add(cell);
    if (++reached === 3) resolveAllReached();
    await held;
  };

  const responses = [
    handleRegister(registerRequest(), requestContext(env)),
    handleRegister(registerRequest(), requestContext(env)),
    handleRegister(registerRequest(), requestContext(env)),
  ];
  await allReached;
  releaseAll();

  const settled = await Promise.all(responses);
  const issued = settled.filter((r) => r.status === 201);
  assert.equal(issued.length, 1, `${issued.length} of three racing registrations were issued a key`);
  const winner = await issued[0].json();
  assert.deepEqual(activeKeyIds(kv), [winner.id]);
});

// An IPv6 caller rotating addresses inside one /64 must land on ONE coordinator,
// or the whole chain above is per-address and the rule is unenforced. ipBucket
// is what guarantees it; this pins that handleRegister actually applies it.
test("registrations from one IPv6 /64 share a coordinator and so share the one key", async () => {
  const kv = registerKv();
  const env = registerEnv(kv);

  const firstResponse = await handleRegister(registerRequest("2001:db8:1:2:3:4:5:6"), requestContext(env));
  const secondResponse = await handleRegister(registerRequest("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), requestContext(env));
  assert.equal(firstResponse.status, 201);
  assert.equal(secondResponse.status, 201);

  assert.equal(env.instances.size, 1, "one /64 was given more than one registration coordinator");
  const second = await secondResponse.json();
  assert.deepEqual(activeKeyIds(kv), [second.id]);
});

// A registration that claims the IP and then FAILS to mint is the other half of
// the same window. Its predecessor is still the IP's only usable key — nothing
// revoked it, because the revoke happens after a commit that never came — so
// the claim it made must not swallow the debt of revoking that predecessor. If
// it does, the next registration is handed a dangling id to revoke, the real
// predecessor is never revoked, and one address holds two permanent keys.
test("a registration whose mint fails does not strand the key it displaced", async () => {
  const kv = registerKv();
  const env = registerEnv(kv);

  const firstResponse = await handleRegister(registerRequest(), requestContext(env));
  assert.equal(firstResponse.status, 201);
  const first = await firstResponse.json();

  // Second registration claims the IP, then its mint throws.
  kv.beforePut = async (cell) => {
    if (cell.startsWith(KEY_PREFIX)) throw new Error("KV write failed");
  };
  await assert.rejects(handleRegister(registerRequest(), requestContext(env)));

  // The failed mint handed out nothing, so the first key is still the IP's one
  // key and must still work.
  assert.deepEqual(activeKeyIds(kv), [first.id], "the failed mint disturbed the existing key");

  // A third registration succeeds. It must revoke the FIRST key — the only one
  // that ever existed — not just the dangling id the failed mint left behind.
  kv.beforePut = async () => {};
  const thirdResponse = await handleRegister(registerRequest(), requestContext(env));
  assert.equal(thirdResponse.status, 201);
  const third = await thirdResponse.json();

  assert.deepEqual(
    activeKeyIds(kv),
    [third.id],
    "a failed mint left one address holding two permanently active keys",
  );
});

// The same debt, lost the other way: a registration displaced WHILE minting
// deletes its own key and answers 503, but it was also carrying the obligation
// to revoke its predecessor. The winner is handed only the displaced id, which
// has no record, so the revoke chain breaks in the middle and the predecessor
// survives alongside the winner.
test("a registration displaced while minting hands its predecessor on to the winner", async () => {
  const kv = registerKv();
  const env = registerEnv(kv);

  const firstResponse = await handleRegister(registerRequest(), requestContext(env));
  assert.equal(firstResponse.status, 201);

  // A claims the IP (predecessor: the first key) and stalls inside mintKey.
  let releaseA;
  const aIsMinting = new Promise((resolveReached) => {
    const held = new Promise((r) => { releaseA = r; });
    let stalled = false;
    kv.beforePut = async (cell) => {
      if (stalled || !cell.startsWith(KEY_PREFIX)) return;
      stalled = true;
      resolveReached();
      await held;
    };
  });
  const a = handleRegister(registerRequest(), requestContext(env));
  await aIsMinting;

  // B registers start to finish while A is parked, displacing A.
  const bResponse = await handleRegister(registerRequest(), requestContext(env));
  assert.equal(bResponse.status, 201);
  const b = await bResponse.json();

  releaseA();
  assert.equal((await a).status, 503);

  assert.deepEqual(
    activeKeyIds(kv),
    [b.id],
    "the predecessor of a displaced registration was never revoked",
  );
});
