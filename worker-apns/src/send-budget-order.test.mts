/**
 * What the daily budget is allowed to charge for.
 *
 * The budget exists to bound what the relay spends against the operator's APNs
 * quota. A request refused at the token-ownership claim never reaches Apple, so
 * charging it is not conservative — it is wrong, and it is an amplification: any
 * holder of any valid key could spend the entire day's budget by sending to
 * device tokens they do not own, delivering nothing, and every legitimate
 * self-hoster is refused for the rest of the day. That turns a cost ceiling into
 * a cheap total outage, which is the opposite of the trade it exists to make.
 *
 * So the order is: minute limit, claim, THEN budget, then dispatch. A budget
 * refusal after the claim settles it as undelivered, which releases it — the
 * same close-out every other post-claim failure path uses.
 *
 *   node --test worker-apns/src/send-budget-order.test.mts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";

const durableObjectStub =
  "data:text/javascript," +
  encodeURIComponent("export class DurableObject{constructor(ctx,env){this.ctx=ctx;this.env=env}}");

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "cloudflare:workers") {
      return { url: durableObjectStub, shortCircuit: true };
    }
    if (specifier.startsWith(".") && !/\.[cm]?[jt]s$/.test(specifier)) {
      return nextResolve(specifier + ".ts", context);
    }
    return nextResolve(specifier, context);
  },
});

const worker = await import("./index.ts");
const { RelayCoordinator } = await import("../../push-relay-shared/relay-coordinator.ts");
const { KEY_PREFIX, KEY_INDEX_PREFIX, BOUND_TOKEN_PREFIX, sha256Hex } = await import(
  "../../push-relay-shared/push-relay-common.ts"
);

const AUTH_KEY = "-----BEGIN PRIVATE KEY-----\nMHc=\n-----END PRIVATE KEY-----";
const API_KEY = "relay-key-under-test";

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
      for (const [k, v] of Object.entries(keyOrEntries)) cells.set(k, v);
    },
    async delete(keys) {
      for (const key of Array.isArray(keys) ? keys : [keys]) cells.delete(key);
    },
  };
}

/** A fully configured APNs env with a budget of exactly one send. */
async function env(kvEntries: [string, unknown][] = []) {
  const kv = new Map(kvEntries);
  kv.set(KEY_PREFIX + (await sha256Hex(API_KEY)), {
    id: "key-under-test",
    label: "test",
    enabled: true,
    createdAt: "2026-01-01T00:00:00Z",
  });
  const instances = new Map();
  return {
    APNS_AUTH_KEY: AUTH_KEY,
    APNS_KEY_ID: "KEYID12345",
    APNS_TEAM_ID: "TEAMID1234",
    APNS_TOPIC: "com.urlxl.mail",
    APNS_ENVIRONMENT: "production",
    APNS_TOKEN_CACHE: {
      async get() {
        return "cached-provider-token"; // skip ES256 signing; nothing here reaches Apple
      },
      async put() {},
      async delete() {},
    },
    RELAY_DAILY_BUDGET: "1",
    // No limiter binding in this harness; the minute tier is covered elsewhere.
    RATELIMIT_FAIL_OPEN: "true",
    API_KEYS: {
      async get(key: string) {
        const value = kv.get(key);
        return value === undefined ? null : value;
      },
    },
    RELAY_COORDINATOR: {
      idFromName: (name: string) => name,
      get(name: string) {
        if (!instances.has(name)) instances.set(name, new RelayCoordinator({ storage: storage() }, {}));
        return instances.get(name);
      },
    },
    USAGE_ANALYTICS: { writeDataPoint() {} },
  };
}

const ctx = { waitUntil(p: Promise<unknown>) { void p; } };

function send(e: unknown, token: string) {
  return worker.default.fetch(
    new Request("https://relay.example/send", {
      method: "POST",
      headers: { Authorization: "Bearer " + API_KEY },
      body: JSON.stringify({ token, title: "t", body: "b" }),
    }),
    e,
    ctx,
  );
}

/** Marks a device token as already owned by another key, via the legacy index. */
async function ownedByAnother(token: string): Promise<[string, unknown][]> {
  return [
    [BOUND_TOKEN_PREFIX + (await sha256Hex(token)), "key-someone-else"],
    [KEY_INDEX_PREFIX + "key-someone-else", "raw-other"],
    [
      KEY_PREFIX + "raw-other",
      { id: "key-someone-else", label: "other", enabled: true, createdAt: "2026-01-01T00:00:00Z" },
    ],
  ];
}

test("a send refused at the ownership claim does not spend the daily budget", async () => {
  const taken = "device-token-owned-by-someone-else";
  const e = await env(await ownedByAnother(taken));

  // Stub Apple so a send that DOES get through can be told apart from one that
  // never reached dispatch.
  const realFetch = globalThis.fetch;
  let appleCalls = 0;
  globalThis.fetch = (async () => {
    appleCalls++;
    return new Response("", { status: 200 });
  }) as typeof fetch;

  try {
    const denied = await send(e, taken);
    assert.equal(denied.status, 403, "expected the claim to be refused");
    assert.equal(appleCalls, 0, "a refused claim reached Apple");

    // The budget is 1. If the refusal above consumed it, this legitimate send
    // to a free token is refused 429 and the relay is down for the day on
    // traffic that delivered nothing.
    const allowed = await send(e, "a-free-device-token");
    assert.equal(
      allowed.status,
      200,
      `the refused send spent the budget; this legitimate send got ${allowed.status}`,
    );
    assert.equal(appleCalls, 1);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("the budget still bounds sends that do reach the provider", async () => {
  // The guard above must not have turned the budget off: the second delivering
  // send, against a budget of 1, is still refused.
  const e = await env();

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response("", { status: 200 })) as typeof fetch;

  try {
    assert.equal((await send(e, "token-one")).status, 200);

    const over = await send(e, "token-two");
    assert.equal(over.status, 429, "the budget did not bound a second delivering send");
    assert.equal(over.headers.get("Retry-After") !== null, true, "429 carried no Retry-After");
  } finally {
    globalThis.fetch = realFetch;
  }
});

// The other half of the same question: what the budget must GIVE BACK.
//
// A draw that is never spent is a draw that should not have been taken. The
// budget bounds what this relay spends against the operator's APNs quota, and a
// send that fails before any request is made to Apple spends none of it — so
// charging it is the same amplification as charging a refused claim, just
// arrived at from the other end. The realistic shape is not an attacker: it is
// one wrong APNS_KEY_ID. Every send then fails provider-token generation, and
// by the time the operator notices and fixes it, the day's budget is gone and
// the relay stays down until UTC midnight on traffic that never left Cloudflare.
//
// This is deliberately narrow. A token Apple REJECTED (410, BadDeviceToken) is
// not refunded: that request reached Apple and spent the quota this budget
// exists to bound. Refunding it would make garbage device tokens free and hand
// any key holder an unmetered channel to Apple, which is the trade backwards.
test("a send that never reaches Apple gives its budget draw back", async () => {
  const e = await env();
  // An empty token cache forces provider-token generation, and the harness's
  // auth key is not a usable ES256 key — so the send fails before any request
  // to Apple, exactly as a wrong APNS_KEY_ID does in production.
  e.APNS_TOKEN_CACHE = {
    async get() {
      return null;
    },
    async put() {},
    async delete() {},
  } as unknown as typeof e.APNS_TOKEN_CACHE;

  const workingCache = (await env()).APNS_TOKEN_CACHE;
  const realFetch = globalThis.fetch;
  let appleCalls = 0;
  const deferred: Promise<unknown>[] = [];
  const trackingCtx = { waitUntil(p: Promise<unknown>) { deferred.push(p); } };
  globalThis.fetch = (async () => {
    appleCalls++;
    return new Response("", { status: 200 });
  }) as typeof fetch;

  const sendWith = (token: string) =>
    worker.default.fetch(
      new Request("https://relay.example/send", {
        method: "POST",
        headers: { Authorization: "Bearer " + API_KEY },
        body: JSON.stringify({ token, title: "t", body: "b" }),
      }),
      e,
      trackingCtx,
    );

  try {
    const failed = await sendWith("token-one");
    assert.equal(failed.status, 502, "expected a delivery failure before Apple");
    assert.equal(appleCalls, 0, "the send reached Apple after all; this test proves nothing");
    await Promise.all(deferred);

    // The operator fixes the credential. The budget is 1: if the failure above
    // kept its draw, the relay is still down for the day having delivered
    // nothing, and no amount of fixing brings it back before UTC midnight.
    e.APNS_TOKEN_CACHE = workingCache;
    const allowed = await sendWith("token-two");
    assert.equal(
      allowed.status,
      200,
      `a send that never reached Apple spent the day's budget; the next got ${allowed.status}`,
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("a token Apple rejected keeps its budget draw", async () => {
  const e = await env();

  const realFetch = globalThis.fetch;
  const deferred: Promise<unknown>[] = [];
  const trackingCtx = { waitUntil(p: Promise<unknown>) { deferred.push(p); } };
  let appleCalls = 0;
  globalThis.fetch = (async () => {
    appleCalls++;
    return new Response(JSON.stringify({ reason: "BadDeviceToken" }), { status: 400 });
  }) as typeof fetch;

  const sendWith = (token: string) =>
    worker.default.fetch(
      new Request("https://relay.example/send", {
        method: "POST",
        headers: { Authorization: "Bearer " + API_KEY },
        body: JSON.stringify({ token, title: "t", body: "b" }),
      }),
      e,
      trackingCtx,
    );

  try {
    assert.equal((await sendWith("garbage-one")).status, 502);
    assert.equal(appleCalls, 1, "the rejected send did not reach Apple");
    await Promise.all(deferred);

    // That request spent Apple's quota, so the budget of 1 is gone. Refunding
    // it would make an endless stream of invented device tokens free.
    const over = await sendWith("garbage-two");
    assert.equal(over.status, 429, "a rejected device token was refunded the quota it spent");
  } finally {
    globalThis.fetch = realFetch;
  }
});
