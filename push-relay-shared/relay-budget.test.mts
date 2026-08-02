/**
 * A ceiling on what the whole relay can spend in a day.
 *
 * The per-minute limiter buckets per key and per registering IP, and the file
 * that defines it says plainly what that leaves open: "a caller who stays under
 * the per-minute cap can sustain it indefinitely, so the minute limit bounds
 * burst rate but not daily volume against someone else's FCM quota." With public
 * registration open, keys are self-issued and an IP is not an identity, so the
 * number of keys one actor can hold is bounded only by the number of addresses
 * they can appear from — and every one of them gets its own per-minute budget.
 *
 * That note names the fix it was waiting for: "use Durable Objects (exact atomic
 * counters, no KV write pressure)". This is that counter. It is aggregate on
 * purpose — a limit that is per-key is one more thing an attacker mints their
 * way around, and the resource being protected (the operator's FCM/APNs quota)
 * is shared, so the limit on it has to be too.
 *
 *   node --test push-relay-shared/relay-budget.test.mts
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

const { RelayCoordinator } = await import("./relay-coordinator.ts");
const { checkDailyBudget } = await import("./push-relay-common.ts");

function storage() {
  const cells = new Map();
  return {
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

/** An env whose coordinator binding hands out one instance per name. */
function budgetEnv(extra = {}) {
  const instances = new Map();
  return {
    instances,
    RELAY_COORDINATOR: {
      idFromName: (name) => name,
      get(name) {
        if (!instances.has(name)) instances.set(name, coordinator());
        return instances.get(name);
      },
    },
    ...extra,
  };
}

function requestContext(env) {
  return { env, ctx: { waitUntil() {} }, requestId: "test", log() {} };
}

const DAY_ONE = Date.UTC(2026, 7, 1, 12, 0, 0);

test("spends the budget and refuses the send that would exceed it", async () => {
  const rc = requestContext(budgetEnv({ RELAY_DAILY_BUDGET: "3" }));

  for (let i = 1; i <= 3; i++) {
    const result = await checkDailyBudget(rc, DAY_ONE);
    assert.equal(result.allowed, true, `send ${i} was refused inside the budget`);
  }

  const over = await checkDailyBudget(rc, DAY_ONE);
  assert.equal(over.allowed, false, "the fourth send was allowed past a budget of 3");
});

test("a refused send does not consume budget it was denied", async () => {
  const rc = requestContext(budgetEnv({ RELAY_DAILY_BUDGET: "1" }));

  assert.equal((await checkDailyBudget(rc, DAY_ONE)).allowed, true);
  assert.equal((await checkDailyBudget(rc, DAY_ONE)).allowed, false);
  // Still exactly at the limit rather than climbing: a rejected caller
  // hammering the relay must not push the counter further from a reset.
  assert.equal((await checkDailyBudget(rc, DAY_ONE)).used, 1);
});

test("the budget resets on the next UTC day", async () => {
  const rc = requestContext(budgetEnv({ RELAY_DAILY_BUDGET: "1" }));

  assert.equal((await checkDailyBudget(rc, DAY_ONE)).allowed, true);
  assert.equal((await checkDailyBudget(rc, DAY_ONE)).allowed, false);

  const nextDay = DAY_ONE + 24 * 60 * 60 * 1000;
  const after = await checkDailyBudget(rc, nextDay);
  assert.equal(after.allowed, true, "the budget did not reset at the day boundary");
  assert.equal(after.used, 1, "the new day started from a stale count");
});

test("every key shares one budget, so minting more keys buys nothing", async () => {
  // The whole point: the counter is not bucketed by key or by IP. Two
  // "different callers" draw from the same pool.
  const env = budgetEnv({ RELAY_DAILY_BUDGET: "2" });
  const alice = requestContext(env);
  const bob = requestContext(env);

  assert.equal((await checkDailyBudget(alice, DAY_ONE)).allowed, true);
  assert.equal((await checkDailyBudget(bob, DAY_ONE)).allowed, true);
  assert.equal((await checkDailyBudget(bob, DAY_ONE)).allowed, false,
    "a second key got its own budget; the cap is per-key, not aggregate");
});

test("no configured budget leaves sends unmetered", async () => {
  // Existing deployments have no RELAY_DAILY_BUDGET set. They must keep working
  // exactly as before rather than inheriting a surprise ceiling — the counter
  // is a ceiling an operator opts into, not a default that silently caps a
  // relay that was fine yesterday.
  const rc = requestContext(budgetEnv());
  for (let i = 0; i < 50; i++) {
    assert.equal((await checkDailyBudget(rc, DAY_ONE)).allowed, true);
  }
});

test("a budget of 0 refuses everything rather than reading as unlimited", async () => {
  // "0" is the shape an operator writes to close the relay. Treating it as
  // "unset" would be the exact inversion of what they asked for.
  const rc = requestContext(budgetEnv({ RELAY_DAILY_BUDGET: "0" }));
  assert.equal((await checkDailyBudget(rc, DAY_ONE)).allowed, false);
});

test("a missing coordinator binding fails closed", async () => {
  // Same reasoning as checkMinuteLimit: a budget that cannot be counted is
  // indistinguishable from a deployment whose binding drifted, and this is the
  // only tier bounding daily volume once it is configured.
  const rc = requestContext({ RELAY_DAILY_BUDGET: "10" });
  assert.equal((await checkDailyBudget(rc, DAY_ONE)).allowed, false);
});
