/**
 * APNs relay configuration, asserted at the edges that act on it.
 *
 * APNS_ENVIRONMENT used to be read with `as "production" | "sandbox"`, a cast
 * that asserts a validation nobody wrote. Every typo became sandbox, every
 * production device token then came back 400 BadDeviceToken, and the backend
 * unregistered the device — all while /health said "configured". A pure-function
 * test of the parser would not have caught that, because the parser was the part
 * that did not exist: what has to be asserted is that an unparseable value
 * reaches /health and /send as a configuration FAILURE. So both are driven here
 * through the real fetch handler.
 *
 *   node --test worker-apns/src/apns-config.test.mts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";

// index.ts value-re-exports RelayCoordinator for the runtime to find, which
// pulls in `cloudflare:workers`. Same stand-in as relay-claims.test.mts.
const durableObjectStub =
  "data:text/javascript," +
  encodeURIComponent("export class DurableObject{constructor(ctx,env){this.ctx=ctx;this.env=env}}");

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "cloudflare:workers") {
      return { url: durableObjectStub, shortCircuit: true };
    }
    // The worker sources import each other without a file extension, which
    // wrangler's bundler resolves and Node's ESM resolver does not. Adding it
    // back here keeps the extension style of the shipped code the thing
    // wrangler expects, rather than bending it to suit the test runner.
    if (specifier.startsWith(".") && !/\.[cm]?[jt]s$/.test(specifier)) {
      return nextResolve(specifier + ".ts", context);
    }
    return nextResolve(specifier, context);
  },
});

const worker = await import("./index.ts");
const { parseApnsEnvironment } = worker;
const { KEY_PREFIX, sha256Hex } = await import("../../push-relay-shared/push-relay-common.ts");

// A .p8 shaped well enough to be present; nothing here reaches Apple.
const AUTH_KEY = "-----BEGIN PRIVATE KEY-----\nMHc=\n-----END PRIVATE KEY-----";
const API_KEY = "relay-key-under-test";

/** A fully configured env, minus whatever the caller overrides. */
async function env(overrides: Record<string, unknown> = {}) {
  const hash = await sha256Hex(API_KEY);
  return {
    APNS_AUTH_KEY: AUTH_KEY,
    APNS_KEY_ID: "KEYID12345",
    APNS_TEAM_ID: "TEAMID1234",
    APNS_TOPIC: "com.urlxl.mail",
    APNS_ENVIRONMENT: "production",
    APNS_TOKEN_CACHE: { async get() { return null; }, async put() {}, async delete() {} },
    API_KEYS: {
      async get(key: string) {
        if (key === KEY_PREFIX + hash) {
          return { id: "key-a", label: "test", enabled: true, createdAt: "2026-01-01T00:00:00Z" };
        }
        return null;
      },
    },
    ...overrides,
  };
}

const ctx = { waitUntil() {} };

function health(e: unknown) {
  return worker.default.fetch(new Request("https://relay.example/health"), e, ctx);
}

function send(e: unknown) {
  return worker.default.fetch(
    new Request("https://relay.example/send", {
      method: "POST",
      headers: { Authorization: "Bearer " + API_KEY },
      body: JSON.stringify({ token: "device-token", title: "t", body: "b" }),
    }),
    e,
    ctx,
  );
}

test("APNS_ENVIRONMENT names a host or is a configuration failure", () => {
  assert.equal(parseApnsEnvironment("production"), "production");
  assert.equal(parseApnsEnvironment("sandbox"), "sandbox");
  // Case and surrounding whitespace are operator noise, not a different value.
  assert.equal(parseApnsEnvironment("  Production "), "production");
  assert.equal(parseApnsEnvironment("SANDBOX"), "sandbox");
  // Unset is the only value that gets a default: a self-hoster who never sets
  // the variable wants the production host.
  assert.equal(parseApnsEnvironment(undefined), "production");
  assert.equal(parseApnsEnvironment(""), "production");
  assert.equal(parseApnsEnvironment("   "), "production");

  // Everything else must be null. "prodution" is the exact typo that used to
  // route production tokens to the sandbox; the rest are the other shapes an
  // operator plausibly writes.
  for (const bad of ["prodution", "prod", "production ish", "dev", "development", "true", "1", "sandbox,production"]) {
    assert.equal(parseApnsEnvironment(bad), null, `accepted ${JSON.stringify(bad)}`);
  }
});

test("an unparseable APNS_ENVIRONMENT reports unconfigured rather than defaulting", async () => {
  const good = await (await health(await env())).json();
  assert.equal(good.configured, true);

  const bad = await (await health(await env({ APNS_ENVIRONMENT: "prodution" }))).json();
  assert.equal(bad.configured, false, "a typo'd environment still reported the relay as configured");
});

test("an unparseable APNS_ENVIRONMENT refuses the send instead of picking a host", async () => {
  const response = await send(await env({ APNS_ENVIRONMENT: "prodution" }));
  assert.equal(response.status, 500);
  assert.equal((await response.json()).error, "relay not configured");
});

test("a missing credential is still a configuration failure", async () => {
  for (const missing of ["APNS_AUTH_KEY", "APNS_KEY_ID", "APNS_TEAM_ID", "APNS_TOPIC"]) {
    const e = await env({ [missing]: "   " });
    assert.equal((await (await health(e)).json()).configured, false, `${missing} blank still read as configured`);
    assert.equal((await send(e)).status, 500, `${missing} blank still attempted a send`);
  }
});
