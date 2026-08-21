/**
 * The one key in an APNs payload that a caller may not write.
 *
 * `aps` is Apple's reserved dictionary — it carries the alert, the sound, and
 * the category that binds the client's Approve/Deny actions for an MFA
 * challenge. Everything else at the top level is custom data, and the relay
 * forwards the caller's `data` map there so the app can read it.
 *
 * `data` is a caller-supplied `Record<string, string>`, and it used to be spread
 * over the payload AFTER `aps` was written. A caller who put an `"aps"` entry in
 * it therefore replaced Apple's dictionary with a string: the push passed key
 * validation, took a per-minute slot and a unit of the daily budget, and then
 * went to Apple as a payload that cannot be delivered. Same shape for an MFA
 * challenge, whose category is what puts the buttons on the notification.
 *
 * So `aps` is written last and wins. Overwriting the whole APNs contract is not
 * something a `data` field gets to do by choosing a name.
 *
 *   node --test worker-apns/src/apns-payload.test.mts
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith(".") && !/\.[cm]?[jt]s$/.test(specifier)) {
      return nextResolve(specifier + ".ts", context);
    }
    return nextResolve(specifier, context);
  },
});

const { sendApnsMessage } = await import("./apns.ts");

const config = {
  authKey: "-----BEGIN PRIVATE KEY-----\nMHc=\n-----END PRIVATE KEY-----",
  keyId: "KEYID12345",
  teamId: "TEAMID1234",
  topic: "com.urlxl.mail",
  environment: "production" as const,
};

/** Skips ES256 signing: nothing in this file reaches Apple. */
const cache = {
  async get() {
    return "cached-provider-token";
  },
  async put() {},
  async delete() {},
};

/** Sends one message against a stubbed Apple and returns the JSON body sent. */
async function payloadFor(message: { token: string; title: string; body: string; data?: Record<string, string> }) {
  const realFetch = globalThis.fetch;
  let sent: string | undefined;
  globalThis.fetch = (async (_url: unknown, init: RequestInit) => {
    sent = init.body as string;
    return new Response("", { status: 200 });
  }) as unknown as typeof fetch;
  try {
    const result = await sendApnsMessage(config, cache as unknown as KVNamespace, message);
    assert.equal(result.ok, true);
  } finally {
    globalThis.fetch = realFetch;
  }
  return JSON.parse(sent!);
}

test("a data field named aps cannot replace Apple's reserved dictionary", async () => {
  const payload = await payloadFor({
    token: "device-token",
    title: "real title",
    body: "real body",
    data: { aps: "clobbered", type: "mail" },
  });

  assert.equal(typeof payload.aps, "object", "the aps dictionary was replaced by a caller's data field");
  assert.equal(payload.aps.alert.title, "real title");
  assert.equal(payload.aps.alert.body, "real body");
  assert.equal(payload.aps.category, "MAIL_NOTIFICATION");
  assert.equal(payload.type, "mail", "unreserved data fields must still ride at the top level");
});

test("an MFA challenge keeps its category even when data tries to overwrite aps", async () => {
  // The category is what puts Approve/Deny on the notification. Losing it to a
  // caller-chosen key name is the difference between a usable 2FA prompt and a
  // dead one.
  const payload = await payloadFor({
    token: "device-token",
    title: "Sign-in request",
    body: "Approve?",
    data: { aps: JSON.stringify({ alert: "nope" }), type: "mfa_challenge" },
  });

  assert.equal(payload.aps.category, "MFA_CHALLENGE");
  assert.equal(payload.aps.alert.body, "Approve?");
});

test("custom data still reaches the top level unchanged", async () => {
  const payload = await payloadFor({
    token: "device-token",
    title: "t",
    body: "b",
    data: { type: "mail", accountId: "acct-1", messageId: "msg-1" },
  });

  assert.equal(payload.accountId, "acct-1");
  assert.equal(payload.messageId, "msg-1");
  assert.equal(payload.aps.sound, "default");
  assert.equal(payload.aps["mutable-content"], 1);
});
