/**
 * What the relay is allowed to call a dead device token.
 *
 * A "stale" verdict is not a delivery failure — it travels back as HTTP 410 and
 * the backend responds by DELETING the device registration
 * (processor/push_dispatch.go, RemoveNativeDevice). That is unrecoverable from
 * the server side: the device has to be paired again by hand, and until it is,
 * the account has lost push 2FA. So the bar for staleness is Apple telling us
 * the token is gone, not Apple telling us we asked wrong.
 *
 * The distinction is not hypothetical here. apns-config.test.mts exists because
 * a typo'd APNS_ENVIRONMENT sent production tokens to the sandbox host, "and the
 * backend unregistered the device" — the environment parser was fixed, but the
 * classifier that turned Apple's complaint into a deletion was not. Every 400
 * below is a relay-side configuration mistake wearing a device-token error's
 * name.
 *
 *   node --test worker-apns/src/apns-stale.test.mts
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

const { isStaleResponse } = await import("./apns.ts");

/** Apple's error bodies are `{"reason":"..."}`, plus a timestamp on 410. */
function reason(name: string): string {
  return JSON.stringify({ reason: name });
}

test("410 Unregistered is the only verdict that may delete a device", () => {
  assert.equal(
    isStaleResponse(410, JSON.stringify({ reason: "Unregistered", timestamp: 1710000000000 })),
    true,
  );
});

test("a 400 naming the device token is a relay fault, not a dead device", () => {
  // BadDeviceToken: the token is well-formed but belongs to the OTHER APNs
  // environment. Every production device looks like this the moment
  // APNS_ENVIRONMENT is wrong — which is precisely how the whole fleet gets
  // unpaired by one bad deploy.
  assert.equal(isStaleResponse(400, reason("BadDeviceToken")), false);

  // DeviceTokenNotForTopic: the token does not match APNS_TOPIC. The name says
  // "DeviceToken", the cause is the topic — ours, not theirs.
  assert.equal(isStaleResponse(400, reason("DeviceTokenNotForTopic")), false);

  // TopicDisallowed / BadTopic: unambiguously our configuration.
  assert.equal(isStaleResponse(400, reason("TopicDisallowed")), false);
  assert.equal(isStaleResponse(400, reason("BadTopic")), false);
});

test("a 400 that merely contains the word Unregistered does not delete a device", () => {
  // Apple documents Unregistered as 410 only. A 400 carrying the string is
  // either a body we misread or a reason we do not know; both must fail toward
  // "retry later", never toward "unpair the device".
  assert.equal(isStaleResponse(400, reason("Unregistered")), false);
});

test("provider-token and server faults are never stale", () => {
  assert.equal(isStaleResponse(403, reason("ExpiredProviderToken")), false);
  assert.equal(isStaleResponse(403, reason("InvalidProviderToken")), false);
  assert.equal(isStaleResponse(429, reason("TooManyRequests")), false);
  assert.equal(isStaleResponse(500, reason("InternalServerError")), false);
  assert.equal(isStaleResponse(503, reason("ServiceUnavailable")), false);
  // An HTML error page from something in front of Apple, with no reason at all.
  assert.equal(isStaleResponse(502, "<html><body>Bad Gateway</body></html>"), false);
});
