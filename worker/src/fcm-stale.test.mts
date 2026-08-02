/**
 * What the FCM relay is allowed to call a dead device token.
 *
 * Same stakes as the APNs relay (see apns-stale.test.mts): a stale verdict
 * leaves here as HTTP 410 and the backend deletes the device registration,
 * taking that account's push 2FA with it. Nothing on the server recovers it.
 *
 * The backend already refuses to be this loose in the other direction —
 * isRelayStaleResponse in processor/native_sender.go was narrowed to "410 AND
 * the structured body" precisely because matching substrings anywhere in a body
 * at any status "handed the relay far more authority than delivering a
 * notification requires". This file holds the relay to the same standard on the
 * input side.
 *
 *   node --test worker/src/fcm-stale.test.mts
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

const { isStaleResponse } = await import("./fcm.ts");

/** An FCM v1 error body, which is what the relay actually reads. */
function fcmError(code: number, status: string, errorCode: string): string {
  return JSON.stringify({
    error: {
      code,
      message: "Requested entity was not found.",
      status,
      details: [
        { "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", errorCode },
      ],
    },
  });
}

test("404 UNREGISTERED is a dead token", () => {
  assert.equal(isStaleResponse(404, fcmError(404, "NOT_FOUND", "UNREGISTERED")), true);
});

test("a malformed or mismatched token is a caller error, not a dead device", () => {
  // INVALID_ARGUMENT is what FCM returns for a token that does not belong to
  // this Firebase project — i.e. FCM_PROJECT_ID pointing at the wrong project,
  // which is a relay misconfiguration that would otherwise unpair every Android
  // device on the first send after deploy.
  assert.equal(isStaleResponse(400, fcmError(400, "INVALID_ARGUMENT", "INVALID_ARGUMENT")), false);
});

test("auth and quota faults are never stale", () => {
  assert.equal(isStaleResponse(401, fcmError(401, "UNAUTHENTICATED", "THIRD_PARTY_AUTH_ERROR")), false);
  assert.equal(isStaleResponse(403, fcmError(403, "PERMISSION_DENIED", "SENDER_ID_MISMATCH")), false);
  assert.equal(isStaleResponse(429, fcmError(429, "RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED")), false);
  assert.equal(isStaleResponse(503, fcmError(503, "UNAVAILABLE", "UNAVAILABLE")), false);
});

test("the word alone does not delete a device without the status to back it", () => {
  // The failure this rules out: anything between us and Google — a proxy, an
  // auth error quoting the request, an HTML error page — that happens to carry
  // the substring. Status and reason must agree.
  assert.equal(isStaleResponse(500, "internal error while handling unregistered sender"), false);
  assert.equal(isStaleResponse(502, "<html>NotRegistered</html>"), false);
  assert.equal(isStaleResponse(200, "unregistered"), false);
});

test("a 404 that is not about registration does not delete a device", () => {
  // A 404 from a wrong send URL (bad project id in the path) is not a verdict
  // about the token at all.
  assert.equal(isStaleResponse(404, "<html><title>404 Not Found</title></html>"), false);
});

test("a 404 needs the structured errorCode, not the word somewhere in the body", () => {
  // The status is right and the word is present, but nothing in the response
  // actually says UNREGISTERED about this token. Matching on the substring
  // would let a proxy's error page, or a message quoting the request, retire a
  // live device — the same "substrings anywhere in the body" shape the backend
  // already rejected in isRelayStaleResponse.
  assert.equal(isStaleResponse(404, "not found: unregistered sender project"), false);
  assert.equal(isStaleResponse(404, JSON.stringify({ error: { message: "unregistered" } })), false);
  // Malformed JSON at the right status is not a verdict either.
  assert.equal(isStaleResponse(404, "{unregistered"), false);
});

test("the errorCode is read from the structured details, wherever it sits", () => {
  // Only the documented shape counts, but it must count regardless of what
  // else Google puts alongside it.
  const body = JSON.stringify({
    error: {
      code: 404,
      status: "NOT_FOUND",
      details: [
        { "@type": "type.googleapis.com/google.rpc.BadRequest" },
        { "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", errorCode: "UNREGISTERED" },
      ],
    },
  });
  assert.equal(isStaleResponse(404, body), true);
});
