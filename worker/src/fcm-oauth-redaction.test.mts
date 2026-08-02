/**
 * What the FCM relay is allowed to say about a failed OAuth token exchange.
 *
 * The relay's logging rule is that upstream response bodies never reach the
 * operator log (push-relay-shared/AGENTS.md). One narrow exception is recorded
 * there — the clipped provider reason on `send.fcm_failed` — and the OAuth
 * exchange is explicitly not covered by it: this is the request that carries
 * the service-account assertion, and its 200 response carries the access token.
 *
 * getAccessToken used to interpolate the whole response body into an error
 * message, and index.ts logs that message as `send.error`. Nothing failed; the
 * body simply went somewhere the contract says it does not go.
 *
 * Every assertion below is written as "the sentinel does not appear", because
 * that is the property that has to survive a future refactor — not the exact
 * wording of any one error string.
 *
 *   node --test worker/src/fcm-oauth-redaction.test.mts
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

const { oauthErrorCode, sendFcmMessage } = await import("./fcm.ts");

/**
 * A string that must never appear in anything the relay throws or logs. Stands
 * in for whatever Google puts in error_description, and for the access token
 * itself on the success path.
 */
const SENTINEL = "SENTINEL-c2VjcmV0-MUST-NOT-APPEAR";

// ---- oauthErrorCode ------------------------------------------------------

test("oauthErrorCode keeps the RFC 6749 enum and drops everything else", () => {
  const body = JSON.stringify({
    error: "invalid_grant",
    error_description: `Invalid JWT Signature. ${SENTINEL}`,
  });
  const code = oauthErrorCode(body);

  assert.equal(code, "invalid_grant", "the enum is the diagnostic an operator needs");
  assert.ok(!code.includes(SENTINEL), "error_description must not survive");
});

test("oauthErrorCode refuses an error field that is not a short identifier", () => {
  // Google is not expected to do this. The point is that the log field cannot
  // become a hole the body fits through even if some upstream decides to put
  // free text, a token, or a whole document where the enum belongs.
  for (const hostile of [
    SENTINEL,
    `invalid_grant: ${SENTINEL}`,
    "a".repeat(500),
    "Invalid JWT Signature.",
    "UPPERCASE_CODE",
  ]) {
    const code = oauthErrorCode(JSON.stringify({ error: hostile }));
    assert.equal(code, "unrecognised", `expected a placeholder for: ${hostile.slice(0, 30)}`);
    assert.ok(!code.includes(SENTINEL));
  }
});

test("oauthErrorCode reports a placeholder for a non-JSON body", () => {
  for (const body of [
    `<html><body>proxy error ${SENTINEL}</body></html>`,
    "",
    SENTINEL,
  ]) {
    const code = oauthErrorCode(body);
    assert.equal(code, "unparsable");
    assert.ok(!code.includes(SENTINEL));
  }
});

test("oauthErrorCode survives JSON that is not an object", () => {
  for (const body of ["null", "42", '"a string"', "[1,2,3]"]) {
    assert.equal(oauthErrorCode(body), "unrecognised");
  }
});

// ---- end to end through sendFcmMessage -----------------------------------

/** A throwaway RSA key, so the assertion really is signed rather than stubbed. */
async function testPrivateKeyPem(): Promise<string> {
  const pair = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;

  const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  const b64 = Buffer.from(pkcs8).toString("base64").replace(/(.{64})/g, "$1\n");
  return `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----\n`;
}

/** A KV cache that never has a token, so every call does the exchange. */
function emptyCache() {
  return {
    get: async () => null,
    put: async () => undefined,
    delete: async () => undefined,
  } as unknown as KVNamespace;
}

/** Runs sendFcmMessage against a stubbed token endpoint and returns the throw. */
async function tokenExchangeFailure(response: Response): Promise<Error> {
  const config = {
    clientEmail: "relay@example.iam.gserviceaccount.com",
    privateKeyPem: await testPrivateKeyPem(),
    projectId: "kypost-relay-test",
  };

  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => response.clone()) as typeof fetch;
  try {
    await sendFcmMessage(config, emptyCache(), {
      token: "device-token",
      title: "t",
      body: "b",
    });
  } catch (err) {
    return err as Error;
  } finally {
    globalThis.fetch = realFetch;
  }
  throw new Error("expected sendFcmMessage to throw");
}

test("a failed token exchange never carries the response body", async () => {
  const err = await tokenExchangeFailure(
    new Response(
      JSON.stringify({ error: "invalid_client", error_description: SENTINEL }),
      { status: 401 },
    ),
  );

  assert.ok(!err.message.includes(SENTINEL), `body leaked into: ${err.message}`);
  assert.match(err.message, /status=401/, "the status is the part operators act on");
  assert.match(err.message, /error=invalid_client/, "the enum is what replaced the body");
});

test("an unparsable token-endpoint failure still says nothing about the body", async () => {
  const err = await tokenExchangeFailure(
    new Response(`<html>gateway timeout ${SENTINEL}</html>`, { status: 502 }),
  );

  assert.ok(!err.message.includes(SENTINEL), `body leaked into: ${err.message}`);
  assert.match(err.message, /status=502/);
  assert.match(err.message, /error=unparsable/);
});

test("an unparsable 200 does not leak a prefix of the access token", async () => {
  // V8's JSON.parse quotes the first ten characters of its input back in the
  // SyntaxError message. On a 200 that input is the token response, so letting
  // the raw parse throw put a prefix of the access token into `send.error`
  // through an exception nobody wrote. Ten characters is not a usable
  // credential; it is also not something that needs to be in a log.
  const err = await tokenExchangeFailure(
    new Response(`${SENTINEL}-not-json`, { status: 200 }),
  );

  assert.ok(!err.message.includes(SENTINEL), `body leaked into: ${err.message}`);
  assert.ok(
    !err.message.includes(SENTINEL.slice(0, 10)),
    `a prefix of the body leaked into: ${err.message}`,
  );
  assert.match(err.message, /was not json/);
});
