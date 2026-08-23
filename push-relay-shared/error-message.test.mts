/**
 * A fail-closed handler must not fail open because its logging threw.
 *
 * Every catch on the relay's refusal paths formatted the caught value as
 * `String((err as Error).message ?? err)`. The cast is a lie the compiler
 * accepts: a `catch` binding is `unknown`, JavaScript permits `throw null`, and
 * reading `.message` off null throws a TypeError out of the handler. The 429
 * for a throwing rate limiter and the 502 for a dead provider then became the
 * outer router's generic 500, and the log line recorded the logging bug instead
 * of the outage that caused it.
 *
 *   node --test push-relay-shared/error-message.test.mts
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

const { checkMinuteLimit, errorMessage } = await import("./push-relay-common.ts");

// The values a `throw` can carry. Anything here reaching `.message` unguarded
// is a second exception; anything here reaching `String()` is fine.
const thrown: [string, unknown, string][] = [
  ["an Error", new Error("boom"), "boom"],
  ["a subclass", new TypeError("wrong type"), "wrong type"],
  ["null", null, "null"],
  ["undefined", undefined, "undefined"],
  ["a bare string", "just a string", "just a string"],
  ["a number", 42, "42"],
  ["a plain object", { code: 500 }, "[object Object]"],
  ["a symbol", Symbol("sym"), "Symbol(sym)"],
];

for (const [label, value, want] of thrown) {
  test(`errorMessage formats ${label} without throwing`, () => {
    assert.equal(errorMessage(value), want);
  });
}

function recordingContext() {
  const lines: Record<string, unknown>[] = [];
  return {
    lines,
    rc: {
      env: {} as never,
      ctx: {} as never,
      requestId: "test-request",
      log: (fields: Record<string, unknown>) => lines.push(fields),
    },
  };
}

// The binding is the one that matters: a limiter that throws must still refuse
// the request, and must say why.
for (const [label, value] of thrown) {
  test(`a rate limiter that throws ${label} still fails closed`, async () => {
    const { rc, lines } = recordingContext();
    const limiter = {
      limit: async () => {
        throw value;
      },
    };

    const allowed = await checkMinuteLimit(limiter, rc as never, "some-key");

    assert.equal(allowed, false, "a throwing limiter must not admit the request");
    const logged = lines.find((l) => l.event === "ratelimit.binding_error");
    assert.ok(logged, "the refusal was not traced");
    assert.equal(typeof logged.error, "string");
  });
}
