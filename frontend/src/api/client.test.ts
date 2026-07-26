import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpError, postJSON } from "./client";

function fakeJSONResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => "application/json" },
    json: async () => body,
    text: async () => JSON.stringify(body)
  } as unknown as Response;
}

describe("requestJSON error handling", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("throws an HttpError carrying the parsed body and status on a non-OK response", async () => {
    const body = { error: "some recipients have no usable key", keylessRecipients: ["carol@example.com"] };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(fakeJSONResponse(409, body)));

    let caught: unknown;
    try {
      await postJSON("/api/mail/send", {});
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(HttpError);
    const err = caught as HttpError;
    expect(err.status).toBe(409);
    expect(err.body).toEqual(body);
    // Same message shape as before this change, so toErrorMessage() callers
    // that only ever read .message are unaffected.
    expect(err.message).toBe("request failed: 409 - some recipients have no usable key");
  });

  it("still produces a plain HttpError (Error subclass) with no body for non-JSON error responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        headers: { get: () => "text/plain" },
        json: async () => {
          throw new Error("not json");
        },
        text: async () => "boom"
      } as unknown as Response)
    );

    let caught: unknown;
    try {
      await postJSON("/api/whatever", {});
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(HttpError);
    expect((caught as HttpError).status).toBe(500);
    expect((caught as HttpError).body).toBeUndefined();
    expect((caught as Error).message).toBe("request failed: 500 - boom");
  });
});
