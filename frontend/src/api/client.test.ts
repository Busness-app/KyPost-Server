import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpError, SessionExpiredError, postFormData, postJSON } from "./client";

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

// The two upload paths (contact import, contact photo) used a bare fetch()
// before, which meant no 401 recovery and no structured error body on exactly
// the routes that carry a file and a session. These assert that going through
// the client did not cost them the one thing the bare fetch got right — the
// browser, not us, setting the multipart Content-Type and its boundary.
describe("postFormData", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    document.cookie = "csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
  });

  it("sends the CSRF header and leaves Content-Type to the browser", async () => {
    document.cookie = "csrf_token=tok-123";
    const fetchMock = vi.fn().mockResolvedValue(fakeJSONResponse(200, { imported: 2 }));
    vi.stubGlobal("fetch", fetchMock);

    const formData = new FormData();
    formData.append("file", new Blob(["BEGIN:VCARD"]), "contacts.vcf");
    await expect(postFormData("/api/contacts/import", formData)).resolves.toEqual({ imported: 2 });

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/contacts/import");
    expect(init.method).toBe("POST");
    expect(init.body).toBe(formData);
    expect(init.credentials).toBe("include");
    expect(init.headers).toEqual({ "X-CSRF-Token": "tok-123" });
  });

  it("throws an HttpError carrying the backend's error body, not response.statusText", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(fakeJSONResponse(413, { error: "file too large" })));

    let caught: unknown;
    try {
      await postFormData("/api/contacts/import", new FormData());
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(HttpError);
    expect((caught as HttpError).status).toBe(413);
    expect((caught as Error).message).toBe("request failed: 413 - file too large");
  });

  it("hands an expired session to the central 401 recovery and still settles for the caller", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(fakeJSONResponse(401, { error: "unauthorized" })));
    const reload = vi.fn();
    vi.stubGlobal("location", { ...window.location, reload });

    // The reload is the recovery, but it is not allowed to be the only thing
    // that unwinds the caller: a promise that never settles leaves every
    // caller's `finally` — loading flags, cleanup — permanently pending if the
    // reload is blocked or deferred. Here reload is stubbed, which is exactly
    // that case.
    let settled = false;
    let caught: unknown;
    try {
      await postFormData("/api/contacts/import", new FormData());
    } catch (e) {
      caught = e;
    } finally {
      settled = true;
    }

    expect(reload).toHaveBeenCalled();
    expect(settled).toBe(true);
    expect(caught).toBeInstanceOf(SessionExpiredError);
  });
});
