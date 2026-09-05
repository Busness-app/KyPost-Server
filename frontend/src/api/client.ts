export function toErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

// HttpError carries the parsed JSON error body alongside the usual Error
// message, so a caller that needs more than the flattened `data.error` string
// (e.g. the mail-send 409's `keylessRecipients` list) can read it without a
// second round-trip. It stays a plain Error subclass — same .message shape as
// before, same `instanceof Error` — so every existing caller that only ever
// read `.message` via toErrorMessage() is unaffected.
export class HttpError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.body = body;
  }
}

// SessionExpiredError is thrown when the server rejects a request because the
// session is gone. It is not a request failure the caller can retry or report:
// a full reload is already in flight, and the only reason it surfaces at all is
// so `finally` blocks run and callers can tell an expiry apart from a real
// error.
export class SessionExpiredError extends Error {
  constructor() {
    super("session expired");
    this.name = "SessionExpiredError";
  }
}

// readCsrfToken reads the non-HttpOnly csrf_token cookie the backend sets
// alongside the session cookie at login (double-submit CSRF pattern — see
// backend's csrfCheckOK). It carries no authority on its own; it only proves
// this request originated from JS that could read our own cookies, which a
// cross-site attacker's forged form/script cannot do. Deliberately NOT exported:
// requestJSON attaches it to every non-GET, including postFormData's uploads, so
// the only reason to reach for it from outside this file was to hand-roll a
// fetch() — which is what the two multipart uploads did, and what cost them the
// 401 recovery and the structured error body. Keeping it private makes that
// contract something the module system enforces rather than something AGENTS.md
// asks for.
function readCsrfToken(): string {
  const match = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function requestResponse(path: string, init?: RequestInit): Promise<Response> {
  const method = (init?.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = { ...(init?.headers as Record<string, string> | undefined) };
  if (method !== "GET" && method !== "HEAD") {
    const csrfToken = readCsrfToken();
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
  }
  const response = await fetch(path, {
    credentials: "include",
    ...init,
    headers
  });
  if (response.status === 401 && !path.startsWith("/api/auth/")) {
    // Session cookie expired (or was revoked) mid-session on an endpoint
    // where a 401 is always unexpected — every endpoint where a 401 is an
    // expected, in-band outcome (login, password change, MFA challenge)
    // lives under /api/auth/ and is excluded above. Force a hard reload
    // rather than trying to recover in-SPA: it re-triggers the normal
    // "not authenticated" flow (see refreshAuth/App.tsx) cleanly.
    //
    // Reject rather than hang. This used to return a never-settling promise so
    // that no caller's .then ran against a session that no longer exists — but
    // it also stopped every caller's `finally` from running, which is where the
    // loading flags get cleared and the cleanup happens. That is only harmless
    // while the reload is guaranteed to win the race, and it isn't: reload can
    // be blocked, deferred by the browser's lifecycle handling, or (in tests)
    // stubbed. A distinct error type keeps the original intent available —
    // callers that must not render an expiry as a normal failure can check for
    // it — without making "the page is about to reload" the only thing keeping
    // application state consistent.
    window.location.reload();
    throw new SessionExpiredError();
  }
  if (!response.ok) {
    let detail = "";
    let body: unknown;
    try {
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        const data = await response.json() as { error?: string; message?: string };
        detail = data.error || data.message || "";
        body = data;
      } else {
        const rawText = (await response.text()).trim();
        // Gateways/CDNs (e.g. Cloudflare) sometimes substitute their own
        // branded HTML error page for certain status codes (502/504) instead
        // of passing the origin's real plain-text error through — dumping
        // that markup into the UI is useless noise, so treat it as "no
        // detail available" and fall through to the bare status message
        // below, same as an empty body.
        const looksLikeHtml = contentType.includes("text/html") || /^<(!doctype|html)/i.test(rawText);
        detail = looksLikeHtml ? "" : rawText;
      }
    } catch {
      detail = "";
    }
    const message = detail ? `request failed: ${response.status} - ${detail}` : `request failed: ${response.status}`;
    throw new HttpError(message, response.status, body);
  }
  return response;
}

async function requestJSON<T>(path: string, init?: RequestInit): Promise<T> {
 const response = await requestResponse(path, init);
 if (response.status === 204) {
    // No body to parse (e.g. DELETE endpoints that answer 204 No Content).
    // response.json() would throw on the empty body, so short-circuit here.
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

export async function getJSON<T>(path: string): Promise<T> {
  return requestJSON<T>(path);
}

export async function putJSON<T>(path: string, body: unknown): Promise<T> {
  return requestJSON<T>(path, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}

export async function postJSON<T>(path: string, body: unknown): Promise<T> {
  return requestJSON<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}

// postFormData is the multipart/form-data arm of the same client: uploads
// (contact import, contact photo) that cannot send a JSON body but need
// everything else requestJSON does — the CSRF header, credentials, the 401
// hard-reload recovery, and an HttpError carrying the backend's structured
// error body and status. Both upload paths used a bare fetch() before, so an
// expired session on them threw "Import failed: Unauthorized" at the user
// instead of re-triggering the sign-in flow, and every backend error message
// was replaced by response.statusText.
//
// Content-Type is deliberately NOT set: the browser has to add it itself,
// because only it knows the multipart boundary it generated for this FormData.
export async function postFormData<T>(path: string, formData: FormData): Promise<T> {
  return requestJSON<T>(path, { method: "POST", body: formData });
}

export async function deleteJSON<T>(path: string, body?: unknown): Promise<T> {
  return requestJSON<T>(path, {
    method: "DELETE",
    ...(body !== undefined ? { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {})
  });
}

// Capsule downloads share authentication, CSRF and error handling with JSON calls.
export async function postBlob(path: string, body: unknown): Promise<Blob> {
 const response = await requestResponse(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
 return response.blob();
}
