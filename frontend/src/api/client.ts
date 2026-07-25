export function toErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

// readCsrfToken reads the non-HttpOnly csrf_token cookie the backend sets
// alongside the session cookie at login (double-submit CSRF pattern — see
// backend's csrfCheckOK). It carries no authority on its own; it only proves
// this request originated from JS that could read our own cookies, which a
// cross-site attacker's forged form/script cannot do. Exported for the rare
// caller (multipart/form-data uploads) that can't go through
// getJSON/postJSON/putJSON/deleteJSON and must attach the header itself.
export function readCsrfToken(): string {
  const match = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function requestJSON<T>(path: string, init?: RequestInit): Promise<T> {
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
    // "not authenticated" flow (see refreshAuth/App.tsx) cleanly. Return a
    // never-resolving promise so no caller's .then/catch runs against this
    // response while the reload is in flight (reload() doesn't synchronously
    // halt JS execution in every browser).
    window.location.reload();
    return new Promise<T>(() => {});
  }
  if (!response.ok) {
    let detail = "";
    try {
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        const data = await response.json() as { error?: string; message?: string };
        detail = data.error || data.message || "";
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
    throw new Error(detail ? `request failed: ${response.status} - ${detail}` : `request failed: ${response.status}`);
  }
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

export async function deleteJSON<T>(path: string, body?: unknown): Promise<T> {
  return requestJSON<T>(path, {
    method: "DELETE",
    ...(body !== undefined ? { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {})
  });
}
