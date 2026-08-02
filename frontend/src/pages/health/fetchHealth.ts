import { getJSON, HttpError } from "../../api/client";

// /api/health answers 503 when the server is unhealthy, and its BODY is the
// health report — the thing this page exists to render.
//
// getJSON throws on any non-2xx, so the page's catch blanked itself out
// precisely when it had something to say: an unhealthy server rendered as
// "could not load health", identical to being logged out or offline. That was
// survivable while `healthy` only tracked IMAP reachability. It stopped being
// survivable when a stale poll daemon started flipping the same flag, because
// then the most important thing the page can tell you is the one thing it
// refused to display.
//
// So a 503 carrying a usable body is a successful read of bad news. Anything
// else — 401, a proxy's HTML error page, a network failure — still throws.
export async function fetchHealth<T>(path = "/api/health"): Promise<T> {
  try {
    return await getJSON<T>(path);
  } catch (error: unknown) {
    if (
      error instanceof HttpError &&
      error.status === 503 &&
      isHealthBody(error.body)
    ) {
      return error.body as T;
    }
    throw error;
  }
}

// A 503 from a reverse proxy in front of this server carries HTML, not a health
// report. `healthy` is the field that makes a body one of ours, and its value
// is necessarily false here — this only runs on a 503.
function isHealthBody(body: unknown): boolean {
  return typeof body === "object" && body !== null && "healthy" in body;
}
