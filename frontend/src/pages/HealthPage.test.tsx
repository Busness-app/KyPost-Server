import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { AuthContext, type AuthState } from "../auth";
import { HealthPage } from "./HealthPage";

// The bug these cover is not in either endpoint — /api/health and /api/status
// have always computed and sent these fields — but in the page's TypeScript
// types, which were narrower than the JSON and silently dropped the rest.
// `classifierFailing` and `nativePushFailing` are deliberately excluded from
// the overall `healthy` flag (it drives container restarts, and a restart fixes
// neither), so this page is the ONLY place they were ever meant to surface.
// While they went unread, mobile push could be dead indefinitely under a banner
// reading "System Healthy" — which is exactly what the first test asserts
// against.

const getJSON = vi.fn();
const postJSON = vi.fn();

vi.mock("../api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  postJSON: (url: string, body: unknown) => postJSON(url, body),
  toErrorMessage: (_e: unknown, fallback: string) => fallback
}));

// Testing Library only registers auto-cleanup when vitest runs with globals
// enabled, which this project does not. See ReadPage.test.tsx.
afterEach(cleanup);

const healthyBase = {
  healthy: true,
  unhealthyForSeconds: 0,
  lastCheckUtc: "2026-08-01T12:00:00Z",
  failureReason: []
};

const statusBase = {
  scanIntervalSeconds: 90,
  checkpoint: "1420",
  emailsProcessedLastHour: 7
};

function mockEndpoints(health: object = {}, status: object = {}) {
  getJSON.mockImplementation((url: string) => {
    if (url === "/api/health") return Promise.resolve({ ...healthyBase, ...health });
    if (url === "/api/status") return Promise.resolve({ ...statusBase, ...status });
    return Promise.reject(new Error(`unexpected GET ${url}`));
  });
}

function renderPage(role: AuthState["role"] = "admin") {
  return render(
    <AuthContext.Provider value={{ authenticated: true, userId: "u1", role }}>
      <HealthPage />
    </AuthContext.Provider>
  );
}

beforeEach(() => {
  getJSON.mockReset();
  postJSON.mockReset();
  vi.useRealTimers();
});

describe("subsystem failures excluded from the healthy flag", () => {
  it("surfaces a failing classifier even while the system reports healthy", async () => {
    mockEndpoints({
      healthy: true,
      classifierFailing: true,
      classifierFailingAt: "2026-08-01T09:30:00Z"
    });
    renderPage();

    // The regression in one line: healthy and failing at the same time, which
    // is a legitimate state, and the page has to say both.
    await screen.findByText("Classification failing");
    expect(screen.getByText("System Healthy")).toBeTruthy();
  });

  it("surfaces a failing mobile push relay, with its last error and last success", async () => {
    mockEndpoints({
      nativePushFailing: true,
      nativePushFailingAt: "2026-08-01T08:00:00Z",
      nativePushLastError: "relay returned 401",
      nativePushLastSuccessUtc: "2026-07-31T23:00:00Z"
    });
    renderPage();

    await screen.findByText("Mobile push failing");
    expect(screen.getByText(/relay returned 401/)).toBeTruthy();
  });

  it("says nothing about either subsystem when both are fine", async () => {
    mockEndpoints();
    renderPage();

    await screen.findByText("System Healthy");
    expect(screen.queryByText("Classification failing")).toBeNull();
    expect(screen.queryByText("Mobile push failing")).toBeNull();
    // "off" and "working" both report false, so the card must not cry wolf.
    expect(screen.getByText("OK")).toBeTruthy();
  });
});

describe("checkpoint", () => {
  // The server sends checkpointReadFailed precisely because an empty checkpoint
  // renders identically to "never polled", and the two want opposite responses
  // from an operator.
  it("distinguishes a failed read from never having polled", async () => {
    mockEndpoints({}, { checkpoint: "", checkpointReadFailed: true });
    renderPage();

    await screen.findByText("Read failed");
    expect(screen.queryByText("Never polled")).toBeNull();
  });

  it("reports never polled when the read succeeded and there is no checkpoint", async () => {
    mockEndpoints({}, { checkpoint: "", checkpointReadFailed: false });
    renderPage();

    await screen.findByText("Never polled");
    expect(screen.queryByText("Read failed")).toBeNull();
  });

  it("shows the checkpoint value when there is one", async () => {
    mockEndpoints();
    renderPage();

    await screen.findByText("1420");
  });
});

describe("classifier queue depth", () => {
  it("reports admission depth so a backlog is visible before mail classifies late", async () => {
    mockEndpoints({}, { classifier: { inFlight: 2, queued: 14, concurrency: 2 } });
    renderPage();

    await screen.findByText("14 queued");
    expect(screen.getByText(/2 in flight of 2 concurrent/)).toBeTruthy();
  });

  it("renders a placeholder when the server did not report a classifier", async () => {
    mockEndpoints();
    const { container } = renderPage();

    await screen.findByText("System Healthy");
    expect(container.textContent).toContain("Classifier Queue");
    expect(screen.queryByText(/in flight of/)).toBeNull();
  });
});

describe("client address", () => {
  it("warns an admin when forwarded headers are not trusted", async () => {
    mockEndpoints({}, { clientIp: "172.18.0.1", proxyHeadersTrusted: false });
    renderPage("admin");

    await screen.findByText("172.18.0.1");
    // The consequence, not just the value: one shared lockout bucket.
    expect(screen.getByText(/every user shares one rate-limit and lockout bucket/)).toBeTruthy();
  });

  it("confirms a correct proxy setup", async () => {
    mockEndpoints({}, { clientIp: "203.0.113.7", proxyHeadersTrusted: true });
    renderPage("admin");

    await screen.findByText("203.0.113.7");
    expect(screen.getByText(/should be your real public address/)).toBeTruthy();
  });

  it("is not shown to non-admins", async () => {
    mockEndpoints({}, { clientIp: "203.0.113.7", proxyHeadersTrusted: true });
    renderPage("user");

    await screen.findByText("System Healthy");
    expect(screen.queryByText("203.0.113.7")).toBeNull();
  });
});

describe("clock skew", () => {
  it("warns when the browser and server disagree by more than the threshold", async () => {
    // Server timestamp 10 minutes in the past relative to this browser.
    const serverTimeUtc = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    mockEndpoints({}, { serverTimeUtc });
    renderPage();

    await screen.findByText("Clock skew detected");
    expect(screen.getByText(/ahead of the server/)).toBeTruthy();
  });

  it("stays quiet for ordinary request latency", async () => {
    const serverTimeUtc = new Date(Date.now() - 3 * 1000).toISOString();
    mockEndpoints({}, { serverTimeUtc });
    renderPage();

    await screen.findByText("System Healthy");
    expect(screen.queryByText("Clock skew detected")).toBeNull();
  });
});

describe("poll freshness", () => {
  // The gap this closes: `healthy` tracks IMAP reachability, which a daemon
  // that has stopped ticking altogether still satisfies. Before this there was
  // no way to tell a working poller from a stopped one.
  function statusWithPoll(ageSeconds: number, extra: object = {}) {
    const serverTimeUtc = "2026-08-01T12:00:00Z";
    const atUtc = new Date(Date.parse(serverTimeUtc) - ageSeconds * 1000).toISOString();
    return {
      serverTimeUtc,
      lastPollTick: {
        atUtc,
        fetched: 12,
        processed: 11,
        skippedSeen: 3,
        failed: 1,
        deferred: 0,
        rateLimited: false,
        checkpointHeld: false,
        ...extra
      }
    };
  }

  it("warns when the last completed poll is far past the scan interval", async () => {
    mockEndpoints({}, statusWithPoll(40 * 60));
    renderPage();

    await screen.findByText("Mail polling has stalled");
    // Healthy and stalled simultaneously is the exact blind spot.
    expect(screen.getByText("System Healthy")).toBeTruthy();
  });

  it("stays quiet for a poll within the interval", async () => {
    mockEndpoints({}, statusWithPoll(30));
    renderPage();

    await screen.findByText("System Healthy");
    expect(screen.queryByText("Mail polling has stalled")).toBeNull();
  });

  it("tolerates a single skipped tick without crying wolf", async () => {
    // Two intervals late on a 90s scan: normal for a slow fetch.
    mockEndpoints({}, statusWithPoll(180));
    renderPage();

    await screen.findByText("System Healthy");
    expect(screen.queryByText("Mail polling has stalled")).toBeNull();
  });

  it("shows the tick counts, not just the age", async () => {
    mockEndpoints({}, statusWithPoll(45));
    renderPage();

    await screen.findByText("45s ago");
    expect(screen.getByText(/12 fetched, 11 processed, 1 failed/)).toBeTruthy();
  });

  it("reports never when no tick has completed", async () => {
    mockEndpoints({}, { serverTimeUtc: "2026-08-01T12:00:00Z" });
    renderPage();

    await screen.findByText("Never");
    expect(screen.getByText(/No poll has completed yet/)).toBeTruthy();
  });

  it("measures age against the server clock, not the browser's", async () => {
    // Browser is an hour off. The poll is 45s old by the server's own
    // reckoning, and must not be reported as an hour stale.
    const serverTimeUtc = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const atUtc = new Date(Date.parse(serverTimeUtc) - 45 * 1000).toISOString();
    mockEndpoints(
      {},
      {
        serverTimeUtc,
        lastPollTick: {
          atUtc,
          fetched: 1,
          processed: 1,
          skippedSeen: 0,
          failed: 0,
          deferred: 0,
          rateLimited: false,
          checkpointHeld: false
        }
      }
    );
    renderPage();

    await screen.findByText("45s ago");
    expect(screen.queryByText("Mail polling has stalled")).toBeNull();
    // The skew itself is still reported, as its own distinct problem.
    expect(screen.getByText("Clock skew detected")).toBeTruthy();
  });
});

describe("retry backlog", () => {
  // Makes the deferred-message state visible. The poller holds the checkpoint
  // below messages it means to retry; without this the only evidence was a log
  // line, and a checkpoint that stopped moving looked broken rather than
  // deliberate.
  it("reports how long the checkpoint has been held and why", async () => {
    mockEndpoints(
      {},
      {
        serverTimeUtc: "2026-08-01T12:00:00Z",
        checkpointHeldSinceUtc: "2026-08-01T11:30:00Z",
        lastPollTick: {
          atUtc: "2026-08-01T11:59:30Z",
          fetched: 5,
          processed: 2,
          skippedSeen: 0,
          failed: 3,
          deferred: 3,
          rateLimited: false,
          checkpointHeld: true
        }
      }
    );
    renderPage();

    await screen.findByText("Messages waiting to be retried");
    expect(screen.getByText(/30m/)).toBeTruthy();
    expect(screen.getByText(/3 message\(s\)/)).toBeTruthy();
    // Says mail is not lost — the deferral is the correct behaviour.
    expect(screen.getByText(/mail is\s+not lost/)).toBeTruthy();
  });

  it("points at the rate limit when that is what deferred the messages", async () => {
    mockEndpoints(
      {},
      {
        serverTimeUtc: "2026-08-01T12:00:00Z",
        checkpointHeldSinceUtc: "2026-08-01T11:55:00Z",
        lastPollTick: {
          atUtc: "2026-08-01T11:59:30Z",
          fetched: 40,
          processed: 20,
          skippedSeen: 0,
          failed: 0,
          deferred: 20,
          rateLimited: true,
          checkpointHeld: true
        }
      }
    );
    renderPage();

    await screen.findByText("Messages waiting to be retried");
    expect(screen.getByText(/per-user rate limit/)).toBeTruthy();
  });

  it("says nothing when the checkpoint is advancing normally", async () => {
    mockEndpoints({}, { serverTimeUtc: "2026-08-01T12:00:00Z" });
    renderPage();

    await screen.findByText("System Healthy");
    expect(screen.queryByText("Messages waiting to be retried")).toBeNull();
  });
});

describe("failures and storage", () => {
  it("counts failed messages over 24h and labels them as messages", async () => {
    mockEndpoints({}, { failedLast24h: 4 });
    renderPage();

    await screen.findByText("4");
    expect(screen.getByText(/Messages, not retry attempts/)).toBeTruthy();
  });

  it("renders state size and the last trim", async () => {
    mockEndpoints({}, { stateDiskBytes: 5 * 1024 * 1024, lastCleanupUtc: "2026-08-01T06:00:00Z" });
    renderPage();

    await screen.findByText("5.0 MiB");
    expect(screen.getByText(/Last trimmed/)).toBeTruthy();
  });

  it("explains the retention window when no trim has run", async () => {
    mockEndpoints({}, { stateDiskBytes: 4096 });
    renderPage();

    await screen.findByText("4.0 KiB");
    expect(screen.getByText(/kept 30 days/)).toBeTruthy();
  });
});

describe("existing behaviour is preserved", () => {
  it("still renders the AI-credits banner alongside a failing classifier", async () => {
    // Credits exhausted is a more specific diagnosis for one cause of a failing
    // classifier, so both banners are expected — the new one must not have
    // replaced it.
    mockEndpoints({
      aiCreditsExhausted: true,
      aiCreditsExhaustedAt: "2026-08-01T07:00:00Z",
      classifierFailing: true
    });
    renderPage();

    await screen.findByText("AI credits exhausted");
    expect(screen.getByText("Classification failing")).toBeTruthy();
  });

  it("still reports unhealthy status and failure reasons", async () => {
    mockEndpoints({
      healthy: false,
      unhealthyForSeconds: 125,
      failureReason: ["imap dial tcp: connection refused"]
    });
    renderPage();

    await screen.findByText("System Unhealthy");
    expect(screen.getByText("imap dial tcp: connection refused")).toBeTruthy();
    expect(screen.getByText("2m 5s")).toBeTruthy();
  });

  it("keeps working when the server sends only the original fields", async () => {
    // Forward compatibility in the other direction: an older server that sends
    // none of the new fields must not break the page.
    getJSON.mockImplementation((url: string) => {
      if (url === "/api/health") return Promise.resolve(healthyBase);
      if (url === "/api/status") return Promise.resolve(statusBase);
      return Promise.reject(new Error(`unexpected GET ${url}`));
    });
    renderPage();

    await waitFor(() => expect(screen.getByText("System Healthy")).toBeTruthy());
    expect(screen.getByText("1420")).toBeTruthy();
  });
});
