import { useEffect, useMemo, useState } from "react";
import { getJSON, postJSON, toErrorMessage } from "../../api/client";
import { fetchHealth } from "../../pages/health/fetchHealth";

export type SystemHealthProps = {
  /**
   * Renders the admin-only controls: "Poll mail now" and the client address.
   * Presentational only — the server enforces both regardless of what this says.
   */
  full?: boolean;
  /**
   * The panel's own title. It lives inside `.health-head`, which is a
   * space-between flex row, so it cannot simply be dropped: without it the
   * controls collapse to the left.
   */
  heading?: string;
};

// These types are the contract with /api/health and /api/status, and both
// endpoints send more than this page used to read. The dropped fields were not
// spare: `classifierFailing` and `nativePushFailing` are deliberately kept OUT
// of the `healthy` flag (which drives container restarts — restarting fixes
// neither), so this page is the only place they were ever meant to surface.
// While they went unread, mobile push could be dead indefinitely under a
// banner reading "System Healthy".
type Health = {
  healthy: boolean;
  unhealthyForSeconds: number;
  lastCheckUtc: string;
  failureReason: string[];
  aiCreditsExhausted?: boolean;
  aiCreditsExhaustedAt?: string;
  // Labels are not being applied right now, whatever the cause: the model
  // missing or still downloading, Ollama unreachable, an upstream error,
  // credits exhausted. Carries no error text by design — a classify failure
  // can quote an upstream response body.
  classifierFailing?: boolean;
  classifierFailingAt?: string;
  // Native (mobile/FCM/APNs) push relay. `false` covers both "off" and
  // "working"; it goes true only when a CONFIGURED relay actually fails.
  nativePushFailing?: boolean;
  nativePushFailingAt?: string;
  nativePushLastError?: string;
  nativePushLastSuccessUtc?: string;
  // The poll daemon runs as its own process under supervisord, with its own
  // in-memory health that /api/health could not see — so every field above that
  // only the daemon observes read as `false`, which renders as "fine". It now
  // publishes them to shared state on a heartbeat; daemonStale means that
  // heartbeat stopped, and the fields above are last known rather than current.
  daemonHeartbeatUtc?: string;
  daemonStale?: boolean;
};

type RunStatus = {
  scanIntervalSeconds: number;
  checkpoint: string;
  emailsProcessedLastHour?: number;
  // Distinguishes "the checkpoint read failed" from "never polled". The
  // backend sets this precisely because an empty checkpoint renders as the
  // latter, and the two want opposite responses from an operator.
  checkpointReadFailed?: boolean;
  // Classifier admission depth. Without it, the only symptom of a backlog the
  // model cannot drain is mail that quietly classifies late — the poll tick
  // reports success either way.
  classifier?: { inFlight: number; queued: number; concurrency: number };
  // How this server resolved the caller's address. Nothing logs client IPs
  // (deliberately), so this is the only way to confirm a reverse proxy is
  // configured such that per-IP lockouts key off real callers: a loopback or
  // bridge address here means every user shares one lockout bucket.
  clientIp?: string;
  proxyHeadersTrusted?: boolean;
  serverTimeUtc?: string;
  // The last COMPLETED poll tick. Absent means none has finished since this
  // account's state was created. A tick that aborts early leaves the previous
  // record in place, so a growing age is the outage signal — which is why this
  // is the only thing that can distinguish a working poller from a stopped one
  // (the healthy flag tracks IMAP reachability, which a stopped poller
  // satisfies).
  lastPollTick?: {
    atUtc: string;
    fetched: number;
    processed: number;
    skippedSeen: number;
    failed: number;
    deferred: number;
    rateLimited: boolean;
    checkpointHeld: boolean;
  };
  // Set while the poll checkpoint is deliberately not advancing because
  // messages are waiting to be retried. Sticky from the FIRST held tick.
  checkpointHeldSinceUtc?: string;
  failedLast24h?: number;
  stateDiskBytes?: number;
  lastCleanupUtc?: string;
};

function formatDuration(totalSeconds: number): string {
  if (totalSeconds <= 0) return "0s";
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const parts: string[] = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes) parts.push(`${minutes}m`);
  if (seconds || parts.length === 0) parts.push(`${seconds}s`);
  return parts.join(" ");
}

/** Local-time rendering that falls back to the raw value rather than "Invalid Date". */
function formatTimestamp(value: string | undefined): string {
  if (!value) return "";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

/**
 * clockSkew reports how far the browser is from the server, in seconds.
 *
 * Every other timestamp on this page is rendered in the browser's local time
 * from a server-supplied instant, so a skewed clock silently misreads all of
 * them — "last checked" can look minutes stale on a perfectly healthy server.
 * Only surfaced past a threshold that ordinary request latency cannot explain.
 */
function clockSkewSeconds(serverTimeUtc: string | undefined): number | null {
  if (!serverTimeUtc) return null;
  const server = new Date(serverTimeUtc).getTime();
  if (Number.isNaN(server)) return null;
  return Math.round((Date.now() - server) / 1000);
}

const CLOCK_SKEW_WARN_SECONDS = 120;

/**
 * secondsBetween measures against the SERVER's clock, not the browser's.
 *
 * "Last poll 40 minutes ago" has to stay true on a machine whose clock is off,
 * because a stale poll and a skewed clock look identical when the browser is
 * the reference — and they need opposite responses.
 */
function secondsBetween(fromUtc: string | undefined, serverTimeUtc: string | undefined): number | null {
  if (!fromUtc || !serverTimeUtc) return null;
  const from = new Date(fromUtc).getTime();
  const server = new Date(serverTimeUtc).getTime();
  if (Number.isNaN(from) || Number.isNaN(server)) return null;
  return Math.max(0, Math.round((server - from) / 1000));
}

/**
 * pollIsStale allows a generous multiple of the configured interval before
 * complaining: one skipped tick is normal (a slow IMAP fetch, a long
 * classification), and a dashboard that cries wolf gets ignored.
 */
function pollIsStale(ageSeconds: number | null, scanIntervalSeconds: number | undefined): boolean {
  if (ageSeconds == null) return false;
  const interval = scanIntervalSeconds && scanIntervalSeconds > 0 ? scanIntervalSeconds : 90;
  return ageSeconds > Math.max(interval * 3, 300);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

export function SystemHealth({ full = false, heading = "Health Dashboard" }: SystemHealthProps = {}) {
  const [health, setHealth] = useState<Health | null>(null);
  const [runStatus, setRunStatus] = useState<RunStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [refreshEvery, setRefreshEvery] = useState(10);
  const [polling, setPolling] = useState(false);
  const [pollStatus, setPollStatus] = useState("");

  async function refreshHealth() {
    setLoading(true);
    try {
      const [nextHealth, nextStatus] = await Promise.all([
        fetchHealth<Health>(),
        getJSON<RunStatus>("/api/status"),
      ]);
      setHealth(nextHealth);
      setRunStatus(nextStatus);
    } catch {
      setHealth(null);
      setRunStatus(null);
    } finally {
      setLoading(false);
    }
  }

  async function pollMailNow() {
    setPolling(true);
    setPollStatus("");
    try {
      await postJSON("/api/admin/mail/poll-now", {});
      setPollStatus("Mail poll triggered.");
      await refreshHealth();
    } catch (error: unknown) {
      setPollStatus(`Failed to trigger mail poll: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setPolling(false);
    }
  }

  useEffect(() => {
    refreshHealth();
  }, []);

  useEffect(() => {
    if (refreshEvery <= 0) return;
    const id = setInterval(refreshHealth, refreshEvery * 1000);
    return () => clearInterval(id);
  }, [refreshEvery]);

  const severityClass = health?.healthy ? "health-ok" : "health-bad";
  const lastChecked = useMemo(
    () => formatTimestamp(health?.lastCheckUtc) || "-",
    [health?.lastCheckUtc]
  );

  const creditsExhaustedAt = useMemo(
    () => formatTimestamp(health?.aiCreditsExhaustedAt),
    [health?.aiCreditsExhaustedAt]
  );

  const daemonHeartbeat = useMemo(
    () => formatTimestamp(health?.daemonHeartbeatUtc),
    [health?.daemonHeartbeatUtc]
  );

  const classifierFailingAt = useMemo(
    () => formatTimestamp(health?.classifierFailingAt),
    [health?.classifierFailingAt]
  );

  const nativePushFailingAt = useMemo(
    () => formatTimestamp(health?.nativePushFailingAt),
    [health?.nativePushFailingAt]
  );

  const nativePushLastSuccess = useMemo(
    () => formatTimestamp(health?.nativePushLastSuccessUtc),
    [health?.nativePushLastSuccessUtc]
  );

  const skewSeconds = useMemo(
    () => clockSkewSeconds(runStatus?.serverTimeUtc),
    [runStatus?.serverTimeUtc]
  );
  const clockSkewed = skewSeconds != null && Math.abs(skewSeconds) > CLOCK_SKEW_WARN_SECONDS;

  const pollAgeSeconds = useMemo(
    () => secondsBetween(runStatus?.lastPollTick?.atUtc, runStatus?.serverTimeUtc),
    [runStatus?.lastPollTick?.atUtc, runStatus?.serverTimeUtc]
  );
  const pollStale = pollIsStale(pollAgeSeconds, runStatus?.scanIntervalSeconds);

  const checkpointHeldSeconds = useMemo(
    () => secondsBetween(runStatus?.checkpointHeldSinceUtc, runStatus?.serverTimeUtc),
    [runStatus?.checkpointHeldSinceUtc, runStatus?.serverTimeUtc]
  );

  return (
    <>
      <div className="health-head">
        <h2>{heading}</h2>
        <div className="health-controls">
          <label>
            <span>Auto-refresh</span>
            <select value={refreshEvery} onChange={(e) => setRefreshEvery(Number(e.target.value))}>
              <option value={0}>Off</option>
              <option value={5}>5s</option>
              <option value={10}>10s</option>
              <option value={30}>30s</option>
            </select>
          </label>
          <button type="button" onClick={refreshHealth} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
          {full && (
            <button type="button" onClick={() => void pollMailNow()} disabled={polling}>
              {polling ? "Polling..." : "Poll mail now"}
            </button>
          )}
        </div>
      </div>
      {pollStatus && <p className="security-muted">{pollStatus}</p>}

      {!health ? (
        <p>Waiting for health data.</p>
      ) : (
        <>
          <div className={`health-banner ${severityClass}`}>
            <strong>{health.healthy ? "System Healthy" : "System Unhealthy"}</strong>
            <span>Last checked: {lastChecked}</span>
          </div>

          {/*
            Placed above every subsystem banner on purpose: when the daemon has
            stopped reporting, everything below it is last-known rather than
            current, and reading "Classification: Working" off a dead reporter is
            the exact mistake this whole signal exists to prevent.
          */}
          {health.daemonStale && (
            <div className="health-banner health-bad" style={{ marginTop: 10 }}>
              <strong>Mail daemon not reporting</strong>
              <span>
                The poll daemon has stopped publishing its health
                {daemonHeartbeat ? ` (last heartbeat ${daemonHeartbeat})` : ""}, so no mail is
                being fetched, classified or pushed. Every subsystem shown below is the last
                thing it reported, not its current state. Check the daemon log; supervisord
                restarts the process automatically if it exited.
              </span>
            </div>
          )}

          {health.aiCreditsExhausted && (
            <div className="health-banner health-bad" style={{ marginTop: 10 }}>
              <strong>AI credits exhausted</strong>
              <span>
                Email classification is paused until AI credits reset
                {creditsExhaustedAt ? ` (since ${creditsExhaustedAt})` : ""}. It resumes automatically
                on the next successful classification.
              </span>
            </div>
          )}

          {/*
            Both banners below report subsystems that are deliberately excluded
            from the overall healthy flag, because flipping it restarts the
            container and a restart fixes neither. That makes this page the only
            place they surface at all — hence banners rather than grid cards.
            The credits banner above is kept separate and shown alongside: it is
            the more specific diagnosis for one cause of a failing classifier.
          */}
          {health.classifierFailing && (
            <div className="health-banner health-bad" style={{ marginTop: 10 }}>
              <strong>Classification failing</strong>
              <span>
                Labels are not being applied to incoming mail
                {classifierFailingAt ? ` (since ${classifierFailingAt})` : ""}. Mail is still
                delivered and readable. Common causes: the model is missing or still downloading,
                Ollama is unreachable, or the classifier returned an error — check the classifier
                logs. Clears automatically on the next successful classification.
              </span>
            </div>
          )}

          {health.nativePushFailing && (
            <div className="health-banner health-bad" style={{ marginTop: 10 }}>
              <strong>Mobile push failing</strong>
              <span>
                The native push relay is rejecting or failing sends
                {nativePushFailingAt ? ` (since ${nativePushFailingAt})` : ""}, so paired mobile
                devices are not receiving notifications. Browser notifications are unaffected.
                {nativePushLastSuccess ? ` Last successful send: ${nativePushLastSuccess}.` : ""}
                {health.nativePushLastError ? ` Last error: ${health.nativePushLastError}` : ""}
              </span>
            </div>
          )}

          {pollStale && (
            <div className="health-banner health-bad" style={{ marginTop: 10 }}>
              <strong>Mail polling has stalled</strong>
              <span>
                The last completed poll was {formatDuration(pollAgeSeconds ?? 0)} ago, well past
                the {runStatus?.scanIntervalSeconds ?? 90}s scan interval. The overall status
                above only reports that IMAP is reachable, which a stopped poller still
                satisfies. Check the server log for a poll tick that is failing before it
                finishes.
              </span>
            </div>
          )}

          {runStatus?.checkpointHeldSinceUtc && (
            <div className="health-banner health-bad" style={{ marginTop: 10 }}>
              <strong>Messages waiting to be retried</strong>
              <span>
                The poll checkpoint has been held back for{" "}
                {formatDuration(checkpointHeldSeconds ?? 0)} so
                {runStatus.lastPollTick?.deferred
                  ? ` ${runStatus.lastPollTick.deferred} message(s)`
                  : " deferred messages"}{" "}
                are not skipped. This is the intended response to a transient failure — mail is
                not lost, and each held message is retried on the next tick — but it does not
                clear on its own.{" "}
                {runStatus.lastPollTick?.rateLimited
                  ? "The per-user rate limit was reached this tick, so raising it (or waiting) will clear the backlog."
                  : "If it persists, classification is failing; see the classifier status above."}
              </span>
            </div>
          )}

          {clockSkewed && (
            <div className="health-banner health-bad" style={{ marginTop: 10 }}>
              <strong>Clock skew detected</strong>
              <span>
                This browser is {formatDuration(Math.abs(skewSeconds ?? 0))}{" "}
                {(skewSeconds ?? 0) > 0 ? "ahead of" : "behind"} the server. Every time on this
                page is rendered in local time from a server timestamp, so they may read as
                stale or in the future.
              </span>
            </div>
          )}

          <div className="health-grid">
            <article className="health-card">
              <h4>Current Status</h4>
              <p className="health-value">{health.healthy ? "Healthy" : "Unhealthy"}</p>
            </article>
            <article className="health-card">
              <h4>Unhealthy Duration</h4>
              <p className="health-value">{formatDuration(health.unhealthyForSeconds ?? 0)}</p>
            </article>
            <article className="health-card">
              <h4>Failure Count</h4>
              <p className="health-value">{health.failureReason?.length ?? 0}</p>
            </article>
            <article className="health-card">
              <h4>Scan Interval</h4>
              <p className="health-value">{runStatus?.scanIntervalSeconds != null ? `${runStatus.scanIntervalSeconds}s` : "-"}</p>
            </article>
            <article className="health-card">
              <h4>Emails Processed Last Hour</h4>
              <p className="health-value">{runStatus?.emailsProcessedLastHour ?? 0}</p>
            </article>
            <article className="health-card">
              <h4>Checkpoint</h4>
              {/*
                An empty checkpoint is ambiguous — "never polled" and "the read
                failed" render identically — so the server sends a flag saying
                which, and the two want opposite responses.
              */}
              <p className="health-value" style={{ fontSize: "0.95rem", fontWeight: 600 }}>
                {runStatus?.checkpointReadFailed
                  ? "Read failed"
                  : runStatus?.checkpoint
                    ? runStatus.checkpoint
                    : runStatus
                      ? "Never polled"
                      : "-"}
              </p>
              {runStatus?.checkpointReadFailed && (
                <p className="security-muted" style={{ margin: "6px 0 0" }}>
                  Could not read the poll checkpoint. This is not the same as never having
                  polled — see the server log.
                </p>
              )}
            </article>
            <article className="health-card">
              <h4>Classification</h4>
              {/*
                "Unknown" rather than "Working" when the daemon has stopped
                reporting. The daemon is the only process that classifies
                anything, so with no heartbeat this field is a stale reading, and
                rendering a stale false as "Working" is what let a dead
                classifier sit behind a green page.
              */}
              <p className="health-value">
                {health.daemonStale ? "Unknown" : health.classifierFailing ? "Failing" : "Working"}
              </p>
            </article>
            <article className="health-card">
              <h4>Classifier Queue</h4>
              {/*
                Admission depth: a queue that stays at the cap while in-flight
                sits at concurrency is a backlog the model cannot drain, which
                otherwise shows up only as mail that classifies late.
              */}
              <p className="health-value">
                {runStatus?.classifier
                  ? `${runStatus.classifier.queued} queued`
                  : "-"}
              </p>
              {runStatus?.classifier && (
                <p className="security-muted" style={{ margin: "6px 0 0" }}>
                  {runStatus.classifier.inFlight} in flight of {runStatus.classifier.concurrency}{" "}
                  concurrent
                </p>
              )}
            </article>
            <article className="health-card">
              <h4>Last Poll</h4>
              {/*
                Age is measured against serverTimeUtc, not the browser clock, so
                a skewed clock shows up as its own warning rather than as a
                phantom stalled poller.
              */}
              <p className="health-value">
                {runStatus?.lastPollTick
                  ? pollAgeSeconds != null
                    ? `${formatDuration(pollAgeSeconds)} ago`
                    : formatTimestamp(runStatus.lastPollTick.atUtc)
                  : "Never"}
              </p>
              {runStatus?.lastPollTick ? (
                <p className="security-muted" style={{ margin: "6px 0 0" }}>
                  {runStatus.lastPollTick.fetched} fetched, {runStatus.lastPollTick.processed}{" "}
                  processed, {runStatus.lastPollTick.failed} failed
                  {runStatus.lastPollTick.deferred > 0
                    ? `, ${runStatus.lastPollTick.deferred} deferred`
                    : ""}
                </p>
              ) : (
                <p className="security-muted" style={{ margin: "6px 0 0" }}>
                  No poll has completed yet for this account.
                </p>
              )}
            </article>
            <article className="health-card">
              <h4>Failed (24h)</h4>
              {/*
                One row per affected message, not per retry attempt — a message
                deferred through a long outage is counted once.
              */}
              <p className="health-value">{runStatus?.failedLast24h ?? 0}</p>
              <p className="security-muted" style={{ margin: "6px 0 0" }}>
                Messages, not retry attempts.
              </p>
            </article>
            <article className="health-card">
              <h4>State Storage</h4>
              <p className="health-value">
                {runStatus?.stateDiskBytes != null ? formatBytes(runStatus.stateDiskBytes) : "-"}
              </p>
              <p className="security-muted" style={{ margin: "6px 0 0" }}>
                {runStatus?.lastCleanupUtc
                  ? `Last trimmed ${formatTimestamp(runStatus.lastCleanupUtc)}`
                  : "Not yet trimmed; history is kept 30 days."}
              </p>
            </article>
            <article className="health-card">
              <h4>Mobile Push</h4>
              {/*
                "false" covers both "no relay configured" and "working", so this
                reports the failing state plainly and leans on the last-success
                timestamp to tell the other two apart.
              */}
              <p className="health-value">{health.nativePushFailing ? "Failing" : "OK"}</p>
              {nativePushLastSuccess && (
                <p className="security-muted" style={{ margin: "6px 0 0" }}>
                  Last success: {nativePushLastSuccess}
                </p>
              )}
            </article>
          </div>

          {full && runStatus?.clientIp && (
            <div className="health-card" style={{ marginTop: 14 }}>
              <h4>Client Address</h4>
              {/*
                Admin-only: it echoes the caller's own address, and it exists
                because nothing logs client IPs (deliberately), leaving an
                operator no other way to confirm a reverse proxy is wired up so
                that per-IP lockouts key off real callers. A loopback or bridge
                address with headers untrusted means every user shares one
                lockout bucket — 50 failures from anyone locks out sign-in for
                everyone.
              */}
              <p className="health-value" style={{ fontSize: "0.95rem", fontWeight: 600 }}>
                {runStatus.clientIp}
              </p>
              <p className="security-muted" style={{ margin: "6px 0 0" }}>
                {runStatus.proxyHeadersTrusted
                  ? "Forwarded headers are trusted; this should be your real public address."
                  : "Forwarded headers are NOT trusted. If this server sits behind a reverse proxy and this is not your real address, every user shares one rate-limit and lockout bucket."}
              </p>
            </div>
          )}

          <div className="health-card" style={{ marginTop: 14 }}>
            <h4>Failure Reasons</h4>
            {health.failureReason && health.failureReason.length > 0 ? (
              <ul className="health-list">
                {health.failureReason.map((reason, idx) => (
                  <li key={`${idx}-${reason}`}>{reason}</li>
                ))}
              </ul>
            ) : (
              <p>No active failure reasons.</p>
            )}
          </div>
        </>
      )}
    </>
  );
}
