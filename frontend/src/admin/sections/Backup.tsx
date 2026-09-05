import { useEffect, useState } from "react";
import { credentialFields, deriveCredential } from "../../api/auth";
import {
  deleteJSON,
  getJSON,
  postBlob,
  postJSON,
  putJSON,
  toErrorMessage,
} from "../../api/client";

type Status = {
  keyId?: string;
  threshold?: number;
  totalShares?: number;
  keyProblem?: string;
  paired: boolean;
  kyrecoveryUrl?: string;
  localDir?: string;
  intervalSec: number;
  nextRun?: string;
  excluded: string;
  allowPrivateRecovery: boolean;
  lastReceipt?: { capsule_id: string; digest: string; deposited_at: string };
  localCopies: { name: string; size_bytes: number }[];
  recent: {
    id: number;
    at: string;
    action: string;
    outcome: string;
    target: string;
    details?: string;
  }[];
};
const base = "/api/admin/backup/";

function activityError(raw: string | undefined): string | null {
  try {
    const details: unknown = JSON.parse(raw || "{}");
    return typeof details === "object" &&
      details !== null &&
      "error" in details &&
      typeof details.error === "string"
      ? details.error
      : null;
  } catch {
    return null;
  }
}

export function Backup() {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [password, setPassword] = useState("");
  const [url, setURL] = useState("");
  const [code, setCode] = useState("");
  const [key, setKey] = useState("");
  const [threshold, setThreshold] = useState(2);
  const [total, setTotal] = useState(3);
  const [minutes, setMinutes] = useState(1440);
  async function refresh() {
    const value = await getJSON<Status>(base + "status");
    setStatus(value);
    setMinutes(value.intervalSec / 60);
    return value;
  }
  useEffect(() => {
    void refresh().catch((e) =>
      setError(toErrorMessage(e, "Unable to load backup status")),
    );
  }, []);
  async function act(
    action:
      | "run"
      | "export-capsule"
      | "drill"
      | "pair-remote"
      | "pairing"
      | "pin-key"
      | "schedule",
  ) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const credential = credentialFields(await deriveCredential("", password));
      setPassword("");
      const body =
        action === "pair-remote"
          ? { ...credential, url, code }
          : action === "pin-key"
            ? { ...credential, publicKey: key, threshold, totalShares: total }
            : action === "schedule"
              ? { ...credential, intervalSec: minutes * 60 }
              : credential;
      if (action === "export-capsule") {
        const blob = await postBlob(base + action, credential);
        const href = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = href;
        a.download = "KyPost.kycap";
        a.click();
        setTimeout(() => URL.revokeObjectURL(href), 1000);
        setNotice("Sealed capsule downloaded.");
      } else if (action === "drill") {
        const result = await postJSON<{
          passed: boolean;
          checks: { name: string; passed: boolean }[];
        }>(base + action, credential);
        setNotice(
          result.passed
            ? "Restore drill passed."
            : "Restore drill failed: " +
                result.checks
                  .filter((c) => !c.passed)
                  .map((c) => c.name)
                  .join(", "),
        );
      } else if (action === "pairing") {
        const result = await deleteJSON<{ message: string }>(
          base + action,
          credential,
        );
        setNotice(result.message);
      } else if (action === "schedule") {
        await putJSON(base + action, body);
        setNotice("Backup schedule saved.");
      } else {
        const result = await postJSON<{
          warning?: string;
          result?: { local_error?: string; local_path?: string };
        }>(base + action, body);
        setNotice(
          result.warning ||
            result.result?.local_error ||
            (action === "run"
              ? "Backup completed."
              : "Recovery key pinned. Compare its fingerprint with the ceremony page."),
        );
        setCode("");
      }
      const updated = await refresh();
      if (action === "pair-remote" || action === "pin-key") {
        setNotice(
          (previous) =>
            `${previous} Fingerprint: ${updated.keyId || "Unavailable — reload to verify the key"}`,
        );
      }
    } catch (e) {
      setError(toErrorMessage(e, "Backup action failed"));
    } finally {
      setPassword("");
      setBusy(false);
    }
  }
  return (
    <div className="config-section backup-section">
      <h3>Sealed backups</h3>
      <p>Encrypted server backups, recoverable only by your custodians.</p>
      <p>IMAP mail is excluded; encrypted pickup messages are included.</p>
      {error && (
        <p className="notice notice-error" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      <div className="backup-overview" aria-label="Backup status">
        <p>
          <strong>Destination</strong>
          <br />
          {status?.paired
            ? status.kyrecoveryUrl
            : status?.localDir || "Not configured"}
        </p>
        <p>
          <strong>Last deposit</strong>
          <br />
          {status?.lastReceipt?.deposited_at || "None yet"}
        </p>
        <p>
          <strong>Schedule</strong>
          <br />
          {status?.intervalSec
            ? `Every ${status.intervalSec / 60} minutes`
            : "Off"}
        </p>
      </div>
      {status?.keyProblem && <p role="alert">{status.keyProblem}</p>}
      {!status?.keyId && (
        <p>
          Pair with KyRecovery or paste your suite recovery public key before
          backing up.
        </p>
      )}
      {status?.keyId && !status.paired && !status.localDir && (
        <p>
          No destination: pair with KyRecovery or configure KYPOST_BACKUP_DIR.
        </p>
      )}
      <fieldset className="config-card config-grid" disabled={busy}>
        <legend>Confirm each action</legend>
        <label>
          Account password{" "}
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <p>
          Enter your account password to enable actions. It is cleared after
          each action. Never enter recovery shares here.
        </p>
        <div className="config-actions">
          <button
            className="button secondary"
            disabled={
              !password ||
              !status?.keyId ||
              (!status.paired && !status.localDir)
            }
            onClick={() => void act("run")}
          >
            Back up now
          </button>
          <button
            className="button secondary"
            disabled={!password || !status?.keyId}
            onClick={() => void act("export-capsule")}
          >
            Download capsule
          </button>
        </div>
        <details className="backup-details">
          <summary>Capsule contents and restore check</summary>
          <div className="config-grid">
            <p>
              Includes configuration, deployment keys, accounts and metadata
              databases.
            </p>
            <p>{status?.excluded}</p>
            <p>
              A drill uses a disposable key. Test your real custodian cards
              separately with an offline restore.
            </p>
            <button
              className="button secondary"
              disabled={!password}
              onClick={() => void act("drill")}
            >
              Run restore drill
            </button>
          </div>
        </details>
        <details className="backup-details">
          <summary>Schedule</summary>
          <div className="config-grid">
            {status?.intervalSec ? (
              <p>Next run: {status.nextRun || "Pending"}</p>
            ) : (
              <p>Automatic backups are off.</p>
            )}
            <label>
              Interval in minutes (0 turns it off; 15–527040 otherwise)
              <input
                type="number"
                min={0}
                max={527040}
                value={minutes}
                onChange={(e) => setMinutes(Number(e.target.value))}
              />
            </label>
            <button
              className="button secondary"
              disabled={
                !password ||
                !Number.isInteger(minutes) ||
                (minutes !== 0 && minutes < 15) ||
                minutes > 527040
              }
              onClick={() => void act("schedule")}
            >
              Save schedule
            </button>
          </div>
        </details>
        <details
          className="backup-details"
          key={String(status?.paired)}
          open={status !== null && !status.paired && !status.keyId}
        >
          <summary>Recovery setup and key</summary>
          <div className="config-grid">
            <p style={{ overflowWrap: "anywhere" }}>
              Recovery key: {status?.keyId || "No key pinned"}
            </p>
            {status?.keyId && (
              <p>
                {status.threshold} of {status.totalShares} custodians
              </p>
            )}
            <p>
              Local copies: {status?.localCopies.length ?? 0} ·{" "}
              {status?.localDir || "Not configured"}
            </p>
            <h4>Pair with KyRecovery</h4>
            <p>
              Use HTTPS and compare the pinned fingerprint out of band, or pin
              the key below before pairing. HTTPS protects the pairing key,
              token and receipts.
            </p>
            {status?.allowPrivateRecovery && (
              <p>Private network destinations are enabled by the operator.</p>
            )}
            <label>
              KyRecovery URL{" "}
              <input
                type="url"
                value={url}
                onChange={(e) => setURL(e.target.value)}
                placeholder="https://recovery.example.com"
              />
            </label>
            <label>
              Six-digit pairing code{" "}
              <input
                inputMode="numeric"
                autoComplete="off"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </label>
            <button
              className="button secondary"
              disabled={!password || !url || !/^\d{6}$/.test(code)}
              onClick={() => void act("pair-remote")}
            >
              Pair
            </button>
            <button
              className="button secondary"
              disabled={!password}
              onClick={() => void act("pairing")}
            >
              Unpair
            </button>
            <p>
              Unpair keeps the key pin, receipts and local copies. A KyRecovery
              admin must separately revoke the token.
            </p>
            <details className="backup-details">
              <summary>Pin the suite key by hand</summary>
              <div className="config-grid">
                <label>
                  Recovery public key (base64)
                  <textarea
                    value={key}
                    onChange={(e) => setKey(e.target.value)}
                  />
                </label>
                <label>
                  Required custodians
                  <input
                    type="number"
                    min={2}
                    max={255}
                    value={threshold}
                    onChange={(e) => setThreshold(Number(e.target.value))}
                  />
                </label>
                <label>
                  Total custodians
                  <input
                    type="number"
                    min={threshold}
                    max={255}
                    value={total}
                    onChange={(e) => setTotal(Number(e.target.value))}
                  />
                </label>
                <button
                  className="button secondary"
                  disabled={!password || !key}
                  onClick={() => void act("pin-key")}
                >
                  Pin key
                </button>
              </div>
            </details>
          </div>
        </details>
      </fieldset>
      {busy && (
        <p role="status">Working. A backup upload can take up to 16 minutes.</p>
      )}
      <details className="backup-details">
        <summary>Recent backup activity</summary>
        <ul>
          {status?.recent.map((row) => (
            <li key={row.id}>
              {row.at} — {row.action}: {row.outcome} {row.target}
              {activityError(row.details) && (
                <p>{activityError(row.details)}</p>
              )}
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}
