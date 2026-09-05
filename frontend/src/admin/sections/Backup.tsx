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
  }[];
};
const base = "/api/admin/backup/";

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
      await refresh();
    } catch (e) {
      setError(toErrorMessage(e, "Backup action failed"));
    } finally {
      setPassword("");
      setBusy(false);
    }
  }
  return (
    <div className="config-section">
      <h3>Sealed backups</h3>
      <p>
        Back up configuration, deployment keys, accounts and metadata databases.
        Only your recovery custodians together can open a capsule.
      </p>
      <p>{status?.excluded}</p>
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
      <div className="config-grid config-grid-two">
        <div className="config-status-card">
          <h4>Recovery key</h4>
          <p style={{ overflowWrap: "anywhere" }}>
            {status?.keyId || "No key pinned"}
          </p>
          {status?.keyId && (
            <p>
              {status.threshold} of {status.totalShares} custodians
            </p>
          )}
        </div>
        <div className="config-status-card">
          <h4>KyRecovery</h4>
          <p>{status?.paired ? status.kyrecoveryUrl : "Not paired"}</p>
          <p>
            {status?.lastReceipt
              ? "Last deposit: " + status.lastReceipt.deposited_at
              : "No deposit receipt"}
          </p>
        </div>
        <div className="config-status-card">
          <h4>Local copies</h4>
          <p>{status?.localDir || "No local directory configured"}</p>
          <p>{status?.localCopies.length ?? 0} retained</p>
        </div>
        <div className="config-status-card">
          <h4>Schedule</h4>
          <p>
            {status?.intervalSec
              ? "Next run: " + (status.nextRun || "Pending")
              : "Off"}
          </p>
        </div>
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
      {status?.intervalSec === 0 && <p>Automatic backups are off.</p>}
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
          Your password is cleared after each action. Recovery shares are never
          entered here.
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
          <button
            className="button secondary"
            disabled={!password}
            onClick={() => void act("drill")}
          >
            Run restore drill
          </button>
        </div>
        <p>
          A drill uses a disposable key. Test your real custodian cards
          separately with an offline restore.
        </p>
        <h4>Schedule</h4>
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
        <h4>Pair with KyRecovery</h4>
        <p>
          Use HTTPS and compare the pinned fingerprint out of band, or pin the
          key below before pairing. HTTPS protects the pairing key, token and
          receipts.
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
        <h4>Pin the suite key by hand</h4>
        <label>
          Recovery public key (base64)
          <textarea value={key} onChange={(e) => setKey(e.target.value)} />
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
      </fieldset>
      {busy && (
        <p role="status">Working. A backup upload can take up to 16 minutes.</p>
      )}
      <h4>Recent backup activity</h4>
      <ul>
        {status?.recent.map((row) => (
          <li key={row.id}>
            {row.at} — {row.action}: {row.outcome} {row.target}
          </li>
        ))}
      </ul>
    </div>
  );
}
