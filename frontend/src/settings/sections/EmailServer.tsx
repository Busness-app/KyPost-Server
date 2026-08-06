import { useEffect, useState } from "react";
import { deleteJSON, getJSON, postJSON, toErrorMessage } from "../../api/client";
import type { IMAPConfigStatus, IMAPForm } from "../../pages/config/settings";

type EmailServerProps = {
  // labelsFromImap is also read by the Labels tab (ConfigPage, admin-only)
  // and by NotificationPrefs, so it stays owned by ConfigPage rather than
  // being duplicated here — this callback just asks it to refresh after a
  // save, exactly like the pre-extraction code did.
  refreshLabels: () => Promise<void>;
};

export function EmailServer({ refreshLabels }: EmailServerProps) {
  const [imapStatus, setImapStatus] = useState<IMAPConfigStatus | null>(null);
  const [imapForm, setImapForm] = useState<IMAPForm>({
    host: "",
    port: 993,
    username: "",
    password: "",
    mailbox: "INBOX",
    smtpHost: "",
    smtpPort: 587
  });
  const [imapMessage, setImapMessage] = useState("");
  const [imapBusy, setImapBusy] = useState(false);

  async function refreshIMAPStatus() {
    const status = await getJSON<IMAPConfigStatus>("/api/imap/config");
    setImapStatus(status);
    if (status.configured) {
      setImapForm((prev) => ({
        host: status.host ?? prev.host,
        port: status.port ?? prev.port,
        username: status.username ?? prev.username,
        password: "",
        mailbox: status.mailbox ?? prev.mailbox,
        smtpHost: status.smtpHost ?? prev.smtpHost,
        smtpPort: status.smtpPort ?? prev.smtpPort
      }));
    }
  }

  useEffect(() => {
    void refreshIMAPStatus();
  }, []);

  async function saveIMAPConfig() {
    setImapBusy(true);
    setImapMessage("");
    try {
      const result = await postJSON<IMAPConfigStatus>("/api/imap/config", imapForm);
      setImapStatus(result);
      setImapForm((prev) => ({ ...prev, password: "" }));
      setImapMessage("IMAP configuration saved.");
      await refreshLabels();
    } catch (error: unknown) {
      const message = toErrorMessage(error, "unknown error");
      setImapMessage(`Failed to save IMAP config: ${message}`);
    } finally {
      setImapBusy(false);
    }
  }

  async function testIMAPConfig() {
    setImapBusy(true);
    setImapMessage("");
    try {
      const result = await postJSON<{ ok: boolean; error?: string; host?: string; port?: number; mailbox?: string }>(
        "/api/imap/test",
        imapForm
      );
      if (result.ok) {
        setImapMessage(`IMAP test passed (${result.host}:${result.port} ${result.mailbox}).`);
      } else {
        setImapMessage(`IMAP test failed: ${result.error ?? "unknown error"}`);
      }
    } catch (error: unknown) {
      const message = toErrorMessage(error, "unknown error");
      setImapMessage(`IMAP test failed: ${message}`);
    } finally {
      setImapBusy(false);
    }
  }

  async function deleteIMAPConfig() {
    setImapBusy(true);
    setImapMessage("");
    try {
      await deleteJSON<{ ok: boolean; configured: boolean }>("/api/imap/config");
      setImapStatus({ configured: false });
      setImapForm({ host: "", port: 993, username: "", password: "", mailbox: "INBOX", smtpHost: "", smtpPort: 587 });
      setImapMessage("Stored IMAP configuration removed.");
    } catch (error: unknown) {
      const message = toErrorMessage(error, "unknown error");
      setImapMessage(`Failed to delete IMAP config: ${message}`);
    } finally {
      setImapBusy(false);
    }
  }

  return (
    <div className="config-card">
      <h3>Email Settings</h3>
      <p className="config-muted">Stored mail credentials are encrypted at rest. SMTP host/port are optional overrides.</p>
      <div className="config-grid config-grid-two">
        <label>
          <div>Host</div>
          <input value={imapForm.host} onChange={(event) => setImapForm((prev) => ({ ...prev, host: event.target.value }))} />
        </label>
        <label>
          <div>Port</div>
          <input
            type="number"
            value={imapForm.port}
            onChange={(event) => setImapForm((prev) => ({ ...prev, port: Number(event.target.value) || 993 }))}
          />
        </label>
        <label>
          <div>Username</div>
          <input value={imapForm.username} onChange={(event) => setImapForm((prev) => ({ ...prev, username: event.target.value }))} />
        </label>
        <label>
          <div>Password or App Password</div>
          <input
            type="password"
            value={imapForm.password}
            onChange={(event) => setImapForm((prev) => ({ ...prev, password: event.target.value }))}
            placeholder="Required when saving changes"
          />
        </label>
        <label>
          <div>Mailbox</div>
          <input value={imapForm.mailbox} onChange={(event) => setImapForm((prev) => ({ ...prev, mailbox: event.target.value }))} />
        </label>
        <label>
          <div>SMTP Host (optional)</div>
          <input
            value={imapForm.smtpHost}
            onChange={(event) => setImapForm((prev) => ({ ...prev, smtpHost: event.target.value }))}
            placeholder="Defaults to IMAP-derived host"
          />
        </label>
        <label>
          <div>SMTP Port (optional)</div>
          <input
            type="number"
            value={imapForm.smtpPort}
            onChange={(event) => setImapForm((prev) => ({ ...prev, smtpPort: Number(event.target.value) || 587 }))}
          />
        </label>
      </div>
      <div className="config-actions">
        <button type="button" onClick={saveIMAPConfig} disabled={imapBusy}>
          {imapBusy ? "Saving..." : "Save Email Settings"}
        </button>
        <button type="button" onClick={testIMAPConfig} disabled={imapBusy}>
          {imapBusy ? "Testing..." : "Test Email Settings"}
        </button>
        <button type="button" onClick={deleteIMAPConfig} disabled={imapBusy}>
          Delete Stored Email Settings
        </button>
      </div>

      {imapStatus ? (
        <div className="config-status-card">
          <p>Configured: {imapStatus.configured ? "Yes" : "No"}</p>
          {imapStatus.path ? <p>Config Path: {imapStatus.path}</p> : null}
          {imapStatus.keyPath ? <p>Key Path: {imapStatus.keyPath}</p> : null}
          {imapStatus.host ? <p>Host: {imapStatus.host}</p> : null}
          {imapStatus.port ? <p>Port: {imapStatus.port}</p> : null}
          {imapStatus.username ? <p>Username: {imapStatus.username}</p> : null}
          {imapStatus.mailbox ? <p>Mailbox: {imapStatus.mailbox}</p> : null}
          {imapStatus.smtpHost ? <p>SMTP Host: {imapStatus.smtpHost}</p> : null}
          {imapStatus.smtpPort ? <p>SMTP Port: {imapStatus.smtpPort}</p> : null}
          {imapStatus.updatedAt ? <p>Updated: {imapStatus.updatedAt}</p> : null}
        </div>
      ) : null}

      {imapMessage ? <p className="config-muted">{imapMessage}</p> : null}
    </div>
  );
}
