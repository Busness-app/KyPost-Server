import { useEffect, useState } from "react";
import { toErrorMessage } from "../../api/client";
import { createSendAsAlias, deleteSendAsAlias, listSendAsAliases, type SendAsAlias } from "../../api/sendas";
import { formatWhen, sendAsStatusClass, sendAsStatusLabel } from "../../pages/config/settings";

export function SendAs() {
  const [sendAsAliases, setSendAsAliases] = useState<SendAsAlias[]>([]);
  const [sendAsEmail, setSendAsEmail] = useState("");
  const [sendAsDisplayName, setSendAsDisplayName] = useState("");
  const [sendAsMessage, setSendAsMessage] = useState("");
  const [sendAsBusy, setSendAsBusy] = useState(false);

  async function refreshSendAsAliases() {
    setSendAsAliases(await listSendAsAliases());
  }

  useEffect(() => {
    void refreshSendAsAliases().catch(() => undefined);
  }, []);

  // While any alias is still verifying, poll for status changes so the list
  // updates on its own once the background verification check (server-side,
  // typically completing within a couple of minutes) resolves it — the user
  // never has to do anything or refresh manually. Stops as soon as nothing
  // is pending, so this never polls indefinitely for an idle account.
  useEffect(() => {
    if (!sendAsAliases.some((alias) => alias.status === "pending")) {
      return;
    }
    const interval = window.setInterval(() => {
      refreshSendAsAliases().catch(() => undefined);
    }, 15000);
    return () => window.clearInterval(interval);
  }, [sendAsAliases]);

  async function addSendAsAlias() {
    const email = sendAsEmail.trim();
    if (!email) {
      setSendAsMessage("Enter an email address first.");
      return;
    }
    setSendAsBusy(true);
    setSendAsMessage("");
    try {
      await createSendAsAlias(email, sendAsDisplayName.trim());
      setSendAsEmail("");
      setSendAsDisplayName("");
      setSendAsMessage("Verification email sent. This address will show as verified automatically once the check completes — no action needed.");
      await refreshSendAsAliases();
    } catch (error: unknown) {
      setSendAsMessage(`Failed to start verification: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setSendAsBusy(false);
    }
  }

  async function removeSendAsAlias(alias: SendAsAlias) {
    if (!window.confirm(`Remove ${alias.email} as a send-as address?`)) {
      return;
    }
    setSendAsBusy(true);
    setSendAsMessage("");
    try {
      await deleteSendAsAlias(alias.id);
      await refreshSendAsAliases();
    } catch (error: unknown) {
      setSendAsMessage(`Failed to remove address: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setSendAsBusy(false);
    }
  }

  return (
    <div className="config-card">
      <h3>Send-As Addresses</h3>
      <p className="config-muted">
        Add a secondary email address you also control. KyPost verifies it automatically — it emails the address
        a one-time code and watches for that same message to come back to this inbox, with no reply or link click
        needed on your part. Once verified, you can choose it as the From address when composing mail.
      </p>
      <div className="config-grid config-grid-two">
        <label>
          <div>Email Address</div>
          <input
            type="email"
            value={sendAsEmail}
            onChange={(event) => setSendAsEmail(event.target.value)}
            placeholder="you@another-domain.com"
          />
        </label>
        <label>
          <div>Display Name (optional)</div>
          <input value={sendAsDisplayName} onChange={(event) => setSendAsDisplayName(event.target.value)} />
        </label>
      </div>
      <div className="config-actions">
        <button type="button" onClick={() => void addSendAsAlias()} disabled={sendAsBusy}>
          {sendAsBusy ? "Working..." : "Verify Address"}
        </button>
      </div>
      {sendAsMessage ? <p className="config-muted">{sendAsMessage}</p> : null}

      {sendAsAliases.length > 0 ? (
        <div className="config-status-card">
          {sendAsAliases.map((alias) => (
            <div
              key={alias.id}
              style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, padding: "6px 0" }}
            >
              <span>
                {alias.displayName ? `${alias.displayName} <${alias.email}>` : alias.email}
                {" — "}
                {alias.status === "verified" && alias.verifiedAt
                  ? `verified ${formatWhen(alias.verifiedAt)}`
                  : alias.status === "failed"
                    ? `verification failed${alias.failedAt ? ` ${formatWhen(alias.failedAt)}` : ""}`
                    : `verifying, expires ${formatWhen(alias.expiresAt)}`}
                {alias.auto ? (
                  <span className="config-muted">
                    {alias.status === "failed"
                      ? " — this is your account address, checked automatically so your public key can be published for it." +
                        " Your key is not being published while this check is failing, which usually means your mail provider" +
                        " does not DKIM-sign the mail you send. KyPost retries weekly."
                      : " — your account address, checked automatically so your public key can be published for it."}
                  </span>
                ) : null}
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span className={`contacts-badge ${sendAsStatusClass(alias.status)}`}>
                  <span className="contacts-dot" aria-hidden="true" />
                  {sendAsStatusLabel(alias.status)}
                </span>
                <button type="button" onClick={() => void removeSendAsAlias(alias)} disabled={sendAsBusy}>
                  Remove
                </button>
              </span>
            </div>
          ))}
        </div>
      ) : (
        <p className="config-muted">No send-as addresses yet.</p>
      )}
    </div>
  );
}
