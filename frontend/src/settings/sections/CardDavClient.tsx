import { useEffect, useState } from "react";
import { toErrorMessage } from "../../api/client";
import {
  deleteCardDAVClientConfig,
  getCardDAVClientConfig,
  saveCardDAVClientConfig,
  syncCardDAVClient,
  type CardDAVClientConfig
} from "../../api/contacts";

export function CardDavClient() {
  const [clientConfig, setClientConfig] = useState<CardDAVClientConfig | null>(null);
  const [clientForm, setClientForm] = useState({ serverUrl: "", username: "", password: "", addressBookPath: "" });
  const [clientBusy, setClientBusy] = useState(false);
  const [clientSyncBusy, setClientSyncBusy] = useState(false);
  const [clientMessage, setClientMessage] = useState("");

  async function refreshCardDAVClientConfig() {
    const status = await getCardDAVClientConfig();
    setClientConfig(status);
    if (status.configured) {
      setClientForm((prev) => ({
        serverUrl: status.serverUrl ?? prev.serverUrl,
        username: status.username ?? prev.username,
        password: "",
        addressBookPath: status.addressBookPath ?? prev.addressBookPath
      }));
    }
  }

  useEffect(() => {
    void refreshCardDAVClientConfig().catch(() => undefined);
  }, []);

  async function saveCardDAVClient() {
    if (!clientForm.serverUrl.trim() || !clientForm.username.trim() || !clientForm.password.trim()) {
      setClientMessage("Server URL, username, and password are required.");
      return;
    }
    setClientBusy(true);
    setClientMessage("");
    try {
      await saveCardDAVClientConfig({
        serverUrl: clientForm.serverUrl.trim(),
        username: clientForm.username.trim(),
        password: clientForm.password.trim(),
        addressBookPath: clientForm.addressBookPath.trim()
      });
      setClientMessage("CardDAV client configuration saved.");
      await refreshCardDAVClientConfig();
    } catch (error: unknown) {
      setClientMessage(`Failed to save CardDAV client configuration: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setClientBusy(false);
    }
  }

  function useDiscoveredAddressBook(path: string) {
    setClientForm((prev) => ({ ...prev, addressBookPath: path }));
    setClientMessage(`Address book pinned to ${path} — click "Save CardDAV Client" then "Sync Now" to apply.`);
  }

  async function deleteCardDAVClient() {
    if (!window.confirm("Remove the stored CardDAV client configuration?")) {
      return;
    }
    setClientBusy(true);
    setClientMessage("");
    try {
      await deleteCardDAVClientConfig();
      setClientConfig({ configured: false });
      setClientForm({ serverUrl: "", username: "", password: "", addressBookPath: "" });
      setClientMessage("CardDAV client configuration removed.");
    } catch (error: unknown) {
      setClientMessage(`Failed to remove CardDAV client configuration: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setClientBusy(false);
    }
  }

  async function runCardDAVClientSync() {
    setClientSyncBusy(true);
    setClientMessage("");
    try {
      const result = await syncCardDAVClient();
      setClientMessage(`Synced: ${result.imported ?? 0} imported, ${result.updated ?? 0} updated.`);
      await refreshCardDAVClientConfig();
    } catch (error: unknown) {
      setClientMessage(`Sync failed: ${toErrorMessage(error, "unknown error")}`);
      await refreshCardDAVClientConfig().catch(() => undefined);
    } finally {
      setClientSyncBusy(false);
    }
  }

  return (
    <div className="config-card">
      <h3>CardDAV Client</h3>
      <p className="config-muted">
        Pull contacts down from an external CardDAV server (iCloud, Google, Nextcloud, Fastmail, etc.) into your
        KyPost address book. Imported contacts then reach the mobile app the same way locally-added ones do.
      </p>
      <div className="config-grid config-grid-two">
        <label>
          <div>Server URL</div>
          <input
            value={clientForm.serverUrl}
            onChange={(event) => setClientForm((prev) => ({ ...prev, serverUrl: event.target.value }))}
            placeholder="https://contacts.example.com/dav/"
          />
        </label>
        <label>
          <div>Username</div>
          <input
            value={clientForm.username}
            onChange={(event) => setClientForm((prev) => ({ ...prev, username: event.target.value }))}
          />
        </label>
        <label>
          <div>Password or App Password</div>
          <input
            type="password"
            value={clientForm.password}
            onChange={(event) => setClientForm((prev) => ({ ...prev, password: event.target.value }))}
            placeholder="Required when saving changes"
          />
        </label>
        <label>
          <div>Address Book Path (optional override)</div>
          <input
            value={clientForm.addressBookPath}
            onChange={(event) => setClientForm((prev) => ({ ...prev, addressBookPath: event.target.value }))}
            placeholder="Leave blank to auto-discover"
          />
        </label>
      </div>
      <p className="config-muted">
        By default the server is auto-discovered, and if it reports more than one address book (common on
        providers like mailbox.org, Nextcloud, or Baikal — a personal book alongside shared/collected ones), the
        first one that actually contains contacts is used. If it still picks the wrong one, copy a path from the
        list below into the override field, save, and sync again.
      </p>
      <div className="config-actions">
        <button type="button" onClick={() => void saveCardDAVClient()} disabled={clientBusy}>
          {clientBusy ? "Saving..." : "Save CardDAV Client"}
        </button>
        <button type="button" onClick={() => void runCardDAVClientSync()} disabled={clientSyncBusy || !clientConfig?.configured}>
          {clientSyncBusy ? "Syncing..." : "Sync Now"}
        </button>
        {clientConfig?.configured ? (
          <button type="button" onClick={() => void deleteCardDAVClient()} disabled={clientBusy}>
            Delete Stored Configuration
          </button>
        ) : null}
      </div>

      {clientConfig?.configured ? (
        <div className="config-status-card">
          <p>Configured: Yes</p>
          <p>Server URL: {clientConfig.serverUrl}</p>
          <p>Username: {clientConfig.username}</p>
          {clientConfig.addressBookPath ? <p>Address Book: {clientConfig.addressBookPath}</p> : null}
          {clientConfig.lastSyncedAt ? <p>Last Synced: {clientConfig.lastSyncedAt}</p> : null}
          {clientConfig.lastSyncError ? (
            <p>Last Sync Error: {clientConfig.lastSyncError}</p>
          ) : clientConfig.lastSyncedAt ? (
            <p>Last Sync Result: {clientConfig.lastSyncImported ?? 0} imported, {clientConfig.lastSyncUpdated ?? 0} updated</p>
          ) : null}
          {clientConfig.discoveredAddressBooks && clientConfig.discoveredAddressBooks.length > 0 ? (
            <div style={{ marginTop: 10 }}>
              <p>Address books found on the server:</p>
              <div className="config-grid">
                {clientConfig.discoveredAddressBooks.map((book) => (
                  <div
                    key={book.path}
                    style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}
                  >
                    <span>
                      {book.path === clientConfig.addressBookPath ? <strong>{book.path}</strong> : book.path}
                      {book.name ? ` (${book.name})` : ""} — {book.contactCount} contact
                      {book.contactCount === 1 ? "" : "s"}
                    </span>
                    {book.path !== clientForm.addressBookPath ? (
                      <button type="button" onClick={() => useDiscoveredAddressBook(book.path)}>
                        Use This
                      </button>
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      ) : null}

      {clientMessage ? <p className="config-muted">{clientMessage}</p> : null}
    </div>
  );
}
