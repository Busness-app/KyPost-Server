import { useEffect, useMemo, useState } from "react";
import { deleteJSON, getJSON, postJSON, putJSON, toErrorMessage } from "../api/client";
import { normalizeConfig, uniqueLabels, type AppConfig } from "../api/config";
import {
  deleteCardDAVClientConfig,
  generateDAVPassword,
  getCardDAVClientConfig,
  getDAVPasswordStatus,
  revokeDAVPassword,
  saveCardDAVClientConfig,
  syncCardDAVClient,
  type CardDAVClientConfig,
  type DAVPasswordStatus
} from "../api/contacts";
import { createSendAsAlias, deleteSendAsAlias, listSendAsAliases, type SendAsAlias } from "../api/sendas";
import {
  listWKDDomains,
  claimWKDDomain,
  verifyWKDDomain,
  deleteWKDDomain,
  wkdDomainRecord,
  type WKDDomainClaim
} from "../api/pgp";
import { useAuth } from "../auth";
import { applyTheme, getStoredTheme, THEME_OPTIONS, type ThemeName } from "../theme";

type LabelsResponse = {
  configured: string[];
  imap: string[];
};

type IMAPConfigStatus = {
  configured: boolean;
  path?: string;
  keyPath?: string;
  host?: string;
  port?: number;
  username?: string;
  mailbox?: string;
  smtpHost?: string;
  smtpPort?: number;
  updatedAt?: string;
  encryptedAtRest?: boolean;
};

type IMAPForm = {
  host: string;
  port: number;
  username: string;
  password: string;
  mailbox: string;
  smtpHost: string;
  smtpPort: number;
};

const LOG_LEVEL_OPTIONS = ["trace", "debug", "info", "warn", "error", "fatal", "panic"];

function formatWhen(value?: string): string {
  if (!value) {
    return "";
  }
  const when = new Date(value);
  if (Number.isNaN(when.getTime())) {
    return "";
  }
  return when.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

function sendAsStatusLabel(status: SendAsAlias["status"]): string {
  switch (status) {
    case "verified":
      return "verified";
    case "failed":
      return "verification failed";
    default:
      return "verifying…";
  }
}

function sendAsStatusClass(status: SendAsAlias["status"]): string {
  switch (status) {
    case "verified":
      return "contacts-status-active";
    case "failed":
      return "contacts-status-failed";
    default:
      return "contacts-status-pending";
  }
}

function getTimezoneOptions(): string[] {
  const intlWithSupportedValues = Intl as typeof Intl & {
    supportedValuesOf: (key: "timeZone") => string[];
  };
  return intlWithSupportedValues.supportedValuesOf("timeZone");
}

function labelsToText(labels: string[]): string {
  return labels.join("\n");
}

function textToLabels(raw: string): string[] {
  return uniqueLabels(raw.split(/\r?\n/));
}

function mappingToText(mapping: Record<string, string[]>): string {
  return Object.keys(mapping)
    .sort((a, b) => a.localeCompare(b))
    .map((label) => `${label}: ${uniqueLabels(mapping[label] ?? []).join(", ")}`)
    .join("\n");
}

function textToMapping(raw: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const splitAt = trimmed.indexOf(":");
    if (splitAt <= 0) {
      continue;
    }
    const label = trimmed.slice(0, splitAt).trim();
    const values = uniqueLabels(trimmed.slice(splitAt + 1).split(","));
    if (label && values.length > 0) {
      out[label] = values;
    }
  }
  return out;
}

export function ConfigPage() {
  const testPrompt = "Email Address: test@example.com Subject Line: Classifier connectivity test Return only the label Updates";

  // Application, Labels, and Remote LLM settings are global/system-owned
  // and admin-only; every user manages their own Email (IMAP/SMTP) settings.
  const auth = useAuth();
  const isAdmin = auth.role === "admin";

  const [cfg, setCfg] = useState<AppConfig | null>(null);
  const [allowlistText, setAllowlistText] = useState("");
  const [keywordMappingText, setKeywordMappingText] = useState("");
  const [labelsFromImap, setLabelsFromImap] = useState<string[]>([]);
  const [configStatus, setConfigStatus] = useState("");
  const [selectedTheme, setSelectedTheme] = useState<ThemeName>(getStoredTheme());

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

  const [sendAsAliases, setSendAsAliases] = useState<SendAsAlias[]>([]);
  const [sendAsEmail, setSendAsEmail] = useState("");
  const [sendAsDisplayName, setSendAsDisplayName] = useState("");
  const [sendAsMessage, setSendAsMessage] = useState("");
  const [sendAsBusy, setSendAsBusy] = useState(false);

  const [classifierTestBusy, setClassifierTestBusy] = useState(false);
  const [classifierTestResult, setClassifierTestResult] = useState("");
  const [activeTab, setActiveTab] = useState<"application" | "email" | "carddav" | "labels" | "llm" | "wkd">(isAdmin ? "application" : "email");
  const configStatusTone = configStatus.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

  const [davStatus, setDavStatus] = useState<DAVPasswordStatus | null>(null);
  const [davBusy, setDavBusy] = useState(false);
  const [revealedPassword, setRevealedPassword] = useState("");
  const [copyStatus, setCopyStatus] = useState("");
  const davURL = auth.username ? `${window.location.origin}/dav/${encodeURIComponent(auth.username)}/contacts/` : "";

  const [clientConfig, setClientConfig] = useState<CardDAVClientConfig | null>(null);
  const [clientForm, setClientForm] = useState({ serverUrl: "", username: "", password: "", addressBookPath: "" });
  const [clientBusy, setClientBusy] = useState(false);
  const [clientSyncBusy, setClientSyncBusy] = useState(false);
  const [clientMessage, setClientMessage] = useState("");

  const [wkdDomains, setWkdDomains] = useState<WKDDomainClaim[]>([]);
  const [wkdLoading, setWkdLoading] = useState(true);
  const [wkdBusy, setWkdBusy] = useState(false);
  const [wkdStatus, setWkdStatus] = useState("");
  const [wkdNewDomain, setWkdNewDomain] = useState("");

  const effectiveAllowlist = useMemo(() => {
    const cfgLabels = textToLabels(allowlistText);
    return uniqueLabels([...cfgLabels]);
  }, [allowlistText]);

  const timezoneOptions = useMemo(() => {
    const all = getTimezoneOptions();
    const timezone = cfg?.timezone;
    if (!timezone || all.includes(timezone)) {
      return all;
    }
    return [timezone, ...all];
  }, [cfg?.timezone]);

  const logLevelOptions = useMemo(() => {
    const logLevel = cfg?.logLevel;
    if (!logLevel || LOG_LEVEL_OPTIONS.includes(logLevel)) {
      return LOG_LEVEL_OPTIONS;
    }
    return [logLevel, ...LOG_LEVEL_OPTIONS];
  }, [cfg?.logLevel]);

  async function refreshLabels() {
    const labelsData = await getJSON<LabelsResponse>("/api/labels");
    setLabelsFromImap(uniqueLabels(labelsData.imap ?? []));
  }

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

  async function refreshDavStatus() {
    setDavStatus(await getDAVPasswordStatus());
  }

  async function refreshSendAsAliases() {
    setSendAsAliases(await listSendAsAliases());
  }

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

  async function refreshWKDDomains() {
    try {
      const res = await listWKDDomains();
      setWkdDomains(res.domains);
    } finally {
      setWkdLoading(false);
    }
  }

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setSelectedTheme(getStoredTheme());
      try {
        const nextConfig = await getJSON<unknown>("/api/config");
        if (cancelled) {
          return;
        }
        const normalized = normalizeConfig(nextConfig);
        setCfg(normalized);
        setAllowlistText(labelsToText(normalized.labels.allowlist));
        setKeywordMappingText(mappingToText(normalized.labels.keywordMappings));
      } catch {
        if (!cancelled) {
          setConfigStatus("Failed to load configuration data.");
        }
        return;
      }

      // Load secondary panels independently so one failure does not block the entire page.
      const loaders = [
        refreshLabels().catch(() => undefined),
        refreshIMAPStatus().catch(() => undefined),
        refreshDavStatus().catch(() => undefined),
        refreshCardDAVClientConfig().catch(() => undefined),
        refreshSendAsAliases().catch(() => undefined)
      ];
      // WKD domain management is admin-only on the backend (s.withAdmin) —
      // skip the fetch entirely for non-admins rather than let it 403.
      if (isAdmin) {
        loaders.push(refreshWKDDomains().catch(() => undefined));
      }
      await Promise.all(loaders);
    };

    load();
    return () => {
      cancelled = true;
    };
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

  if (!cfg) {
    return (
      <section className="panel">
        <h2>Configuration</h2>
        <p>{configStatus || "Loading configuration..."}</p>
      </section>
    );
  }

  async function saveConfig() {
    if (!cfg) return;
    const next: AppConfig = {
      ...cfg,
      labels: {
        ...cfg.labels,
        allowlist: effectiveAllowlist,
        keywordMappings: textToMapping(keywordMappingText)
      }
    };

    // The API key input is write-only (never populated from a loaded
    // config), so a non-empty value here can only mean the user just typed
    // a new one. Only send apiKey in that case — an empty string would
    // otherwise look like "clear the key" to a naive reader of the diff,
    // even though the server already preserves the existing key on empty.
    // apiKeySet is a response-only computed field; never send it back.
    const typedApiKey = next.classifier.apiKey.trim();
    const { apiKeySet: _apiKeySet, apiKey: _apiKey, ...classifierRest } = next.classifier;
    const payload = {
      ...next,
      classifier: typedApiKey ? { ...classifierRest, apiKey: typedApiKey } : classifierRest
    };

    try {
      await putJSON<{ ok: boolean }>("/api/config", payload);
      setCfg({
        ...next,
        classifier: {
          ...next.classifier,
          apiKey: "",
          apiKeySet: typedApiKey ? true : next.classifier.apiKeySet
        }
      });
      setConfigStatus("Configuration saved.");
    } catch {
      setConfigStatus("Failed to save configuration.");
    }
  }

  function saveTheme() {
    applyTheme(selectedTheme);
    setConfigStatus(`Theme set to ${selectedTheme}.`);
  }

  function applyImapLabelsToAllowlist() {
    const merged = uniqueLabels([...effectiveAllowlist, ...labelsFromImap]);
    setAllowlistText(labelsToText(merged));
    setConfigStatus("Merged discovered IMAP labels into allowlist (not yet saved).");
  }

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

  async function runClassifierTest() {
    setClassifierTestBusy(true);
    setClassifierTestResult("");
    try {
      const result = await postJSON<{ ok: boolean; response?: string; error?: string; baseUrl?: string; path?: string }>(
        "/api/classifier/test",
        { prompt: testPrompt }
      );
      if (!result.ok) {
        setClassifierTestResult(`Classifier test failed: ${result.error ?? "unknown error"}`);
      } else {
        setClassifierTestResult(
          `Classifier test passed\nBase URL: ${result.baseUrl ?? ""}\nPath: ${result.path ?? ""}\nResponse: ${result.response ?? ""}`
        );
      }
    } catch (error: unknown) {
      const message = toErrorMessage(error, "unknown error");
      setClassifierTestResult(`Classifier test failed: ${message}`);
    } finally {
      setClassifierTestBusy(false);
    }
  }

  function updateConfig<K extends keyof AppConfig>(key: K, value: AppConfig[K]) {
    setCfg((prev) => (prev ? { ...prev, [key]: value } : prev));
  }

  async function generateDavPassword() {
    setDavBusy(true);
    setCopyStatus("");
    try {
      const generated = await generateDAVPassword();
      setRevealedPassword(generated.password);
      await refreshDavStatus();
    } catch (error: unknown) {
      setConfigStatus(`Failed to generate CardDAV password: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setDavBusy(false);
    }
  }

  async function revokeDavPassword() {
    if (
      !window.confirm(
        "Revoke the CardDAV app password? Any connected CardDAV client will stop syncing until you generate a new one."
      )
    ) {
      return;
    }
    setDavBusy(true);
    setCopyStatus("");
    try {
      await revokeDAVPassword();
      setRevealedPassword("");
      await refreshDavStatus();
    } catch (error: unknown) {
      setConfigStatus(`Failed to revoke CardDAV password: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setDavBusy(false);
    }
  }

  function copyDavPassword() {
    if (!revealedPassword || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(revealedPassword).then(
      () => setCopyStatus("Copied to clipboard."),
      () => setCopyStatus("Could not copy automatically — copy it manually.")
    );
  }

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

  function copyWKDText(text: string) {
    void navigator.clipboard?.writeText(text);
  }

  async function addWKDDomain() {
    const domain = wkdNewDomain.trim().toLowerCase();
    if (!domain) return;
    setWkdBusy(true);
    setWkdStatus("");
    try {
      await claimWKDDomain(domain);
      setWkdNewDomain("");
      await refreshWKDDomains();
    } catch (error: unknown) {
      setWkdStatus(`Failed to add domain: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setWkdBusy(false);
    }
  }

  async function runWKDDomainVerify(domain: string) {
    setWkdBusy(true);
    setWkdStatus("");
    try {
      const result = await verifyWKDDomain(domain);
      await refreshWKDDomains();
      setWkdStatus(
        result.verified
          ? `${domain} verified. Also point openpgpkey.${domain} at this server (DNS or a tunnel) so key lookups can actually resolve.`
          : `${domain} is not verified yet — make sure the DNS TXT record is in place and has propagated, then try again.`
      );
    } catch (error: unknown) {
      setWkdStatus(`Failed to verify domain: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setWkdBusy(false);
    }
  }

  async function removeWKDDomain(domain: string) {
    if (!window.confirm(`Stop publishing keys for ${domain}? Users will no longer be discoverable via WKD at this domain.`)) {
      return;
    }
    setWkdBusy(true);
    setWkdStatus("");
    try {
      await deleteWKDDomain(domain);
      await refreshWKDDomains();
    } catch (error: unknown) {
      setWkdStatus(`Failed to remove domain: ${toErrorMessage(error, "unknown error")}`);
    } finally {
      setWkdBusy(false);
    }
  }

  return (
    <section className="panel config-page">
      <div className="config-header">
        <h2>Configuration</h2>
        <p>{isAdmin ? "Manage system behavior, email connectivity, labels, and model integration." : "Manage your email connectivity."}</p>
      </div>

      <div className="config-tabs" role="tablist" aria-label="Configuration sections">
        {isAdmin ? (
          <button type="button" role="tab" aria-selected={activeTab === "application"} className={`config-tab${activeTab === "application" ? " active" : ""}`} onClick={() => setActiveTab("application")}>Application</button>
        ) : null}
        <button type="button" role="tab" aria-selected={activeTab === "email"} className={`config-tab${activeTab === "email" ? " active" : ""}`} onClick={() => setActiveTab("email")}>Email Settings</button>
        <button type="button" role="tab" aria-selected={activeTab === "carddav"} className={`config-tab${activeTab === "carddav" ? " active" : ""}`} onClick={() => setActiveTab("carddav")}>CardDAV</button>
        {isAdmin ? (
          <button type="button" role="tab" aria-selected={activeTab === "labels"} className={`config-tab${activeTab === "labels" ? " active" : ""}`} onClick={() => setActiveTab("labels")}>Labels</button>
        ) : null}
        {isAdmin ? (
          <button type="button" role="tab" aria-selected={activeTab === "llm"} className={`config-tab${activeTab === "llm" ? " active" : ""}`} onClick={() => setActiveTab("llm")}>Remote LLM</button>
        ) : null}
        {isAdmin ? (
          <button type="button" role="tab" aria-selected={activeTab === "wkd"} className={`config-tab${activeTab === "wkd" ? " active" : ""}`} onClick={() => setActiveTab("wkd")}>WKD Domains</button>
        ) : null}
      </div>

      {activeTab === "application" && isAdmin ? (
        <div className="config-card" role="tabpanel">
          <h3>Application</h3>
          <p className="config-muted">Core runtime and interface settings.</p>
          <div className="config-grid config-grid-two">
            <label>
              <div>Timezone</div>
              <select value={cfg.timezone} onChange={(event) => updateConfig("timezone", event.target.value)}>
                {timezoneOptions.map((timezone) => (
                  <option key={timezone} value={timezone}>
                    {timezone}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <div>Log Level</div>
              <select value={cfg.logLevel} onChange={(event) => updateConfig("logLevel", event.target.value)}>
                {logLevelOptions.map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <div>Scan Interval (seconds)</div>
              <input
                type="number"
                value={cfg.scan.intervalSeconds}
                onChange={(event) => updateConfig("scan", { intervalSeconds: Number(event.target.value) || 0 })}
              />
            </label>
            <label>
              <div>Rate Limit Per Minute</div>
              <input
                type="number"
                value={cfg.rateLimits.perMinute}
                onChange={(event) => updateConfig("rateLimits", { ...cfg.rateLimits, perMinute: Number(event.target.value) || 0 })}
              />
            </label>
            <label>
              <div>Rate Limit Per Hour</div>
              <input
                type="number"
                value={cfg.rateLimits.perHour}
                onChange={(event) => updateConfig("rateLimits", { ...cfg.rateLimits, perHour: Number(event.target.value) || 0 })}
              />
            </label>
            <label>
              <div>Theme</div>
              <select value={selectedTheme} onChange={(event) => setSelectedTheme(event.target.value as ThemeName)}>
                {THEME_OPTIONS.map((theme) => (
                  <option key={theme} value={theme}>
                    {theme}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="config-actions">
            <button type="button" onClick={saveTheme}>Apply Theme</button>
            <button type="button" onClick={saveConfig}>Save Configuration</button>
          </div>
        </div>
      ) : null}

      {!isAdmin ? (
        <div className="config-card">
          <h3>Appearance</h3>
          <p className="config-muted">Theme is stored in this browser only.</p>
          <div className="config-grid config-grid-two">
            <label>
              <div>Theme</div>
              <select value={selectedTheme} onChange={(event) => setSelectedTheme(event.target.value as ThemeName)}>
                {THEME_OPTIONS.map((theme) => (
                  <option key={theme} value={theme}>
                    {theme}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="config-actions">
            <button type="button" onClick={saveTheme}>Apply Theme</button>
          </div>
        </div>
      ) : null}

      {activeTab === "email" ? (
        <div role="tabpanel">
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
        </div>
      ) : null}

      {activeTab === "carddav" ? (
        <div className="config-carddav-layout" role="tabpanel">
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

          <div className="config-card">
            <h3>CardDAV Access</h3>
            <p className="config-muted">
              Point a CardDAV-capable app (iOS/macOS Contacts, Nextcloud, Thunderbird, or the KyPost mobile app) at
              the address below using an app-specific password — never your account login password.
            </p>
            {davURL ? (
              <div className="contacts-dav-url">
                <code>{davURL}</code>
              </div>
            ) : null}
            <div className="contacts-dav-status">
              {davStatus?.configured ? (
                <span className="contacts-badge contacts-status-active">
                  <span className="contacts-dot" aria-hidden="true" />
                  app password configured
                </span>
              ) : (
                <span className="contacts-badge contacts-status-inactive">
                  <span className="contacts-dot" aria-hidden="true" />
                  no app password yet
                </span>
              )}
            </div>
            {revealedPassword ? (
              <div className="contacts-dav-reveal">
                <p className="config-muted">
                  Copy this now — it will not be shown again. Use it as the password for the CardDAV account above.
                </p>
                <div className="contacts-dav-secret">
                  <code>{revealedPassword}</code>
                  <button type="button" onClick={copyDavPassword}>
                    Copy
                  </button>
                </div>
                {copyStatus ? <p className="config-muted">{copyStatus}</p> : null}
              </div>
            ) : null}
            <div className="config-actions">
              <button type="button" onClick={() => void generateDavPassword()} disabled={davBusy}>
                {davBusy ? "Working..." : davStatus?.configured ? "Regenerate Password" : "Generate Password"}
              </button>
              {davStatus?.configured ? (
                <button type="button" onClick={() => void revokeDavPassword()} disabled={davBusy}>
                  Revoke
                </button>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}

      {activeTab === "labels" && isAdmin ? (
        <div className="config-card" role="tabpanel">
          <h3>Label Rules</h3>
          <p className="config-muted">One label per line. Use keyword mappings to route alternate IMAP keywords.</p>
          <div className="config-grid">
            <label>
              <div>Allowlist</div>
              <textarea rows={10} value={allowlistText} onChange={(event) => setAllowlistText(event.target.value)} className="config-textarea" />
            </label>
            <label>
              <div>Keyword Mappings (Label: Keyword1, Keyword2)</div>
              <textarea
                rows={8}
                value={keywordMappingText}
                onChange={(event) => setKeywordMappingText(event.target.value)}
                className="config-textarea"
              />
            </label>
          </div>
          <div className="config-actions">
            <button type="button" onClick={applyImapLabelsToAllowlist}>Merge IMAP Labels</button>
            <button type="button" onClick={saveConfig}>Save Configuration</button>
          </div>
          <p className="config-muted">{labelsFromImap.length > 0 ? `Discovered IMAP labels: ${labelsFromImap.join(", ")}` : "No IMAP labels discovered yet."}</p>
        </div>
      ) : null}

      {activeTab === "llm" && isAdmin ? (
        <div className="config-card" role="tabpanel">
          <h3>Remote LLM Model</h3>
          <p className="config-muted">Connection settings for model classification calls.</p>
          <div className="config-grid config-grid-two">
            <label>
              <div>Base URL</div>
              <input value={cfg.classifier.baseUrl} onChange={(event) => updateConfig("classifier", { ...cfg.classifier, baseUrl: event.target.value })} />
            </label>
            <label>
              <div>Classify Path</div>
              <input
                value={cfg.classifier.classifyPath}
                onChange={(event) => updateConfig("classifier", { ...cfg.classifier, classifyPath: event.target.value })}
              />
            </label>
            <label>
              <div>API Key</div>
              <input
                type="password"
                value={cfg.classifier.apiKey}
                onChange={(event) => updateConfig("classifier", { ...cfg.classifier, apiKey: event.target.value })}
                placeholder="Leave blank to keep the existing key"
              />
              <p className="config-muted">
                {cfg.classifier.apiKeySet ? "An API key is currently configured." : "No API key is configured yet."}
              </p>
            </label>
          </div>
          <div className="config-actions">
            <button type="button" onClick={saveConfig}>Save Configuration</button>
            <button type="button" onClick={runClassifierTest} disabled={classifierTestBusy}>
              {classifierTestBusy ? "Testing..." : "Run Classifier Test"}
            </button>
          </div>
          {classifierTestResult ? <pre className="config-pre">{classifierTestResult}</pre> : null}
        </div>
      ) : null}

      {activeTab === "wkd" && isAdmin ? (
        <div className="config-card" role="tabpanel">
          <h3>WKD key publishing (domains)</h3>
          <p className="config-muted">
            Web Key Directory (WKD) lets other mail clients look up a user's PGP key automatically, without it
            being shared directly. Verifying a domain here proves this instance controls its DNS, and lets any
            user on that domain publish their key there (each user opts in individually on their Security page).
          </p>

          {wkdLoading ? (
            <p className="config-muted">Loading...</p>
          ) : wkdDomains.length > 0 ? (
            <div className="config-status-card">
              {wkdDomains.map((d) => {
                const record = wkdDomainRecord(d);
                return (
                  <div key={d.domain} style={{ padding: "10px 0" }}>
                    <div className="security-card-head">
                      <span>{d.domain}</span>
                      <span className={`security-badge ${d.verified ? "security-badge-on" : "security-badge-off"}`}>
                        <span className="security-dot" aria-hidden="true" />
                        {d.verified ? "verified" : "unverified"}
                      </span>
                    </div>
                    {d.verified ? (
                      <p className="config-muted">
                        Also make sure <code>openpgpkey.{d.domain}</code> points at this server (DNS or a
                        tunnel) so key lookups actually resolve.
                      </p>
                    ) : (
                      <>
                        <p className="config-muted">Add this DNS TXT record to prove control of {d.domain}:</p>
                        <p className="config-muted">
                          Name: <code>{record.name}</code>{" "}
                          <button type="button" onClick={() => copyWKDText(record.name)}>
                            Copy
                          </button>
                        </p>
                        <p className="config-muted">
                          Value: <code>{record.value}</code>{" "}
                          <button type="button" onClick={() => copyWKDText(record.value)}>
                            Copy
                          </button>
                        </p>
                      </>
                    )}
                    <div className="security-actions">
                      {!d.verified ? (
                        <button type="button" disabled={wkdBusy} onClick={() => void runWKDDomainVerify(d.domain)}>
                          Verify
                        </button>
                      ) : null}
                      <button
                        type="button"
                        className="security-action-danger"
                        disabled={wkdBusy}
                        onClick={() => void removeWKDDomain(d.domain)}
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="config-muted">No domains published yet.</p>
          )}

          <div className="config-grid config-grid-two">
            <label>
              <div>Domain to publish keys for</div>
              <input
                value={wkdNewDomain}
                onChange={(event) => setWkdNewDomain(event.target.value)}
                placeholder="example.com"
              />
            </label>
          </div>
          <div className="config-actions">
            <button type="button" onClick={() => void addWKDDomain()} disabled={wkdBusy || wkdNewDomain.trim() === ""}>
              {wkdBusy ? "Working..." : "Add domain"}
            </button>
          </div>
          {wkdStatus ? <p className="config-muted">{wkdStatus}</p> : null}
        </div>
      ) : null}

      {configStatus ? <p className={configStatusTone}>{configStatus}</p> : null}
    </section>
  );
}
