import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { getJSON, postJSON, putJSON, toErrorMessage } from "../api/client";
import { normalizeConfig, uniqueLabels, type AppConfig } from "../api/config";
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

import {
  LOG_LEVEL_OPTIONS,
  getTimezoneOptions,
  labelsToText,
  textToLabels,
  mappingToText,
  textToMapping,
  resolveConfigTab,
  type ConfigTab,
  type LabelsResponse
} from "./config/settings";
import { Appearance } from "../settings/sections/Appearance";
import { EmailServer } from "../settings/sections/EmailServer";
import { SendAs } from "../settings/sections/SendAs";
import { CardDavClient } from "../settings/sections/CardDavClient";
import { CardDavAccess } from "../settings/sections/CardDavAccess";
import { NotificationPrefs } from "../settings/sections/NotificationPrefs";

type ServerVersionResponse = {
  installedVersion: string;
  latestVersion: string;
  upgradeAvailable: boolean;
  checkedAt?: string;
  error?: string;
};

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
  const [serverVersion, setServerVersion] = useState<ServerVersionResponse | null>(null);
  const [serverVersionError, setServerVersionError] = useState("");

  const [classifierTestBusy, setClassifierTestBusy] = useState(false);
  const [classifierTestResult, setClassifierTestResult] = useState("");
  // The tab lives in the URL so a link can open one and a reload keeps it —
  // which is also what lets the retired /notifications route redirect to the
  // Notifications tab instead of dumping the user on Email Settings.
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = resolveConfigTab(searchParams.get("tab"), isAdmin);
  function setActiveTab(tab: ConfigTab) {
    const next = new URLSearchParams(searchParams);
    next.set("tab", tab);
    // Replace, not push: switching tabs is not navigation, and pushing would
    // mean Back walks through every tab visited instead of leaving the page.
    setSearchParams(next, { replace: true });
  }
  const configStatusTone = configStatus.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

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

  async function refreshWKDDomains() {
    try {
      const res = await listWKDDomains();
      setWkdDomains(res.domains);
    } catch (e) {
      setWkdStatus(`Failed to load domains: ${toErrorMessage(e, "unknown error")}`);
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
      const loaders = [refreshLabels().catch(() => undefined)];
      // WKD domain management is admin-only on the backend (s.withAdmin) —
      // skip the fetch entirely for non-admins rather than let it 403.
      if (isAdmin) {
        loaders.push(
          refreshWKDDomains().catch(() => undefined),
          getJSON<ServerVersionResponse>("/api/server/version")
            .then((status) => {
              if (!cancelled) {
                setServerVersion(status);
                setServerVersionError("");
              }
            })
            .catch(() => {
              if (!cancelled) setServerVersionError("Version check has not completed yet.");
            })
        );
      }
      await Promise.all(loaders);
    };

    load();
    return () => {
      cancelled = true;
    };
  }, []);

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

  function copyWKDText(text: string) {
    void navigator.clipboard?.writeText(text);
  }

  async function addWKDDomain() {
    const domain = wkdNewDomain.trim().toLowerCase();
    if (!domain) return;
    // Re-claiming an already-listed domain mints a fresh token and resets
    // Verified to false server-side (wkdpublish.Store.Create), instantly
    // unpublishing every user currently served under it until it's
    // re-verified — the same blast radius Remove already warns about, so
    // Add needs the same confirmation for the same case.
    if (
      wkdDomains.some((d) => d.domain === domain) &&
      !window.confirm(
        `${domain} is already claimed. Re-adding it mints a new verification token and immediately unpublishes every user's key at this domain until it's re-verified. Continue?`
      )
    ) {
      return;
    }
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
        <button type="button" role="tab" aria-selected={activeTab === "notifications"} className={`config-tab${activeTab === "notifications" ? " active" : ""}`} onClick={() => setActiveTab("notifications")}>Notifications</button>
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
          <div className="config-card" style={{ marginTop: 16 }}>
            <h3>KyPost Updates</h3>
            {serverVersion ? (
              <>
                <p>Installed version: {serverVersion.installedVersion || "unknown"}</p>
                {serverVersion.error ? (
                  <p className="notice notice-error">{serverVersion.error}</p>
                ) : serverVersion.upgradeAvailable ? (
                  <p className="notice notice-warning">
                    Version {serverVersion.latestVersion} is available. The primary admin has been emailed.
                  </p>
                ) : (
                  <p className="config-muted">You&apos;re running the latest available KyPost version.</p>
                )}
                {serverVersion.checkedAt ? <p className="config-muted">Last checked: {new Date(serverVersion.checkedAt).toLocaleString()}</p> : null}
              </>
            ) : (
              <p className="config-muted">{serverVersionError || "Checking for updates..."}</p>
            )}
            <p className="config-muted">
              Update from the host with <code>./scripts/update-host.sh</code>. To enable automatic updates, install the optional systemd timer described in the documentation.
            </p>
          </div>
        </div>
      ) : null}

      {!isAdmin ? <Appearance selectedTheme={selectedTheme} setSelectedTheme={setSelectedTheme} saveTheme={saveTheme} /> : null}

      {activeTab === "email" ? (
        <div role="tabpanel">
          <EmailServer refreshLabels={refreshLabels} />
          <SendAs />
        </div>
      ) : null}

      {activeTab === "carddav" ? (
        <div className="config-carddav-layout" role="tabpanel">
          <CardDavClient />
          <CardDavAccess setConfigStatus={setConfigStatus} />
        </div>
      ) : null}

      {activeTab === "notifications" ? <NotificationPrefs cfg={cfg} labelsFromImap={labelsFromImap} /> : null}

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
