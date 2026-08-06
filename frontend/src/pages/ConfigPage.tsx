import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { getJSON, postJSON, putJSON, toErrorMessage } from "../api/client";
import { normalizeConfig, type AppConfig } from "../api/config";
import { useAuth } from "../auth";

import { resolveConfigTab, type ConfigTab } from "./config/settings";
import { Appearance } from "../settings/sections/Appearance";
import { EmailServer } from "../settings/sections/EmailServer";
import { SendAs } from "../settings/sections/SendAs";
import { CardDavClient } from "../settings/sections/CardDavClient";
import { CardDavAccess } from "../settings/sections/CardDavAccess";
import { NotificationPrefs } from "../settings/sections/NotificationPrefs";
import { ApplicationRuntime } from "../admin/sections/ApplicationRuntime";
import { LabelRules } from "../admin/sections/LabelRules";
import { WkdDomains } from "../admin/sections/WkdDomains";

export function ConfigPage() {
  const testPrompt = "Email Address: test@example.com Subject Line: Classifier connectivity test Return only the label Updates";

  // Application, Labels, and Remote LLM settings are global/system-owned
  // and admin-only; every user manages their own Email (IMAP/SMTP) settings.
  const auth = useAuth();
  const isAdmin = auth.role === "admin";

  const [cfg, setCfg] = useState<AppConfig | null>(null);
  const [configStatus, setConfigStatus] = useState("");

  const [classifierTestBusy, setClassifierTestBusy] = useState(false);
  const [classifierTestResult, setClassifierTestResult] = useState("");
  // The tab lives in the URL so a link can open one and a reload keeps it —
  // which is also what lets the retired /notifications route redirect to the
  // Notifications tab instead of dumping the user on Email Settings.
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = resolveConfigTab(searchParams.get("tab"), isAdmin);
  // A just-generated CardDAV app password is shown exactly once and cannot
  // be re-fetched (see CardDavAccess). Switching tabs unmounts it and
  // destroys the only copy, so while one is on screen, tab switches are
  // blocked rather than allowed to silently discard it. The only way out is
  // CardDavAccess's own Copy/Done control, which clears this flag.
  const [davPasswordRevealed, setDavPasswordRevealed] = useState(false);
  const [tabSwitchBlockedMessage, setTabSwitchBlockedMessage] = useState("");
  useEffect(() => {
    if (!davPasswordRevealed) {
      setTabSwitchBlockedMessage("");
    }
  }, [davPasswordRevealed]);
  function setActiveTab(tab: ConfigTab) {
    if (davPasswordRevealed) {
      setTabSwitchBlockedMessage(
        "Copy or dismiss the generated CardDAV password before switching tabs — it will not be shown again."
      );
      return;
    }
    const next = new URLSearchParams(searchParams);
    next.set("tab", tab);
    // Replace, not push: switching tabs is not navigation, and pushing would
    // mean Back walks through every tab visited instead of leaving the page.
    setSearchParams(next, { replace: true });
  }
  const configStatusTone = configStatus.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

  // This banner is now fed only by tabs that still route status through
  // ConfigPage (Appearance, CardDavAccess, and this file's own Remote LLM
  // save) — Application/Labels/WKD each show their own local status inside
  // their own card. Switching tabs never unmounts ConfigPage (the tab lives
  // in a query param on the same route), so without this a message from one
  // tab would sit here indefinitely and could appear alongside a *different*
  // section's own fresh status line, reading as a duplicate notice.
  useEffect(() => {
    setConfigStatus("");
  }, [activeTab]);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const nextConfig = await getJSON<unknown>("/api/config");
        if (cancelled) {
          return;
        }
        setCfg(normalizeConfig(nextConfig));
      } catch {
        if (!cancelled) {
          setConfigStatus("Failed to load configuration data.");
        }
      }
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

    // The API key input is write-only (never populated from a loaded
    // config), so a non-empty value here can only mean the user just typed
    // a new one. Only send apiKey in that case — an empty string would
    // otherwise look like "clear the key" to a naive reader of the diff,
    // even though the server already preserves the existing key on empty.
    // apiKeySet is a response-only computed field; never send it back.
    const typedApiKey = cfg.classifier.apiKey.trim();
    const { apiKeySet: _apiKeySet, apiKey: _apiKey, ...classifierRest } = cfg.classifier;
    const classifierPayload = typedApiKey ? { ...classifierRest, apiKey: typedApiKey } : classifierRest;

    try {
      // ConfigPage's own `cfg` is a one-time snapshot from mount — it never
      // sees edits ApplicationRuntime/LabelRules make through their own
      // saveConfigPatch, and this component never unmounts on a tab switch
      // (the tab lives in a query param on the same route). Spreading the
      // stale `cfg` here would silently revert whatever those saved in the
      // meantime, so this reads fresh immediately before writing, same as
      // saveConfigPatch does.
      const current = normalizeConfig(await getJSON<unknown>("/api/config"));
      const payload = { ...current, classifier: classifierPayload };
      await putJSON<{ ok: boolean }>("/api/config", payload);
      setCfg({
        ...current,
        classifier: {
          ...classifierRest,
          apiKey: "",
          apiKeySet: typedApiKey ? true : current.classifier.apiKeySet
        }
      });
      setConfigStatus("Configuration saved.");
    } catch {
      setConfigStatus("Failed to save configuration.");
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

      {tabSwitchBlockedMessage ? (
        <p className="notice notice-error" role="alert">
          {tabSwitchBlockedMessage}
        </p>
      ) : null}

      {activeTab === "application" && isAdmin ? <ApplicationRuntime /> : null}

      {!isAdmin ? <Appearance onStatus={setConfigStatus} /> : null}

      {activeTab === "email" ? (
        <div role="tabpanel">
          <EmailServer />
          <SendAs />
        </div>
      ) : null}

      {activeTab === "carddav" ? (
        <div className="config-carddav-layout" role="tabpanel">
          <CardDavClient />
          <CardDavAccess setConfigStatus={setConfigStatus} onRevealedPasswordChange={setDavPasswordRevealed} />
        </div>
      ) : null}

      {activeTab === "notifications" ? <NotificationPrefs /> : null}

      {activeTab === "labels" && isAdmin ? <LabelRules /> : null}

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

      {activeTab === "wkd" && isAdmin ? <WkdDomains /> : null}

      {configStatus ? <p className={configStatusTone}>{configStatus}</p> : null}
    </section>
  );
}
