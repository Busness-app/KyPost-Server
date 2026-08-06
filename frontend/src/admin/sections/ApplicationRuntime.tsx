import { useEffect, useMemo, useState } from "react";
import { getJSON } from "../../api/client";
import { normalizeConfig, type AppConfig } from "../../api/config";
import { applyTheme, getStoredTheme, THEME_OPTIONS, type ThemeName } from "../../theme";
import { LOG_LEVEL_OPTIONS, getTimezoneOptions } from "../../pages/config/settings";
import { saveConfigPatch } from "./configSave";

type ServerVersionResponse = {
  installedVersion: string;
  latestVersion: string;
  upgradeAvailable: boolean;
  checkedAt?: string;
  error?: string;
};

export function ApplicationRuntime() {
  const [cfg, setCfg] = useState<AppConfig | null>(null);
  const [configStatus, setConfigStatus] = useState("");
  const [selectedTheme, setSelectedTheme] = useState<ThemeName>(getStoredTheme());
  const [serverVersion, setServerVersion] = useState<ServerVersionResponse | null>(null);
  const [serverVersionError, setServerVersionError] = useState("");

  const configStatusTone = configStatus.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

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

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setSelectedTheme(getStoredTheme());
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
        return;
      }

      try {
        const status = await getJSON<ServerVersionResponse>("/api/server/version");
        if (!cancelled) {
          setServerVersion(status);
          setServerVersionError("");
        }
      } catch {
        if (!cancelled) setServerVersionError("Version check has not completed yet.");
      }
    };

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  function updateConfig<K extends keyof AppConfig>(key: K, value: AppConfig[K]) {
    setCfg((prev) => (prev ? { ...prev, [key]: value } : prev));
  }

  function saveTheme() {
    applyTheme(selectedTheme);
    setConfigStatus(`Theme set to ${selectedTheme}.`);
  }

  async function saveConfig() {
    if (!cfg) return;
    try {
      await saveConfigPatch({
        timezone: cfg.timezone,
        logLevel: cfg.logLevel,
        scan: cfg.scan,
        rateLimits: cfg.rateLimits
      });
      setConfigStatus("Configuration saved.");
    } catch {
      setConfigStatus("Failed to save configuration.");
    }
  }

  if (!cfg) {
    return null;
  }

  return (
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
      {configStatus ? <p className={configStatusTone}>{configStatus}</p> : null}
    </div>
  );
}
