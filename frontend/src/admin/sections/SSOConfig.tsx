import { FormEvent, useEffect, useState } from "react";
import { getJSON, putJSON, toErrorMessage } from "../../api/client";

type SSOSettings = {
  enabled: boolean;
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  autoProvision: boolean;
};

export function SSOConfig() {
  const [settings, setSettings] = useState<SSOSettings>({
    enabled: false,
    issuerUrl: "",
    clientId: "",
    clientSecret: "",
    autoProvision: true,
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    getJSON<SSOSettings>("/api/admin/sso")
      .then((data) => {
        setSettings(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(toErrorMessage(err, "Failed to load SSO configuration"));
        setLoading(false);
      });
  }, []);

  const applyPreset = (issuer: string, client: string) => {
    setSettings((prev) => ({
      ...prev,
      enabled: true,
      issuerUrl: issuer,
      clientId: client,
      autoProvision: true,
    }));
  };

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    setMessage("");
    setError("");

    try {
      await putJSON("/api/admin/sso", settings);
      setMessage("SSO settings saved successfully.");
    } catch (err) {
      setError(toErrorMessage(err, "Failed to save SSO settings"));
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return <p className="muted">Loading SSO settings…</p>;
  }

  return (
    <form onSubmit={handleSave} className="config-section">
      <div className="section-head">
        <h3>Single Sign-On & OIDC Provider</h3>
        <p className="muted">
          Connect KySignOn, Authentik, Keycloak, or any standard OpenID Connect provider for centralized authentication.
        </p>
      </div>

      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1.25rem", flexWrap: "wrap" }}>
        <button
          type="button"
          className="button secondary sm"
          onClick={() => applyPreset("https://auth.urlxl.com", "kypost")}
        >
          + KySignOn Preset
        </button>
      </div>

      <div className="field-group">
        <label className="checkbox-label" style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={settings.enabled}
            onChange={(e) => setSettings({ ...settings, enabled: e.target.checked })}
          />
          <strong>Enable Single Sign-On (SSO)</strong>
        </label>
      </div>

      <div className="field-group">
        <label htmlFor="sso_issuer">Issuer URL</label>
        <input
          id="sso_issuer"
          type="url"
          className="input font-mono"
          placeholder="https://auth.urlxl.com"
          value={settings.issuerUrl}
          onChange={(e) => setSettings({ ...settings, issuerUrl: e.target.value })}
          required={settings.enabled}
        />
        <span className="muted" style={{ fontSize: "0.75rem", marginTop: "0.25rem", display: "block" }}>
          The OIDC base issuer URL supporting <code>.well-known/openid-configuration</code>.
        </span>
      </div>

      <div className="field-group">
        <label htmlFor="sso_client_id">OAuth Client ID</label>
        <input
          id="sso_client_id"
          type="text"
          className="input font-mono"
          placeholder="kypost"
          value={settings.clientId}
          onChange={(e) => setSettings({ ...settings, clientId: e.target.value })}
          required={settings.enabled}
        />
      </div>

      <div className="field-group">
        <label htmlFor="sso_client_secret">Client Secret (optional for PKCE public clients)</label>
        <input
          id="sso_client_secret"
          type="password"
          className="input font-mono"
          placeholder="••••••••"
          value={settings.clientSecret || ""}
          onChange={(e) => setSettings({ ...settings, clientSecret: e.target.value })}
        />
      </div>

      <div className="field-group">
        <label className="checkbox-label" style={{ display: "flex", alignItems: "center", gap: "0.5rem", cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={settings.autoProvision}
            onChange={(e) => setSettings({ ...settings, autoProvision: e.target.checked })}
          />
          <span>Auto-provision new accounts upon successful SSO authentication</span>
        </label>
      </div>

      {message ? <p className="status-success" style={{ color: "#4deeea" }}>{message}</p> : null}
      {error ? <p className="status-error" style={{ color: "#ef4444" }}>{error}</p> : null}

      <div className="actions" style={{ marginTop: "1rem" }}>
        <button type="submit" className="button" disabled={saving}>
          {saving ? "Saving…" : "Save SSO Settings"}
        </button>
      </div>
    </form>
  );
}
