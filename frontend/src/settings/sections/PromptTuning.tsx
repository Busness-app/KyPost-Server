import { useEffect, useState } from "react";
import { getJSON, putJSON } from "../../api/client";
import { loadLabelPrefs, saveLabelPrefsPatch } from "./labelPrefs";

type TuningResponse = {
  content: string;
  path?: string;
};

type TuningSaveResponse = {
  ok: boolean;
  path?: string;
  restartOk?: boolean;
  restartError?: string;
};

type OllamaVersionResponse = {
  installedVersion: string;
  latestVersion: string;
  upgradeAvailable: boolean;
  checkedAt?: string;
  error?: string;
};

/**
 * The account's own labelling instructions.
 *
 * Per-user, not per-instance: every user has their own TUNING.md and their own
 * auto-apply preference, and both endpoints are withAuth. The Ollama version
 * above them is read-only instance information — shown here because it is what
 * decides whether these instructions are being followed by a current model.
 */
export function PromptTuning() {
  const [tuningText, setTuningText] = useState("");
  const [tuningStatus, setTuningStatus] = useState("");
  const [autoApplyEnabled, setAutoApplyEnabled] = useState(true);
  const [labelPrefsStatus, setLabelPrefsStatus] = useState("");
  const [ollamaVersion, setOllamaVersion] = useState<OllamaVersionResponse | null>(null);
  const [ollamaVersionError, setOllamaVersionError] = useState("");

  async function toggleAutoApply(enabled: boolean) {
    const previous = autoApplyEnabled;
    setAutoApplyEnabled(enabled);
    try {
      // Read-merge-write: this endpoint replaces the account's whole label
      // block, so sending only this field would blank their label list.
      await saveLabelPrefsPatch({ autoApplyEnabled: enabled });
      setLabelPrefsStatus(
        enabled
          ? "Automatic keyword labeling enabled."
          : "Automatic keyword labeling disabled — new mail will be tagged with your default label only."
      );
    } catch {
      setAutoApplyEnabled(previous);
      setLabelPrefsStatus("Failed to update labeling preference.");
    }
  }

  async function saveTuning() {
    try {
      const result = await putJSON<TuningSaveResponse>("/api/tuning", { content: tuningText });
      setTuningStatus(
        result.restartOk === false
          ? `Tuning saved, but classifier restart needs attention: ${result.restartError ?? "unknown restart failure"}`
          : "TUNING.md saved and classifier restarted."
      );
    } catch {
      setTuningStatus("Failed to save tuning file.");
    }
  }

  useEffect(() => {
    getJSON<TuningResponse>("/api/tuning")
      .then((tuningData) => {
        setTuningText(tuningData.content ?? "");
      })
      .catch(() => setTuningStatus("Failed to load tuning settings."));
  }, []);

  useEffect(() => {
    loadLabelPrefs()
      .then((prefs) => setAutoApplyEnabled(prefs.autoApplyEnabled))
      .catch(() => setLabelPrefsStatus("Failed to load labeling preference."));
  }, []);

  useEffect(() => {
    getJSON<OllamaVersionResponse>("/api/ollama/version")
      .then((data) => {
        setOllamaVersion(data);
        setOllamaVersionError("");
      })
      .catch(() => setOllamaVersionError("Checking installed Ollama version..."));
  }, []);

  return (
    <>
      <div style={{ marginBottom: "1.5em" }}>
        <h3>Ollama Version</h3>
        {ollamaVersion ? (
          <>
            <p>Installed version: {ollamaVersion.installedVersion || "unknown"}</p>
            {ollamaVersion.upgradeAvailable ? (
              <p className="notice notice-warning">
                A newer Ollama version ({ollamaVersion.latestVersion}) is available upstream. This container
                doesn't update itself — rebuild and redeploy it to pick up the newer Ollama. The admin has
                been emailed about this.
              </p>
            ) : (
              <p className="config-muted">You're running the latest available Ollama version.</p>
            )}
          </>
        ) : (
          <p className="config-muted">{ollamaVersionError || "Loading Ollama version..."}</p>
        )}
      </div>

      <div>
        <h3>TUNING.md</h3>
        <p>Edit and save the markdown instructions used for message labeling.</p>

        <div style={{ marginBottom: "1em" }}>
          <label style={{ display: "flex", alignItems: "center", gap: "0.5em" }}>
            <input
              type="checkbox"
              checked={autoApplyEnabled}
              onChange={(e) => toggleAutoApply(e.target.checked)}
            />
            Automatically apply keyword labels
          </label>
          <p className="config-muted">
            When off, the AI classifier is skipped and every new message is tagged with your default label ("Primary" if configured, otherwise your first configured label) only.
          </p>
          {labelPrefsStatus ? <p>{labelPrefsStatus}</p> : null}
        </div>

        <label>
          <div>TUNING.md</div>
          <textarea rows={18} value={tuningText} onChange={(e) => setTuningText(e.target.value)} style={{ width: "100%" }} />
        </label>

        <button type="button" onClick={saveTuning}>Save TUNING.md</button>
        {tuningStatus ? <p>{tuningStatus}</p> : null}
      </div>
    </>
  );
}
