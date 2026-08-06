import { useEffect, useMemo, useState } from "react";
import { getJSON } from "../../api/client";
import { normalizeConfig, uniqueLabels } from "../../api/config";
import {
  labelsToText,
  textToLabels,
  mappingToText,
  textToMapping,
  type LabelsResponse
} from "../../pages/config/settings";
import { saveConfigPatch } from "./configSave";

export function LabelRules() {
  const [allowlistText, setAllowlistText] = useState("");
  const [keywordMappingText, setKeywordMappingText] = useState("");
  const [labelsFromImap, setLabelsFromImap] = useState<string[]>([]);
  const [configStatus, setConfigStatus] = useState("");

  const configStatusTone = configStatus.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

  const effectiveAllowlist = useMemo(() => {
    const cfgLabels = textToLabels(allowlistText);
    return uniqueLabels([...cfgLabels]);
  }, [allowlistText]);

  async function refreshLabels() {
    const labelsData = await getJSON<LabelsResponse>("/api/labels");
    setLabelsFromImap(uniqueLabels(labelsData.imap ?? []));
  }

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const nextConfig = await getJSON<unknown>("/api/config");
        if (cancelled) {
          return;
        }
        const normalized = normalizeConfig(nextConfig);
        setAllowlistText(labelsToText(normalized.labels.allowlist));
        setKeywordMappingText(mappingToText(normalized.labels.keywordMappings));
      } catch {
        if (!cancelled) {
          setConfigStatus("Failed to load configuration data.");
        }
        return;
      }

      await refreshLabels().catch(() => undefined);
    };

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  function applyImapLabelsToAllowlist() {
    const merged = uniqueLabels([...effectiveAllowlist, ...labelsFromImap]);
    setAllowlistText(labelsToText(merged));
    setConfigStatus("Merged discovered IMAP labels into allowlist (not yet saved).");
  }

  async function saveConfig() {
    try {
      await saveConfigPatch({
        labels: {
          allowlist: effectiveAllowlist,
          keywordMappings: textToMapping(keywordMappingText)
        }
      });
      setConfigStatus("Configuration saved.");
    } catch {
      setConfigStatus("Failed to save configuration.");
    }
  }

  return (
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
      {configStatus ? <p className={configStatusTone}>{configStatus}</p> : null}
    </div>
  );
}
