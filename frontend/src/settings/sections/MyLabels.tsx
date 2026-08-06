import { useEffect, useMemo, useState } from "react";
import { getJSON } from "../../api/client";
import { uniqueLabels } from "../../api/config";
import {
  labelsToText,
  textToLabels,
  mappingToText,
  textToMapping,
  type LabelsResponse
} from "../../pages/config/settings";
import { loadLabelPrefs, saveLabelPrefsPatch } from "./labelPrefs";

/**
 * This account's own label set.
 *
 * Seeded from the instance house list the first time the account is seen, and
 * independent of it afterwards — an admin editing the house list does not
 * reach back into an account that already has its own.
 */
export function MyLabels() {
  const [allowlistText, setAllowlistText] = useState("");
  const [keywordMappingText, setKeywordMappingText] = useState("");
  const [labelsFromImap, setLabelsFromImap] = useState<string[]>([]);
  const [status, setStatus] = useState("");
  // Guards Save. Saving before the initial read has seeded the textareas would
  // PUT an empty allowlist over whatever this account actually has — and an
  // empty allowlist means nothing gets labelled at all.
  const [loaded, setLoaded] = useState(false);

  const statusTone = status.toLowerCase().includes("failed") ? "notice notice-error" : "notice notice-success";

  const effectiveAllowlist = useMemo(() => uniqueLabels([...textToLabels(allowlistText)]), [allowlistText]);

  async function refreshLabels() {
    const labelsData = await getJSON<LabelsResponse>("/api/labels");
    setLabelsFromImap(uniqueLabels(labelsData.imap ?? []));
  }

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const prefs = await loadLabelPrefs();
        if (cancelled) {
          return;
        }
        setAllowlistText(labelsToText(prefs.allowlist));
        setKeywordMappingText(mappingToText(prefs.keywordMappings));
        setLoaded(true);
      } catch {
        if (!cancelled) {
          setStatus("Failed to load your labels.");
        }
        return;
      }

      await refreshLabels().catch(() => undefined);
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  function applyImapLabelsToAllowlist() {
    const merged = uniqueLabels([...effectiveAllowlist, ...labelsFromImap]);
    setAllowlistText(labelsToText(merged));
    setStatus("Merged discovered IMAP labels into your list (not yet saved).");
  }

  async function save() {
    if (!loaded) return;
    try {
      await saveLabelPrefsPatch({
        allowlist: effectiveAllowlist,
        keywordMappings: textToMapping(keywordMappingText)
      });
      setStatus("Your labels were saved.");
    } catch {
      setStatus("Failed to save your labels.");
    }
  }

  return (
    <div className="config-card">
      <h3>Your labels</h3>
      <p className="config-muted">
        One label per line — these are the labels the classifier may choose from for your mail, applied as IMAP
        keywords. They started as a copy of the instance defaults and are yours to change; editing them affects
        nobody else. Use keyword mappings to route alternate IMAP keywords.
      </p>
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
        <button type="button" onClick={() => void save()} disabled={!loaded}>Save Labels</button>
      </div>
      <p className="config-muted">{labelsFromImap.length > 0 ? `Discovered IMAP labels: ${labelsFromImap.join(", ")}` : "No IMAP labels discovered yet."}</p>
      {status ? <p className={statusTone}>{status}</p> : null}
    </div>
  );
}
