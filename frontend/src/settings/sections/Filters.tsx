import { useEffect, useState } from "react";
import { getJSON, toErrorMessage } from "../../api/client";
import {
  type Action,
  type Condition,
  type MatchGroup,
  type Rule,
  type RunRulesResult,
  createRule,
  deleteRule,
  getRuleSieve,
  listRules,
  putRuleSieve,
  reorderRules,
  runRulesNow,
  updateRule
} from "../../api/rules";
import { RulesHelpModal } from "../../components/RulesHelpModal";
import { ACTION_TYPES, ruleActionsError } from "../../lib/ruleActions";

const FIELD_OPTIONS = ["from", "to", "cc", "bcc", "subject", "body", "keyword"] as const;
const COMPARATOR_OPTIONS = ["contains", "is", "matches", "regex"] as const;
const ACTION_TYPE_OPTIONS = ACTION_TYPES;

function actionNeedsValue(type: string): boolean {
  return type === "keyword" || type === "unkeyword" || type === "move";
}

function actionValueLabel(type: string): string {
  return type === "move" ? "Target folder" : "Keyword";
}

function summarizeCondition(c: Condition): string {
  if (c.group) {
    const joiner = c.group.op === "anyof" ? " OR " : " AND ";
    return "(" + c.group.conditions.map(summarizeCondition).join(joiner) + ")";
  }
  const neg = c.negate ? "NOT " : "";
  return `${neg}${c.field} ${c.comparator}${c.value ? ` "${c.value}"` : ""}`;
}

function summarizeAction(a: Action): string {
  switch (a.type) {
    case "keyword":
      return `add keyword "${a.value ?? ""}"`;
    case "unkeyword":
      return `remove keyword "${a.value ?? ""}"`;
    case "move":
      return `move to "${a.value ?? ""}"`;
    case "read":
      return "mark as read";
    case "archive":
      return "archive";
    case "spam":
      return "mark as spam";
    case "delete":
      return "delete";
    case "stop":
      return "stop processing further rules";
    default:
      return a.type;
  }
}

function summarizeRule(rule: Rule): string {
  const op = rule.match.op === "anyof" ? "ANY" : "ALL";
  const conditions = rule.match.conditions.map(summarizeCondition).join(", ") || "(no conditions)";
  const actions = rule.actions.map(summarizeAction).join(", ") || "(no actions)";
  return `If ${op} of: ${conditions} → ${actions}`;
}

function blankRule(): Partial<Rule> {
  return {
    name: "New rule",
    enabled: false,
    scope: {},
    match: { op: "allof", conditions: [{ field: "from", comparator: "contains", value: "" }] },
    actions: [{ type: "archive" }]
  };
}

export function Filters() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [draft, setDraft] = useState<Rule | null>(null);
  const [scriptMode, setScriptMode] = useState<Record<string, boolean>>({});
  const [scriptText, setScriptText] = useState<Record<string, string>>({});
  const [scriptError, setScriptError] = useState<Record<string, string>>({});
  const [scriptBusy, setScriptBusy] = useState<Record<string, boolean>>({});
  const [availableKeywords, setAvailableKeywords] = useState<string[]>([]);
  const [runFolder, setRunFolder] = useState("INBOX");
  const [runBusy, setRunBusy] = useState(false);
  const [runError, setRunError] = useState("");
  const [runResult, setRunResult] = useState<RunRulesResult | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [creatingRule, setCreatingRule] = useState(false);

  // The server rejects these outright (rules.ValidateRule); showing the reason
  // while the rule is being composed beats surfacing it as a 400 on Save.
  const draftActionsError = draft ? ruleActionsError(draft.actions) : "";

  async function loadRules() {
    setLoading(true);
    setError("");
    try {
      const list = await listRules();
      setRules(list);
    } catch (e) {
      setError(toErrorMessage(e, "failed to load rules"));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadRules();
    getJSON<{ configured: string[]; imap: string[] }>("/api/labels")
      .then((data) => {
        const merged = new Set([...(data.configured ?? []), ...(data.imap ?? [])]);
        setAvailableKeywords(Array.from(merged).sort());
      })
      .catch(() => setAvailableKeywords([]));
  }, []);

  async function handleCreateRule() {
    if (creatingRule) return;
    setCreatingRule(true);
    setError("");
    try {
      const created = await createRule(blankRule());
      await loadRules();
      setExpandedId(created.id);
      setDraft(created);
    } catch (e) {
      setError(toErrorMessage(e, "failed to create rule"));
    } finally {
      setCreatingRule(false);
    }
  }

  async function handleToggleEnabled(rule: Rule) {
    setError("");
    try {
      await updateRule(rule.id, { ...rule, enabled: !rule.enabled });
      await loadRules();
    } catch (e) {
      setError(toErrorMessage(e, "failed to update rule"));
    }
  }

  async function handleDeleteRule(id: string) {
    if (!window.confirm("Delete this rule?")) return;
    setError("");
    try {
      await deleteRule(id);
      if (expandedId === id) {
        setExpandedId(null);
        setDraft(null);
      }
      await loadRules();
    } catch (e) {
      setError(toErrorMessage(e, "failed to delete rule"));
    }
  }

  async function handleMove(index: number, direction: -1 | 1) {
    const target = index + direction;
    if (target < 0 || target >= rules.length) return;
    const ids = rules.map((r) => r.id);
    const [moved] = ids.splice(index, 1);
    ids.splice(target, 0, moved);
    setError("");
    try {
      await reorderRules(ids);
      await loadRules();
    } catch (e) {
      setError(toErrorMessage(e, "failed to reorder rules"));
    }
  }

  function beginEdit(rule: Rule) {
    setExpandedId(rule.id);
    setDraft(structuredClone(rule));
  }

  function updateDraftMatch(next: MatchGroup) {
    setDraft((current) => (current ? { ...current, match: next } : current));
  }

  function updateDraftCondition(index: number, patch: Partial<Condition>) {
    if (!draft) return;
    const conditions = draft.match.conditions.slice();
    conditions[index] = { ...conditions[index], ...patch };
    updateDraftMatch({ ...draft.match, conditions });
  }

  function addDraftCondition() {
    if (!draft) return;
    updateDraftMatch({
      ...draft.match,
      conditions: [...draft.match.conditions, { field: "from", comparator: "contains", value: "" }]
    });
  }

  function removeDraftCondition(index: number) {
    if (!draft) return;
    const conditions = draft.match.conditions.filter((_, i) => i !== index);
    updateDraftMatch({ ...draft.match, conditions });
  }

  function updateDraftAction(index: number, patch: Partial<Action>) {
    if (!draft) return;
    const actions = draft.actions.slice();
    actions[index] = { ...actions[index], ...patch };
    setDraft({ ...draft, actions });
  }

  // "keyword", not "archive": archive is visibility-changing and so must be the
  // rule's last action, which made the default for "+ Action" the one type that
  // is invalid to append to a rule that already ends in one.
  function addDraftAction() {
    if (!draft) return;
    setDraft({ ...draft, actions: [...draft.actions, { type: "keyword", value: "" }] });
  }

  function removeDraftAction(index: number) {
    if (!draft) return;
    setDraft({ ...draft, actions: draft.actions.filter((_, i) => i !== index) });
  }

  async function saveDraft() {
    if (!draft) return;
    setError("");
    try {
      await updateRule(draft.id, draft);
      setExpandedId(null);
      setDraft(null);
      await loadRules();
    } catch (e) {
      setError(toErrorMessage(e, "failed to save rule"));
    }
  }

  async function toggleScriptView(rule: Rule) {
    const nowOn = !scriptMode[rule.id];
    setScriptMode((current) => ({ ...current, [rule.id]: nowOn }));
    if (!nowOn) return;
    setScriptBusy((current) => ({ ...current, [rule.id]: true }));
    setScriptError((current) => ({ ...current, [rule.id]: "" }));
    try {
      const script = await getRuleSieve(rule.id);
      setScriptText((current) => ({ ...current, [rule.id]: script }));
    } catch (e) {
      setScriptError((current) => ({ ...current, [rule.id]: toErrorMessage(e, "failed to load script") }));
    } finally {
      setScriptBusy((current) => ({ ...current, [rule.id]: false }));
    }
  }

  async function saveScript(rule: Rule) {
    const text = scriptText[rule.id] ?? "";
    setScriptBusy((current) => ({ ...current, [rule.id]: true }));
    setScriptError((current) => ({ ...current, [rule.id]: "" }));
    try {
      await putRuleSieve(rule.id, text);
      await loadRules();
      // Keep the user's text in view (don't discard on success either) —
      // reload from the server's canonical re-compile so formatting
      // normalizes.
      const recompiled = await getRuleSieve(rule.id);
      setScriptText((current) => ({ ...current, [rule.id]: recompiled }));
    } catch (e) {
      // A parse error must NOT discard the user's edits — leave scriptText
      // exactly as they typed it, just show the error.
      setScriptError((current) => ({ ...current, [rule.id]: toErrorMessage(e, "failed to save script") }));
    } finally {
      setScriptBusy((current) => ({ ...current, [rule.id]: false }));
    }
  }

  async function handleRunNow() {
    setRunBusy(true);
    setRunError("");
    setRunResult(null);
    try {
      const result = await runRulesNow(runFolder.trim() || "INBOX");
      setRunResult(result);
    } catch (e) {
      setRunError(toErrorMessage(e, "failed to run rules"));
    } finally {
      setRunBusy(false);
    }
  }

  return (
    <>
      <header className="security-header">
        <p>Automatically tag, move, or act on incoming mail — rules run on every new message and can also be run on demand against existing mail.</p>
        <button type="button" className="contacts-action" onClick={() => setHelpOpen(true)}>
          How to write rules
        </button>
      </header>

      <RulesHelpModal isOpen={helpOpen} onClose={() => setHelpOpen(false)} />

      {error ? <p className="security-muted">{error}</p> : null}

      <div className="security-layout">
        <div className="security-card">
          <div className="security-card-head">
            <h3>Your rules</h3>
            <button type="button" onClick={handleCreateRule} disabled={creatingRule}>
              + New rule
            </button>
          </div>

          {loading ? <p className="security-muted">Loading…</p> : null}
          {!loading && rules.length === 0 ? <p className="security-muted">No rules yet.</p> : null}

          {rules.map((rule, index) => (
            <div className="security-section rule-row" key={rule.id}>
              <div className="rule-row-head">
                <label className="security-check">
                  <input type="checkbox" checked={rule.enabled} onChange={() => void handleToggleEnabled(rule)} />
                  <strong>{rule.name}</strong>
                </label>
                <div className="security-actions">
                  <button type="button" onClick={() => handleMove(index, -1)} disabled={index === 0}>
                    ↑
                  </button>
                  <button type="button" onClick={() => handleMove(index, 1)} disabled={index === rules.length - 1}>
                    ↓
                  </button>
                  <button type="button" onClick={() => beginEdit(rule)}>
                    Edit
                  </button>
                  <button type="button" onClick={() => void toggleScriptView(rule)}>
                    {scriptMode[rule.id] ? "Hide script" : "View as script"}
                  </button>
                  <button type="button" className="security-action-danger" onClick={() => void handleDeleteRule(rule.id)}>
                    Delete
                  </button>
                </div>
              </div>
              <p className="security-muted rule-summary">{summarizeRule(rule)}</p>

              {scriptMode[rule.id] ? (
                <div className="rule-script-editor">
                  {scriptBusy[rule.id] ? <p className="security-muted">Loading…</p> : null}
                  <textarea
                    className="rule-script-textarea"
                    value={scriptText[rule.id] ?? ""}
                    onChange={(e) => setScriptText((current) => ({ ...current, [rule.id]: e.target.value }))}
                    rows={8}
                    spellCheck={false}
                  />
                  {scriptError[rule.id] ? <p className="rule-script-error">{scriptError[rule.id]}</p> : null}
                  <div className="security-actions">
                    <button type="button" onClick={() => void saveScript(rule)} disabled={scriptBusy[rule.id]}>
                      Save script
                    </button>
                  </div>
                </div>
              ) : null}

              {expandedId === rule.id && draft ? (
                <div className="rule-builder">
                  {!draft.guiEditable ? (
                    <p className="security-muted">
                      This rule's conditions are too complex for the visual builder (hand-edited script with nested
                      groups) — use "View as script" above to edit it.
                    </p>
                  ) : (
                    <>
                      <label>
                        <div>Name</div>
                        <input
                          type="text"
                          value={draft.name}
                          onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                        />
                      </label>

                      <label>
                        <div>Match</div>
                        <select
                          value={draft.match.op}
                          onChange={(e) => updateDraftMatch({ ...draft.match, op: e.target.value })}
                        >
                          <option value="allof">ALL of the following (AND)</option>
                          <option value="anyof">ANY of the following (OR)</option>
                        </select>
                      </label>

                      {draft.match.conditions.map((c, i) => (
                        <div className="rule-condition-row" key={i}>
                          <label className="security-check">
                            <input
                              type="checkbox"
                              checked={!!c.negate}
                              onChange={(e) => updateDraftCondition(i, { negate: e.target.checked })}
                            />
                            NOT
                          </label>
                          <select value={c.field} onChange={(e) => updateDraftCondition(i, { field: e.target.value })}>
                            {FIELD_OPTIONS.map((f) => (
                              <option key={f} value={f}>
                                {f}
                              </option>
                            ))}
                          </select>
                          <select
                            value={c.comparator}
                            onChange={(e) => updateDraftCondition(i, { comparator: e.target.value })}
                          >
                            {COMPARATOR_OPTIONS.map((c2) => (
                              <option key={c2} value={c2}>
                                {c2}
                              </option>
                            ))}
                          </select>
                          <input
                            type="text"
                            value={c.value ?? ""}
                            onChange={(e) => updateDraftCondition(i, { value: e.target.value })}
                            placeholder="value"
                          />
                          <button type="button" onClick={() => removeDraftCondition(i)}>
                            Remove
                          </button>
                        </div>
                      ))}
                      <div className="security-actions">
                        <button type="button" onClick={addDraftCondition}>
                          + Condition
                        </button>
                      </div>

                      <div>Actions</div>
                      {draft.actions.map((a, i) => (
                        <div className="rule-action-row" key={i}>
                          <select value={a.type} onChange={(e) => updateDraftAction(i, { type: e.target.value })}>
                            {ACTION_TYPE_OPTIONS.map((t) => (
                              <option key={t} value={t}>
                                {t}
                              </option>
                            ))}
                          </select>
                          {actionNeedsValue(a.type) ? (
                            <input
                              type="text"
                              value={a.value ?? ""}
                              onChange={(e) => updateDraftAction(i, { value: e.target.value })}
                              placeholder={actionValueLabel(a.type)}
                              list={a.type !== "move" ? "rule-keyword-options" : undefined}
                            />
                          ) : null}
                          <button type="button" onClick={() => removeDraftAction(i)}>
                            Remove
                          </button>
                        </div>
                      ))}
                      <div className="security-actions">
                        <button type="button" onClick={addDraftAction}>
                          + Action
                        </button>
                      </div>
                      {draftActionsError ? <p className="rule-script-error">{draftActionsError}</p> : null}
                    </>
                  )}

                  <div className="security-actions">
                    <button
                      type="button"
                      onClick={saveDraft}
                      disabled={!draft.guiEditable || draftActionsError !== ""}
                    >
                      Save
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setExpandedId(null);
                        setDraft(null);
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : null}
            </div>
          ))}

          <datalist id="rule-keyword-options">
            {availableKeywords.map((kw) => (
              <option key={kw} value={kw} />
            ))}
          </datalist>
        </div>

        <div className="security-card">
          <div className="security-card-head">
            <h3>Run rules now</h3>
          </div>
          <div className="security-section">
            <p className="security-muted">
              Apply every enabled rule to existing mail in a folder right now, independent of the automatic poller.
            </p>
            <label>
              <div>Folder</div>
              <input type="text" value={runFolder} onChange={(e) => setRunFolder(e.target.value)} placeholder="INBOX" />
            </label>
            <div className="security-actions">
              <button type="button" onClick={() => void handleRunNow()} disabled={runBusy}>
                {runBusy ? "Running…" : "Run rules now"}
              </button>
            </div>
            {runError ? <p className="security-muted">{runError}</p> : null}
            {runResult ? (
              <ul className="rule-run-results">
                <li>Scanned: {runResult.scanned}</li>
                <li>Matched: {runResult.matched}</li>
                <li>Applied: {runResult.applied}</li>
                <li>Failed: {runResult.failed}</li>
              </ul>
            ) : null}
          </div>
        </div>
      </div>
    </>
  );
}
