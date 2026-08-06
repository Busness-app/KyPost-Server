import { PanelTabs } from "../../components/PanelTabs";
import { PromptTuning } from "../../settings/sections/PromptTuning";
import { Decisions } from "../../settings/sections/Decisions";

/**
 * How this account's mail gets classified and labelled.
 *
 * Everything here is per-user — each account has its own TUNING.md, its own
 * auto-apply preference and its own decision log, and every endpoint behind
 * them is withAuth. Nothing on this panel is admin-gated, and nothing that is
 * instance-wide belongs on it: the label allowlist is global config saved
 * through an admin-only PUT /api/config, so it lives on Server instead.
 */
export function AutomationPanel() {
  return (
    <section className="panel">
      <div className="config-header">
        <h2>Email Labels</h2>
        <p>How your mail is classified and labelled.</p>
      </div>
      <PanelTabs
        ariaLabel="Email Labels sections"
        tabs={[
          { id: "prompt-tuning", label: "Prompt Tuning", body: <PromptTuning /> },
          { id: "decisions", label: "Decisions", body: <Decisions /> }
        ]}
      />
    </section>
  );
}
