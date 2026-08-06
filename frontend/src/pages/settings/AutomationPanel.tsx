import { PanelTabs } from "../../components/PanelTabs";
import { MyLabels } from "../../settings/sections/MyLabels";
import { PromptTuning } from "../../settings/sections/PromptTuning";
import { Decisions } from "../../settings/sections/Decisions";

/**
 * How this account's mail gets classified and labelled.
 *
 * Everything here is per-user — each account has its own label list, its own
 * TUNING.md, its own auto-apply preference and its own decision log, and every
 * endpoint behind them is withAuth. Nothing on this panel is admin-gated.
 *
 * The instance HOUSE list on Server is a different thing: it is what a new
 * account's list is copied from, not what any existing account uses.
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
          { id: "labels", label: "Your Labels", body: <MyLabels /> },
          { id: "prompt-tuning", label: "Prompt Tuning", body: <PromptTuning /> },
          { id: "decisions", label: "Decisions", body: <Decisions /> }
        ]}
      />
    </section>
  );
}
