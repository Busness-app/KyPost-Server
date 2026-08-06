import { useAuth } from "../../auth";
import { PanelTabs, type PanelTab } from "../../components/PanelTabs";
import { LabelRules } from "../../admin/sections/LabelRules";
import { PromptTuning } from "../../admin/sections/PromptTuning";

/**
 * How mail gets classified and labelled.
 *
 * Under Config rather than Admin because prompt tuning is a per-user setting —
 * every signed-in user has their own TUNING.md and their own decision log, and
 * the endpoints behind them are all withAuth. Label rules are the admin half,
 * so that tab appears only for admins; the server enforces it regardless,
 * since saving them is a PUT /api/config, which is withAdmin.
 */
export function AutomationPanel() {
  const auth = useAuth();

  const tabs: PanelTab[] = [{ id: "prompt-tuning", label: "Prompt Tuning", body: <PromptTuning /> }];
  if (auth.role === "admin") {
    tabs.push({ id: "label-rules", label: "Label Rules", body: <LabelRules /> });
  }

  return (
    <section className="panel">
      <div className="config-header">
        <h2>Automation</h2>
        <p>How mail is classified and labelled.</p>
      </div>
      <PanelTabs ariaLabel="Automation sections" tabs={tabs} />
    </section>
  );
}
