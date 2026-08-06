import { LabelRules } from "../../admin/sections/LabelRules";
import { PromptTuning } from "../../admin/sections/PromptTuning";

export function AutomationPanel() {
  return (
    <section className="panel">
      <div className="config-header">
        <h2>Automation</h2>
        <p>How mail is classified and labelled.</p>
      </div>
      <div id="label-rules"><LabelRules /></div>
      <div id="prompt-tuning"><PromptTuning /></div>
    </section>
  );
}
