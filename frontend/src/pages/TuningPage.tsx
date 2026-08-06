// The old standalone prompt-tuning route. The UI now lives in
// admin/sections/PromptTuning so the Automation panel can compose it; this page
// is the shell that keeps /tuning working until that route becomes a redirect.
import { PromptTuning } from "../admin/sections/PromptTuning";

export function TuningPage() {
  return (
    <section className="panel">
      <PromptTuning />
    </section>
  );
}
