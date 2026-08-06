// The old standalone Filters route. The rules UI itself now lives in
// settings/sections/Filters so the Mail panel can compose it; this page is the
// shell that keeps /rules working until that route becomes a redirect.
import { Filters } from "../settings/sections/Filters";

export function RulesPage() {
  return (
    <section className="panel security-page">
      <h2>Filter Rules</h2>
      <Filters />
    </section>
  );
}
