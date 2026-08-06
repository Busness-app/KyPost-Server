// The old standalone logs route. The viewer now lives in admin/sections/Logs so
// the Diagnostics panel can compose it; this page is the shell that keeps /logs
// working until that route becomes a redirect.
import { Logs } from "../admin/sections/Logs";

export function LogsPage() {
  return (
    <section className="panel logs-page-panel">
      <h2 style={{ marginTop: 0 }}>Logs</h2>
      <Logs />
    </section>
  );
}
