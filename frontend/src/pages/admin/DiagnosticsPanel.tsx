import { SystemHealth } from "../../settings/sections/SystemHealth";
import { Logs } from "../../admin/sections/Logs";

/**
 * The full health view plus the server logs. Status is the same dashboard with
 * `full` off, which is what non-admins get instead of this.
 */
export function DiagnosticsPanel() {
  return (
    <section className="panel health-page-panel">
      <div id="health"><SystemHealth full heading="Diagnostics" /></div>
      <div id="logs"><Logs /></div>
    </section>
  );
}
