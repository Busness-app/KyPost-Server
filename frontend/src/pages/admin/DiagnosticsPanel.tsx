import { PanelTabs } from "../../components/PanelTabs";
import { SystemHealth } from "../../settings/sections/SystemHealth";
import { Logs } from "../../admin/sections/Logs";

/**
 * The full health view plus the server logs. Status is the same dashboard with
 * `full` off, which is what non-admins get instead of this.
 */
export function DiagnosticsPanel() {
  return (
    <section className="panel health-page-panel">
      <PanelTabs
        ariaLabel="Diagnostics sections"
        tabs={[
          { id: "health", label: "System Health", body: <SystemHealth full heading="Diagnostics" /> },
          { id: "logs", label: "Logs", body: <Logs /> }
        ]}
      />
    </section>
  );
}
