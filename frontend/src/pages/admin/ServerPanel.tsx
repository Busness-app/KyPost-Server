import { PanelTabs } from "../../components/PanelTabs";
import { ApplicationRuntime } from "../../admin/sections/ApplicationRuntime";
import { WkdDomains } from "../../admin/sections/WkdDomains";
import { LabelRules } from "../../admin/sections/LabelRules";
import { Users } from "../../admin/sections/Users";

/**
 * Server-level settings: how the instance runs, what it can prove it owns,
 * and who can sign in to it.
 *
 * WKD domain verification lives here rather than with Automation because
 * proving DNS control over a mail domain is identity infrastructure, not
 * classification. The per-user "publish my key" opt-in is a different control
 * and stays on Security.
 *
 * Label rules are here for the same reason: the allowlist is instance-wide and
 * saved through PUT /api/config, which is withAdmin. Automation holds only
 * per-user settings.
 */
export function ServerPanel() {
  return (
    <section className="panel">
      <div className="config-header">
        <h2>Server</h2>
        <p>Runtime behaviour, updates, verified mail domains, and user accounts.</p>
      </div>
      <PanelTabs
        ariaLabel="Server sections"
        tabs={[
          { id: "runtime", label: "Application", body: <ApplicationRuntime /> },
          { id: "label-rules", label: "Label Rules", body: <LabelRules /> },
          { id: "wkd-domains", label: "WKD Domains", body: <WkdDomains /> },
          { id: "users", label: "Manage Users", body: <Users /> }
        ]}
      />
    </section>
  );
}
