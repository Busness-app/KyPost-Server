import { PanelTabs } from "../../components/PanelTabs";
import { ApplicationRuntime } from "../../admin/sections/ApplicationRuntime";
import { SSOConfig } from "../../admin/sections/SSOConfig";
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
 * The default label list is here for the same reason: it is the house list a
 * new account is seeded from, saved through PUT /api/config (withAdmin). Each
 * account's OWN labels live on Email Labels and are not affected by it.
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
          { id: "sso", label: "Single Sign-On (SSO)", body: <SSOConfig /> },
          { id: "label-rules", label: "Default Labels", body: <LabelRules /> },
          { id: "wkd-domains", label: "WKD Domains", body: <WkdDomains /> },
          { id: "users", label: "Manage Users", body: <Users /> }
        ]}
      />
    </section>
  );
}
