import { ApplicationRuntime } from "../../admin/sections/ApplicationRuntime";
import { WkdDomains } from "../../admin/sections/WkdDomains";
import { Users } from "../../admin/sections/Users";

/**
 * Server-level settings: how the instance runs, what it can prove it owns,
 * and who can sign in to it.
 *
 * WKD domain verification lives here rather than with Automation because
 * proving DNS control over a mail domain is identity infrastructure, not
 * classification. The per-user "publish my key" opt-in is a different control
 * and stays on Security.
 */
export function ServerPanel() {
  return (
    <section className="panel">
      <div className="config-header">
        <h2>Server</h2>
        <p>Runtime behaviour, updates, verified mail domains, and user accounts.</p>
      </div>
      <div id="runtime"><ApplicationRuntime /></div>
      <div id="wkd-domains"><WkdDomains /></div>
      <div id="users"><Users /></div>
    </section>
  );
}
