import { SystemHealth } from "../../settings/sections/SystemHealth";

/**
 * The trimmed health view, for everyone.
 *
 * A non-admin needs to see that their own mail has stopped syncing; they do
 * not need the poll-now control or the client address. Admins get the full
 * view under Diagnostics instead, so this panel is hidden from them.
 */
export function StatusPanel() {
  return (
    <section className="panel health-page-panel">
      <SystemHealth full={false} heading="Status" />
    </section>
  );
}
