// The old standalone health route. The dashboard itself now lives in
// settings/sections/SystemHealth so both Status (trimmed, everyone) and
// Diagnostics (full, admin) can compose it; this page is the shell that keeps
// /health working until that route becomes a redirect.
//
// It passes `full` from the caller's role, which is what the two inline
// `auth.role === "admin"` checks used to decide.
import { useAuth } from "../auth";
import { SystemHealth } from "../settings/sections/SystemHealth";

export function HealthPage() {
  const auth = useAuth();
  return (
    <section className="panel health-page-panel">
      <SystemHealth full={auth.role === "admin"} />
    </section>
  );
}
