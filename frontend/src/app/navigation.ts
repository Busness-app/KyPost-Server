// The settings sidebar's items and the build version shown in the license
// overlay. Data, not behaviour — kept out of App.tsx so adding a settings
// page is a one-line edit in an obvious place.

// Bump this when releasing a new build. Shown in the license overlay.
export const APP_VERSION = 1;

export const settingsNavItems: ReadonlyArray<{ to: string; label: string; adminOnly?: boolean }> = [
  { to: "/login", label: "Login" },
  { to: "/health", label: "System Health" },
  { to: "/config", label: "Configuration" },
  { to: "/notifications", label: "Pairing" },
  { to: "/security", label: "Security" },
  { to: "/rules", label: "Filters" },
  { to: "/tuning", label: "Prompt Tuning" },
  { to: "/users", label: "Manage Users", adminOnly: true },
  { to: "/logs", label: "System Logs", adminOnly: true }
];
