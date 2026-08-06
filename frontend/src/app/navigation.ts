// The settings sidebar's groups and the build version shown in the license
// overlay. Data, not behaviour — kept out of App.tsx so adding a panel is a
// one-line edit in an obvious place.

// Bump this when releasing a new build. Shown in the license overlay.
export const APP_VERSION = 1;

export type SettingsNavItem = { to: string; label: string };

export type SettingsNavGroup = {
  /** Rendered only when more than one group is visible. */
  heading?: string;
  items: ReadonlyArray<SettingsNavItem>;
};

/** Panels anyone can reach. Status is the trimmed health view. */
const CONFIG_ITEMS: ReadonlyArray<SettingsNavItem> = [
  { to: "/settings/appearance", label: "Appearance" },
  { to: "/settings/mail", label: "Mail" },
  { to: "/settings/security", label: "Security" },
  { to: "/settings/notifications", label: "Notifications" },
  // Automation is Config, not Admin: prompt tuning is per-user (its endpoints
  // are all withAuth, and every user has their own TUNING.md). The panel hides
  // its admin-only Label Rules tab from non-admins.
  { to: "/settings/automation", label: "Automation" }
];

const STATUS_ITEM: SettingsNavItem = { to: "/settings/status", label: "Status" };

const ADMIN_ITEMS: ReadonlyArray<SettingsNavItem> = [
  { to: "/admin/server", label: "Server" },
  { to: "/admin/diagnostics", label: "Diagnostics" }
];

/**
 * A non-admin sees one flat list: a heading would be labelling the only group
 * there is. An admin sees Config and Admin, and loses Status because
 * Diagnostics is the same page without the trimming.
 */
export function visibleSettingsGroups(isAdmin: boolean): ReadonlyArray<SettingsNavGroup> {
  if (!isAdmin) {
    return [{ items: [...CONFIG_ITEMS, STATUS_ITEM] }];
  }
  return [
    { heading: "Config", items: CONFIG_ITEMS },
    { heading: "Admin", items: ADMIN_ITEMS }
  ];
}
