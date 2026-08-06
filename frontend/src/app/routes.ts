// Retired settings paths.
//
// These appear in docs, bookmarks, and — like the /notifications redirect that
// preceded them — in service workers cached inside installed PWAs, which can
// send a tap here long after the deploy. They redirect rather than 404.

const REDIRECTS: Record<string, string> = {
  "/config": "/settings/mail",
  "/notifications": "/settings/notifications",
  "/security": "/settings/security",
  // Panels are tabbed, so these point at a ?tab= rather than a #hash: the
  // section only exists in the DOM while its tab is the active one.
  "/rules": "/settings/mail?tab=rules",
  "/tuning": "/settings/automation?tab=prompt-tuning",
  "/users": "/admin/server?tab=users",
  "/logs": "/admin/diagnostics?tab=logs",
  // Automation shipped under /admin before it moved to Config. Prompt tuning
  // is per-user, so an admin-only path was wrong for it.
  "/admin/automation": "/settings/automation"
};

/** Every path this table retires, for wiring the Routes. */
export const LEGACY_SETTINGS_PATHS: ReadonlyArray<string> = [...Object.keys(REDIRECTS), "/health"];

/**
 * Old path -> new path, or null if the path is still live.
 *
 * /health splits on role because Status is the trimmed view and Diagnostics is
 * the full one; everything else maps the same way for everyone.
 */
export function legacySettingsRedirect(path: string, isAdmin: boolean): string | null {
  if (path === "/health") {
    return isAdmin ? "/admin/diagnostics" : "/settings/status";
  }
  return REDIRECTS[path] ?? null;
}
