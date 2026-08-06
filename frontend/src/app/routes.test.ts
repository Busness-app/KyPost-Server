import { describe, expect, it } from "vitest";
import { LEGACY_SETTINGS_PATHS, legacySettingsRedirect } from "./routes";

describe("legacySettingsRedirect", () => {
  it("sends every retired path somewhere real", () => {
    expect(legacySettingsRedirect("/config", false)).toBe("/settings/mail");
    expect(legacySettingsRedirect("/notifications", false)).toBe("/settings/notifications");
    expect(legacySettingsRedirect("/security", false)).toBe("/settings/security");
    expect(legacySettingsRedirect("/rules", false)).toBe("/settings/mail?tab=rules");
    expect(legacySettingsRedirect("/tuning", true)).toBe("/settings/automation?tab=prompt-tuning");
    expect(legacySettingsRedirect("/users", true)).toBe("/admin/server?tab=users");
    expect(legacySettingsRedirect("/logs", true)).toBe("/admin/diagnostics?tab=logs");
  });

  it("keeps the pre-move Automation path working, since it shipped once", () => {
    expect(legacySettingsRedirect("/admin/automation", true)).toBe("/settings/automation");
    expect(legacySettingsRedirect("/admin/automation", false)).toBe("/settings/automation");
  });

  it("splits health by role, because Status is the trimmed view", () => {
    expect(legacySettingsRedirect("/health", false)).toBe("/settings/status");
    expect(legacySettingsRedirect("/health", true)).toBe("/admin/diagnostics");
  });

  it("leaves live paths alone", () => {
    // /password is the forced-reset interstitial and /login the signed-out
    // front door. Redirecting either would strand a user who cannot yet
    // navigate anywhere else.
    expect(legacySettingsRedirect("/password", false)).toBeNull();
    expect(legacySettingsRedirect("/login", false)).toBeNull();
    expect(legacySettingsRedirect("/read", false)).toBeNull();
    expect(legacySettingsRedirect("/contacts", false)).toBeNull();
  });

  it("resolves every path it claims to retire, for both roles", () => {
    // The Routes are wired from this list, so an entry with no mapping would
    // render a redirect to the fallback instead of the panel that replaced it.
    for (const path of LEGACY_SETTINGS_PATHS) {
      for (const isAdmin of [true, false]) {
        expect(legacySettingsRedirect(path, isAdmin), path).not.toBeNull();
      }
    }
  });

  it("never redirects to a path that is itself retired", () => {
    for (const path of LEGACY_SETTINGS_PATHS) {
      for (const isAdmin of [true, false]) {
        const target = legacySettingsRedirect(path, isAdmin) ?? "";
        expect(LEGACY_SETTINGS_PATHS).not.toContain(target.split("?")[0].split("#")[0]);
      }
    }
  });
});
