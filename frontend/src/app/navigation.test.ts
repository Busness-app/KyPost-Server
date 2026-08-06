import { describe, expect, it } from "vitest";
import { visibleSettingsGroups, settingsNavItems } from "./navigation";

describe("visibleSettingsGroups", () => {
  it("gives a non-admin one unheaded group, so no header labels a lone list", () => {
    const groups = visibleSettingsGroups(false);
    expect(groups).toHaveLength(1);
    expect(groups[0].heading).toBeUndefined();
    expect(groups[0].items.map((i) => i.label)).toEqual([
      "Appearance",
      "Mail",
      "Security",
      "Notifications",
      "Status"
    ]);
  });

  it("gives an admin two headed groups", () => {
    const groups = visibleSettingsGroups(true);
    expect(groups.map((g) => g.heading)).toEqual(["Config", "Admin"]);
    expect(groups[1].items.map((i) => i.label)).toEqual(["Server", "Automation", "Diagnostics"]);
  });

  it("hides Status from admins, who have Diagnostics instead", () => {
    const labels = visibleSettingsGroups(true).flatMap((g) => g.items.map((i) => i.label));
    expect(labels).not.toContain("Status");
    expect(labels).toContain("Diagnostics");
  });

  it("drops the Login entry, which redirected signed-in users to the inbox", () => {
    for (const isAdmin of [true, false]) {
      const routes = visibleSettingsGroups(isAdmin).flatMap((g) => g.items.map((i) => i.to));
      expect(routes).not.toContain("/login");
      expect(routes).not.toContain("/password");
    }
  });

  it("routes every item under /settings or /admin", () => {
    for (const isAdmin of [true, false]) {
      for (const group of visibleSettingsGroups(isAdmin)) {
        for (const item of group.items) {
          expect(item.to).toMatch(/^\/(settings|admin)\//);
        }
      }
    }
  });

  it("keeps the deprecated shim pointing at routes that currently exist", () => {
    // The sidebar still renders settingsNavItems. visibleSettingsGroups points at
    // /settings/* and /admin/*, which App.tsx does not route yet.
    for (const item of settingsNavItems) {
      expect(item.to).not.toMatch(/^\/(settings|admin)\//);
    }
  });
});
