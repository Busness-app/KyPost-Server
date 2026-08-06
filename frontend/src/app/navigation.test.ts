import { describe, expect, it } from "vitest";
import { visibleSettingsGroups } from "./navigation";

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
      "Automation",
      "Status"
    ]);
  });

  it("gives an admin two headed groups", () => {
    const groups = visibleSettingsGroups(true);
    expect(groups.map((g) => g.heading)).toEqual(["Config", "Admin"]);
    expect(groups[1].items.map((i) => i.label)).toEqual(["Server", "Diagnostics"]);
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

});

// The sidebar renders whatever this module returns, so an entry with no matching
// route in App.tsx is a dead link — which is exactly what shipped once during
// this restructure, when the nav pointed at panels that did not exist yet.
// Reading the router source is blunt, but it is the only thing that actually
// couples the two files.
describe("every nav target is routed", () => {
  it("has a Route in App.tsx for each item both roles can see", async () => {
    const { readFileSync } = await import("node:fs");
    // Relative to the vitest root (frontend/), not this file: import.meta.url
    // is not a file: URL under the jsdom environment.
    const app = readFileSync("src/App.tsx", "utf8");

    const targets = new Set(
      [true, false].flatMap((isAdmin) =>
        visibleSettingsGroups(isAdmin).flatMap((group) => group.items.map((item) => item.to))
      )
    );

    for (const target of targets) {
      expect(app, `no <Route path="${target}"> in App.tsx`).toContain(`path="${target}"`);
    }
  });
});

// Automation sits under Config, not Admin. Prompt tuning is per-user — every
// signed-in user has their own TUNING.md and decision log, and those endpoints
// are withAuth — so an admin-only entry would have locked users out of their
// own setting. The panel hides its admin-only Label Rules tab instead.
describe("Automation placement", () => {
  it("is reachable by a non-admin", () => {
    const routes = visibleSettingsGroups(false).flatMap((g) => g.items.map((i) => i.to));
    expect(routes).toContain("/settings/automation");
  });

  it("is not under /admin, which would imply a gate it does not have", () => {
    for (const isAdmin of [true, false]) {
      const automation = visibleSettingsGroups(isAdmin)
        .flatMap((g) => g.items)
        .find((i) => i.label === "Automation");
      expect(automation?.to).toBe("/settings/automation");
    }
  });
});
