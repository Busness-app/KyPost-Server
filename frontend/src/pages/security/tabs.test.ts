import { describe, expect, it } from "vitest";
import { SECURITY_TABS, SECURITY_TAB_LABELS, resolveSecurityTab } from "./tabs";

describe("resolveSecurityTab", () => {
  it("opens each real tab", () => {
    expect(resolveSecurityTab("signin")).toBe("signin");
    expect(resolveSecurityTab("devices")).toBe("devices");
    expect(resolveSecurityTab("carddav")).toBe("carddav");
    expect(resolveSecurityTab("mail")).toBe("mail");
  });

  it("falls back to sign-in for a missing or unrecognised tab", () => {
    expect(resolveSecurityTab(null)).toBe("signin");
    expect(resolveSecurityTab("")).toBe("signin");
    expect(resolveSecurityTab("approvals")).toBe("signin");
    expect(resolveSecurityTab("../../etc/passwd")).toBe("signin");
  });

  it("labels every tab, so the strip can never render a blank button", () => {
    for (const tab of SECURITY_TABS) {
      expect(SECURITY_TAB_LABELS[tab]).toBeTruthy();
    }
  });

  // The slug and the label are deliberately different here, and neither is
  // free to follow the other: `mail` is in ?tab= links that already exist, and
  // "Encryption" is what the tab actually holds.
  it("shows the PGP tab as Encryption while keeping its mail slug", () => {
    expect(SECURITY_TAB_LABELS.mail).toBe("Encryption");
    expect(resolveSecurityTab("mail")).toBe("mail");
  });
});
