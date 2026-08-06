// Security's tabs. Pure, so the URL-to-tab fallback is testable.

/**
 * The three questions the page answers, in the order they render.
 *
 * These are the eyebrow labels the cards already carried — "Approvals" is gone
 * because approving a sign-in is something a device does, so it belongs with the
 * devices rather than beside them.
 */
export const SECURITY_TABS = ["signin", "devices", "mail"] as const;

export type SecurityTab = (typeof SECURITY_TABS)[number];

export const SECURITY_TAB_LABELS: Record<SecurityTab, string> = {
  signin: "Sign-in",
  devices: "Devices",
  mail: "Mail"
};

/** Falls back to Sign-in for anything unrecognised, so a bad link still renders. */
export function resolveSecurityTab(raw: string | null): SecurityTab {
  const value = (raw ?? "").trim();
  return SECURITY_TABS.includes(value as SecurityTab) ? (value as SecurityTab) : "signin";
}
