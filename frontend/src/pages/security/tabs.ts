// Security's tabs. Pure, so the URL-to-tab fallback is testable.

/**
 * The questions the page answers, in the order they render.
 *
 * These are the eyebrow labels the cards already carried — "Approvals" is gone
 * because approving a sign-in is something a device does, so it belongs with the
 * devices rather than beside them.
 *
 * CardDAV access is its own tab rather than a card under Devices: it is a
 * credential you issue for an app, not a device you paired, and it owns a
 * one-time secret whose loss is unrecoverable — which is hard to notice
 * appended below a device list.
 */
export const SECURITY_TABS = ["signin", "devices", "carddav", "mail"] as const;

export type SecurityTab = (typeof SECURITY_TABS)[number];

export const SECURITY_TAB_LABELS: Record<SecurityTab, string> = {
  signin: "Sign-in",
  devices: "Devices",
  carddav: "CardDAV",
  mail: "Mail"
};

/** Falls back to Sign-in for anything unrecognised, so a bad link still renders. */
export function resolveSecurityTab(raw: string | null): SecurityTab {
  const value = (raw ?? "").trim();
  return SECURITY_TABS.includes(value as SecurityTab) ? (value as SecurityTab) : "signin";
}
