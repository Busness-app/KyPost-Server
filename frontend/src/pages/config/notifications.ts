// The Notifications tab's shapes and the two pure decisions it makes: what a
// stored preferences blob means, and which keywords are offerable. Pure — no
// React — so the fail-closed reading of a settings file written by an older
// server is testable on its own.

import { uniqueLabels, type AppConfig } from "../../api/config";

// Per-user delivery preferences, stored server-side per account (the global
// config no longer carries notification mode/keywords).
export type NotificationPrefs = {
  mode: "all" | "keywords" | "none";
  keywords: string[];
  // Off by default. See the copy rendered next to this toggle, and
  // UserNotificationSettings.ContentPreview on the server, for why.
  contentPreview: boolean;
};

export type NotificationVapidResponse = {
  publicKey: string;
};

export type NotificationTestResponse = {
  ok: boolean;
  subscriptions: number;
  sent: number;
  failed: number;
  removedStale?: number;
  activeSubscriptions?: number;
  nativeDevices?: number;
  nativeSent?: number;
  nativeFailed?: number;
  nativeRemovedStale?: number;
  nativeError?: string;
};

export function normalizePrefs(input: unknown): NotificationPrefs {
  const source = (input ?? {}) as Record<string, unknown>;
  const mode = source.mode === "all" || source.mode === "keywords" ? source.mode : "none";
  const keywords = Array.isArray(source.keywords) ? source.keywords.map(String) : [];
  // Anything other than an explicit true is off: an older settings file with
  // no such field must read as private, not as opted in.
  const contentPreview = source.contentPreview === true;
  return { mode, keywords, contentPreview };
}

/**
 * Every keyword worth offering as a notification trigger.
 *
 * `selected` is folded in so a keyword the account already notifies on stays
 * visible (and stays checked) after it is dropped from the allowlist or
 * disappears from IMAP — otherwise the option vanishes while the preference
 * behind it survives on the server, and the only way to turn it off is to
 * guess that it is still there.
 *
 * Takes the IMAP label array rather than the whole /api/labels response so it
 * can read ConfigPage's existing `labelsFromImap` state instead of forcing a
 * second fetch.
 */
export function collectNotificationKeywordOptions(
  cfg: AppConfig,
  imapLabels: string[],
  selected: string[]
): string[] {
  const configured = cfg.labels.allowlist ?? [];
  const mapped = Object.values(cfg.labels.keywordMappings ?? {}).flat();
  return uniqueLabels([...configured, ...mapped, ...imapLabels, ...selected]);
}

/**
 * Whether switching away from "none" on this browser should warn about sleep
 * state. Mobile browsers suspend service workers aggressively enough that a
 * newly enabled subscription silently delivers nothing.
 */
export function shouldWarnAboutSleepState(
  previousMode: NotificationPrefs["mode"],
  nextMode: NotificationPrefs["mode"],
  userAgent: string
): boolean {
  if (previousMode !== "none" || nextMode === "none") {
    return false;
  }
  return /Android|iPhone|iPad|iPod|Mobile/i.test(userAgent);
}
