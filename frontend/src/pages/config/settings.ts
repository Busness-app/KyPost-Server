// ConfigPage's local shapes and the text<->structure conversions its
// textarea-backed fields use. Pure — no React — so the parsing that turns
// operator-typed text into label lists and mappings is testable on its own.

import { uniqueLabels } from "../../api/config";
import type { SendAsAlias } from "../../api/sendas";

export type LabelsResponse = {
  configured: string[];
  imap: string[];
};

export type IMAPConfigStatus = {
  configured: boolean;
  path?: string;
  keyPath?: string;
  host?: string;
  port?: number;
  username?: string;
  mailbox?: string;
  smtpHost?: string;
  smtpPort?: number;
  updatedAt?: string;
  encryptedAtRest?: boolean;
};

export type IMAPForm = {
  host: string;
  port: number;
  username: string;
  password: string;
  mailbox: string;
  smtpHost: string;
  smtpPort: number;
};

export const LOG_LEVEL_OPTIONS = ["trace", "debug", "info", "warn", "error", "fatal", "panic"];

/**
 * The Configuration tabs, in the order they render.
 *
 * `notifications` sits with `email` and `carddav` in the everyone-sees-it set
 * because notification delivery is a per-account preference, not system
 * configuration — the admin-only tabs are the ones backed by the global config.
 */
export const CONFIG_TABS = [
  "application",
  "email",
  "carddav",
  "notifications",
  "labels",
  "llm",
  "wkd"
] as const;

export type ConfigTab = (typeof CONFIG_TABS)[number];

const ADMIN_ONLY_TABS: ReadonlySet<ConfigTab> = new Set<ConfigTab>([
  "application",
  "labels",
  "llm",
  "wkd"
]);

/**
 * Which tab a `?tab=` value should open.
 *
 * Falls back rather than trusting the URL, in both directions: an unrecognised
 * value and an admin-only tab requested by a non-admin both land on that user's
 * default tab. Returning the raw value would render a page with a tab strip and
 * no panel under it, which reads as a broken page rather than as a bad link —
 * and the non-admin case is reachable by pasting a colleague's URL, not just by
 * typing nonsense.
 */
export function resolveConfigTab(raw: string | null, isAdmin: boolean): ConfigTab {
  const fallback: ConfigTab = isAdmin ? "application" : "email";
  const value = (raw ?? "").trim();
  if (!CONFIG_TABS.includes(value as ConfigTab)) {
    return fallback;
  }
  const tab = value as ConfigTab;
  return ADMIN_ONLY_TABS.has(tab) && !isAdmin ? fallback : tab;
}

export function formatWhen(value?: string): string {
  if (!value) {
    return "";
  }
  const when = new Date(value);
  if (Number.isNaN(when.getTime())) {
    return "";
  }
  return when.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

export function sendAsStatusLabel(status: SendAsAlias["status"]): string {
  switch (status) {
    case "verified":
      return "verified";
    case "failed":
      return "verification failed";
    default:
      return "verifying…";
  }
}

export function sendAsStatusClass(status: SendAsAlias["status"]): string {
  switch (status) {
    case "verified":
      return "contacts-status-active";
    case "failed":
      return "contacts-status-failed";
    default:
      return "contacts-status-pending";
  }
}

export function getTimezoneOptions(): string[] {
  const intlWithSupportedValues = Intl as typeof Intl & {
    supportedValuesOf: (key: "timeZone") => string[];
  };
  return intlWithSupportedValues.supportedValuesOf("timeZone");
}

export function labelsToText(labels: string[]): string {
  return labels.join("\n");
}

export function textToLabels(raw: string): string[] {
  return uniqueLabels(raw.split(/\r?\n/));
}

export function mappingToText(mapping: Record<string, string[]>): string {
  return Object.keys(mapping)
    .sort((a, b) => a.localeCompare(b))
    .map((label) => `${label}: ${uniqueLabels(mapping[label] ?? []).join(", ")}`)
    .join("\n");
}

export function textToMapping(raw: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const splitAt = trimmed.indexOf(":");
    if (splitAt <= 0) {
      continue;
    }
    const label = trimmed.slice(0, splitAt).trim();
    const values = uniqueLabels(trimmed.slice(splitAt + 1).split(","));
    if (label && values.length > 0) {
      out[label] = values;
    }
  }
  return out;
}
