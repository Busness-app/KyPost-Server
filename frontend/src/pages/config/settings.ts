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
