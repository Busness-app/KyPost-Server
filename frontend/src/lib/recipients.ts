import type { Contact } from "../api/contacts";

export type RecipientToken = {
  email: string;
  name?: string;
  isCustom: boolean;
};

export type RecipientFieldState = {
  tokens: RecipientToken[];
  draft: string;
};

export function contactToToken(contact: Contact): RecipientToken | null {
  const email = contact.emails?.[0]?.value;
  if (!email) return null;
  return { email, name: contact.fn, isCustom: false };
}

export function serializeRecipientField(state: RecipientFieldState): string {
  return [...state.tokens.map((t) => t.email), state.draft.trim()].filter(Boolean).join(", ");
}

export function parseRecipientField(raw: string): RecipientFieldState {
  const tokens = raw
    .split(/[,;]/)
    .map((segment) => segment.trim())
    .filter(Boolean)
    .map((email) => ({ email, isCustom: true }));
  return { tokens, draft: "" };
}

export function isDuplicateInField(tokens: RecipientToken[], email: string): boolean {
  const normalized = email.trim().toLowerCase();
  return tokens.some((t) => t.email.toLowerCase() === normalized);
}

export function isPlausibleEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

/**
 * Splits a serialized recipient string into bare addresses, using the same
 * comma-or-semicolon rule parseRecipientField does. Callers that need a list
 * (e.g. per-recipient PGP key resolution) must use this rather than their own
 * split, or a semicolon-separated field silently becomes one malformed
 * address.
 */
export function splitAddressList(raw: string): string[] {
  return parseRecipientField(raw).tokens.map((t) => t.email);
}
