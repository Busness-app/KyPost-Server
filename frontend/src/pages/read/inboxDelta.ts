// Folding a since= cursor response into the window the client already holds.
//
// Split out of ReadPage so the merge rules are testable on their own: they are
// where a delta can silently lose mail, and "the row vanished" is not something
// a render test reliably catches.
import type { InboxEmail } from "./types";

export type InboxDeltaResponse = {
  tabs?: string[];
  byTab?: Record<string, InboxEmail[]>;
  delta?: boolean;
  cursor?: number;
  removed?: string[];
};

// applyInboxDelta returns the next byTab for a delta response. The server sends
// only what changed — entries it re-sends, and `removed` for messages that left
// the window — so anything it does not mention must survive untouched.
//
// An entry is re-filed rather than patched in place: a keyword change moves a
// message to a different tab, and patching would leave a copy in the old one.
export function applyInboxDelta(
  current: Record<string, InboxEmail[]>,
  delta: InboxDeltaResponse
): Record<string, InboxEmail[]> {
  const previous = new Map<string, InboxEmail>();
  Object.values(current).forEach((items) => {
    items.forEach((item) => previous.set(item.messageId, item));
  });

  const gone = new Set(delta.removed ?? []);
  const incoming = new Map<string, { tab: string; email: InboxEmail }>();
  Object.entries(delta.byTab ?? {}).forEach(([tab, items]) => {
    items.forEach((email) => incoming.set(email.messageId, { tab, email }));
  });

  const next: Record<string, InboxEmail[]> = {};
  // Seed the scaffold the response declares so a tab that just emptied still
  // renders as an empty tab instead of disappearing from the strip.
  (delta.tabs ?? []).forEach((tab) => {
    next[tab] = [];
  });
  Object.entries(current).forEach(([tab, items]) => {
    next[tab] = (next[tab] ?? []).concat(
      items.filter((item) => !gone.has(item.messageId) && !incoming.has(item.messageId))
    );
  });

  incoming.forEach(({ tab, email }, messageId) => {
    if (gone.has(messageId)) return;
    const prior = previous.get(messageId);
    // changeType "updated" carries no body on purpose — the client already has
    // it. Take everything else from the server; only the body is ours to keep.
    const merged = prior && !email.body ? { ...email, body: prior.body, bodyMode: prior.bodyMode } : email;
    next[tab] = (next[tab] ?? []).concat(merged);
  });

  return next;
}

// messageIDsIn is the flattened id set of a window, for pruning state keyed by
// message id (selection, swipe-hidden rows) against what actually survived.
export function messageIDsIn(byTab: Record<string, InboxEmail[]>): Set<string> {
  const ids = new Set<string>();
  Object.values(byTab).forEach((items) => items.forEach((item) => ids.add(item.messageId)));
  return ids;
}

// withoutMessages drops every named message from every tab — the optimistic
// half of an inbox action, applied the moment the server accepts it rather
// than after a reload confirms it.
export function withoutMessages(
  byTab: Record<string, InboxEmail[]>,
  messageIds: string[]
): Record<string, InboxEmail[]> {
  const gone = new Set(messageIds);
  const next: Record<string, InboxEmail[]> = {};
  Object.entries(byTab).forEach(([tab, items]) => {
    next[tab] = items.filter((item) => !gone.has(item.messageId));
  });
  return next;
}
