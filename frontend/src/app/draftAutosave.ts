// Autosave for the compose window.
//
// This saves to sessionStorage, NOT to the server, and the "not to the server"
// half is forced by what the server's draft endpoint is. POST /api/mail/draft is a bare IMAP APPEND
// (see imap.APIClient.SaveDraft): it returns no UID and has no replace, so
// autosaving there would append a brand-new message on every tick — dozens of
// copies of one half-written email in the Drafts folder. It also rejects a
// draft with no recipient, which is exactly the state a compose window is in
// for its first minute.
//
// Browser-side storage also covers strictly more failure modes than a server
// draft would: a crashed tab, a closed window and a reload all lose the compose
// buffer, and none of them involve the server at all.
//
// SESSION storage, not local. What is stored is the PLAINTEXT of a message the
// user may be about to PGP-encrypt — body, recipients, subject and attachment
// names — and localStorage keeps that on disk until something deletes it, which
// on a shared workstation, a profile backup, or a machine that is simply not
// re-opened is "indefinitely". sessionStorage is scoped to the tab: it survives
// the cases this feature actually exists for (a reload, a crash restore, a
// reopened-closed-tab) and dies with the tab in the cases it was never worth
// keeping plaintext for. The one case it gives up is a deliberate browser quit
// and restart; that is the trade, and it is the direction the product's
// end-to-end claim has to lean.
//
// Explicit "Save Draft" still writes a real IMAP draft. This is the safety
// net underneath it, not a replacement.
//
// Neither store is encrypted, so same-origin XSS reads it either way — that is
// not what changed here. What changed is how long the plaintext outlives the
// session that produced it.

import type { ComposeAttachment } from "./types";

/** Bump when the stored shape changes; a mismatch discards rather than guesses. */
const SNAPSHOT_VERSION = 1;

/**
 * How long a snapshot stays restorable before it is discarded on sight.
 *
 * The tab bounds the plaintext's lifetime; this bounds it inside a long-lived
 * tab, which a PWA left open for days is. clearDraftSnapshot on logout does not
 * cover that: a user who neither logs out nor closes the tab skips it, and
 * those are precisely the cases this feature exists to survive.
 *
 * The bound is enforced from two places, and it needs both:
 * purgeExpiredDraftSnapshots at startup and hourly, and a check on read.
 * Reading alone is not an expiry — loadDraftSnapshot is called only when a
 * blank compose window is opened, so a user who never composes again would
 * never trigger it.
 */
const MAX_SNAPSHOT_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * Keyed per user. A shared browser must not hand one account's unsent draft to
 * whoever logs in next — clearDraftSnapshot on logout is the primary defence,
 * but the key means a missed clear still cannot cross accounts.
 */
const KEY_PREFIX = "kypost-compose-draft:";

function storageKey(userId: string): string {
  return `${KEY_PREFIX}${userId}`;
}

/** The single place that names which Storage holds draft plaintext. */
function draftStorage(): Storage {
  return window.sessionStorage;
}

/** isExpired centralises the age rule for both the read path and the sweep. */
function isExpired(savedAt: unknown, now: number): boolean {
  const savedAtMs = Date.parse(typeof savedAt === "string" ? savedAt : "");
  // An unparseable or absent savedAt is treated as expired rather than as
  // "fresh": a snapshot whose age cannot be established is exactly the one that
  // has been sitting there since before this check existed, and it is plaintext.
  return !Number.isFinite(savedAtMs) || now - savedAtMs > MAX_SNAPSHOT_AGE_MS;
}

/**
 * purgeExpiredDraftSnapshots deletes every expired snapshot in this origin,
 * for every user, and is what makes MAX_SNAPSHOT_AGE_MS an actual bound inside
 * a tab that stays open.
 *
 * Expiring on read alone bounds nothing. loadDraftSnapshot runs in one place —
 * opening a BLANK compose window — so the plaintext of a message the user may
 * have been about to PGP-encrypt is deleted only if they come back and start
 * another one. Sweeping at startup and hourly means the age limit holds while
 * the app is open at all, and sweeping ALL keys rather than the current user's
 * covers the shared browser where the previous account never signs in again.
 *
 * It also deletes every draft key in localStorage OUTRIGHT, regardless of age.
 * Nothing writes them any more; what is there was written by a version that
 * stored draft plaintext persistently, and leaving it would mean the switch to
 * sessionStorage protected only drafts written after the upgrade.
 */
export function purgeExpiredDraftSnapshots(now: number = Date.now()): void {
  try {
    const storage = draftStorage();
    // Collect first: removeItem reindexes the store, so deleting while walking
    // it by index skips entries.
    const expired: string[] = [];
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (!key?.startsWith(KEY_PREFIX)) continue;
      let savedAt: unknown = null;
      try {
        savedAt = (JSON.parse(storage.getItem(key) ?? "") as Partial<DraftSnapshot>)?.savedAt;
      } catch {
        // Unparseable is unreadable is unrestorable — and it is still
        // plaintext, so it goes.
      }
      if (isExpired(savedAt, now)) {
        expired.push(key);
      }
    }
    for (const key of expired) {
      storage.removeItem(key);
    }
  } catch {
    // Storage disabled or unavailable. See saveDraftSnapshot.
  }
  purgeLegacyPersistentDrafts();
}

/** purgeLegacyPersistentDrafts removes draft plaintext left in localStorage by
 *  versions that stored it there. Age is not consulted: no age makes persistent
 *  plaintext of an unsent encrypted message worth keeping. */
function purgeLegacyPersistentDrafts(): void {
  try {
    const storage = window.localStorage;
    const stale: string[] = [];
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (key?.startsWith(KEY_PREFIX)) stale.push(key);
    }
    for (const key of stale) {
      storage.removeItem(key);
    }
  } catch {
    // Storage disabled or unavailable. See saveDraftSnapshot.
  }
}

export type DraftSnapshot = {
  version: number;
  to: string;
  cc: string;
  bcc: string;
  subject: string;
  body: string;
  /**
   * Names only — attachment BYTES are deliberately not stored. Web storage
   * caps around 5 MB per origin and one attachment may be 25 MB
   * (MAX_ATTACHMENT_BYTES), so storing them would blow the quota and take the
   * whole snapshot with it. Keeping the names lets the restore notice say what
   * has to be re-attached instead of silently dropping them.
   */
  attachmentNames: string[];
  savedAt: string;
};

export type DraftInput = {
  to: string;
  cc: string;
  bcc: string;
  subject: string;
  body: string;
  attachments: ComposeAttachment[];
};

/**
 * hasContent reports whether a draft is worth saving or restoring.
 *
 * Quill leaves an empty editor as "<p><br></p>", so a body check has to strip
 * markup before deciding — otherwise every freshly opened compose window looks
 * like unsaved work and stomps a real snapshot with an empty one.
 */
export function hasContent(draft: DraftInput): boolean {
  const bodyText = new DOMParser().parseFromString(draft.body, "text/html").body.textContent?.trim() ?? "";
  return Boolean(
    draft.to.trim() ||
      draft.cc.trim() ||
      draft.bcc.trim() ||
      draft.subject.trim() ||
      bodyText ||
      draft.attachments.length
  );
}

/**
 * saveDraftSnapshot persists a draft, or clears the stored one when the draft
 * is empty. Never throws: a quota error or a browser with storage disabled
 * must not surface as an exception in the middle of typing.
 */
export function saveDraftSnapshot(userId: string, draft: DraftInput): void {
  if (!userId) return;
  try {
    if (!hasContent(draft)) {
      draftStorage().removeItem(storageKey(userId));
      return;
    }
    const snapshot: DraftSnapshot = {
      version: SNAPSHOT_VERSION,
      to: draft.to,
      cc: draft.cc,
      bcc: draft.bcc,
      subject: draft.subject,
      body: draft.body,
      attachmentNames: draft.attachments.map((a) => a.name),
      savedAt: new Date().toISOString()
    };
    draftStorage().setItem(storageKey(userId), JSON.stringify(snapshot));
  } catch {
    // Storage full, disabled, or unavailable (private mode). Autosave is a
    // best-effort safety net; losing it must not cost the user their typing.
  }
}

/** loadDraftSnapshot returns the stored draft, or null if there is none, it is
 *  unreadable, or it was written by a different version. */
export function loadDraftSnapshot(userId: string): DraftSnapshot | null {
  if (!userId) return null;
  try {
    const raw = draftStorage().getItem(storageKey(userId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<DraftSnapshot>;
    if (parsed?.version !== SNAPSHOT_VERSION) {
      draftStorage().removeItem(storageKey(userId));
      return null;
    }
    // Expire on read as well as on the startup sweep: this is the path that
    // must never hand back a stale draft, whatever the sweep did or didn't
    // catch (storage written by another tab since startup, a clock change).
    if (isExpired(parsed.savedAt, Date.now())) {
      draftStorage().removeItem(storageKey(userId));
      return null;
    }
    return {
      version: SNAPSHOT_VERSION,
      to: parsed.to ?? "",
      cc: parsed.cc ?? "",
      bcc: parsed.bcc ?? "",
      subject: parsed.subject ?? "",
      body: parsed.body ?? "",
      attachmentNames: Array.isArray(parsed.attachmentNames)
        ? parsed.attachmentNames.filter((n): n is string => typeof n === "string")
        : [],
      savedAt: parsed.savedAt ?? ""
    };
  } catch {
    return null;
  }
}

/**
 * clearDraftSnapshot drops the stored draft. Called when the work is safe
 * (sent, or written to a real IMAP draft) or deliberately abandoned (trashed),
 * and on logout so the next person at this browser cannot read it.
 */
export function clearDraftSnapshot(userId: string): void {
  if (!userId) return;
  try {
    draftStorage().removeItem(storageKey(userId));
  } catch {
    // See saveDraftSnapshot.
  }
}

/** restoreNotice describes what was recovered, naming any attachments that
 *  could not be, so the user re-attaches them rather than sending without. */
export function restoreNotice(snapshot: DraftSnapshot): string {
  const base = "Restored your unsent draft.";
  if (snapshot.attachmentNames.length === 0) {
    return base;
  }
  return `${base} Attachments were not saved — re-attach: ${snapshot.attachmentNames.join(", ")}`;
}
