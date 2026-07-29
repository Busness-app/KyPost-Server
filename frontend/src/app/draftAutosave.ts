// Autosave for the compose window.
//
// This saves to localStorage, NOT to the server, and that is forced by what
// the server's draft endpoint is. POST /api/mail/draft is a bare IMAP APPEND
// (see imap.APIClient.SaveDraft): it returns no UID and has no replace, so
// autosaving there would append a brand-new message on every tick — dozens of
// copies of one half-written email in the Drafts folder. It also rejects a
// draft with no recipient, which is exactly the state a compose window is in
// for its first minute.
//
// localStorage also covers strictly more failure modes than a server draft
// would: a crashed tab, a closed window, a browser restart, and a reboot all
// lose the compose buffer, and none of them involve the server at all.
//
// Explicit "Save Draft" still writes a real IMAP draft. This is the safety
// net underneath it, not a replacement.

import type { ComposeAttachment } from "./types";

/** Bump when the stored shape changes; a mismatch discards rather than guesses. */
const SNAPSHOT_VERSION = 1;

/**
 * How long a snapshot stays restorable before it is discarded on sight.
 *
 * This matters more here than in a typical autosave. The buffer being stored
 * is the PLAINTEXT of a message the user may be about to PGP-encrypt, and it
 * is stored unencrypted. clearDraftSnapshot on logout was the only thing that
 * ever removed it — but closing the tab, crashing, rebooting, or simply never
 * clicking Log Out all skip that path, and those are precisely the cases this
 * feature exists to survive. Without an expiry the plaintext of an
 * end-to-end-encrypted email sat in localStorage indefinitely.
 *
 * 24 hours keeps the actual recovery story (crash, accidental close, restart,
 * "I'll finish this after lunch") while bounding how long the plaintext can
 * outlive the session that produced it.
 */
const MAX_SNAPSHOT_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * Keyed per user. A shared browser must not hand one account's unsent draft to
 * whoever logs in next — clearDraftSnapshot on logout is the primary defence,
 * but the key means a missed clear still cannot cross accounts.
 */
function storageKey(userId: string): string {
  return `kypost-compose-draft:${userId}`;
}

export type DraftSnapshot = {
  version: number;
  to: string;
  cc: string;
  bcc: string;
  subject: string;
  body: string;
  /**
   * Names only — attachment BYTES are deliberately not stored. localStorage
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
  const bodyText = draft.body.replace(/<[^>]*>/g, "").replace(/&nbsp;/g, " ").trim();
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
      window.localStorage.removeItem(storageKey(userId));
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
    window.localStorage.setItem(storageKey(userId), JSON.stringify(snapshot));
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
    const raw = window.localStorage.getItem(storageKey(userId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<DraftSnapshot>;
    if (parsed?.version !== SNAPSHOT_VERSION) {
      window.localStorage.removeItem(storageKey(userId));
      return null;
    }
    // Expire on read. An unparseable or absent savedAt is treated as expired
    // rather than as "fresh": a snapshot whose age cannot be established is
    // exactly the one that has been sitting there since before this check
    // existed, and it is plaintext.
    const savedAtMs = Date.parse(parsed.savedAt ?? "");
    if (!Number.isFinite(savedAtMs) || Date.now() - savedAtMs > MAX_SNAPSHOT_AGE_MS) {
      window.localStorage.removeItem(storageKey(userId));
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
    window.localStorage.removeItem(storageKey(userId));
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
