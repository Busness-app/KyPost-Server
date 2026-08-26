// Shared shapes for the read view: the message record the inbox API returns,
// its decrypted counterpart, and the list's sort/swipe state.
export type InboxEmail = {
  messageId: string;
  sender: string;
  sentTo?: string;
  cc?: string;
  bcc?: string;
  subject: string;
  body?: string;
  /**
   * Which MIME part `body` came from, as reported by the server. Absent means
   * the server could not know — a client-protected account's PGP mail, which
   * only this browser can decrypt, or a mail-cache entry written before the
   * field existed. Route it through displayBody (read/body.ts) rather than
   * reading it directly: this describes the message the server sent, and for a
   * client-protected account that is the envelope, not the plaintext.
   */
  bodyMode?: "html" | "plain";
  label?: string;
  keywords?: string[];
  status: string;
  detail?: string;
  atUtc: string;
  hasAttachments?: boolean;
  pgpEncrypted?: boolean;
  pgpSigned?: boolean;
  pgpVerified?: boolean;
  pgpSignerFingerprint?: string;
  pgpDecryptError?: string;
  /**
   * Only ever set on a `since=` delta response: "new" means the entry carries a
   * body and the client should insert it, "updated" means flags or label moved
   * and the body is deliberately absent because the client already has it.
   * Absent entirely on a full snapshot. See applyInboxDelta.
   */
  changeType?: "new" | "updated";
};

// DecryptedView is one locally-decrypted message: the plaintext body plus
// what the signature check found. Held in component state only, so it is
// gone on reload along with the key that produced it.
export type DecryptedView = {
  body: string;
  /**
   * Which MIME part `body` came from, read by pgpClient off the decrypted
   * entity's own Content-Type. Undefined only for inline PGP, which decrypts to
   * bare text with no MIME headers. Route it through displayBody, never
   * directly: the server's `bodyMode` describes the envelope and says nothing
   * about a plaintext only this browser has.
   */
  bodyMode?: "html" | "plain";
  signed: boolean;
  verified: boolean;
  signerFingerprint: string;
  error: string;
  /**
   * True when `body` was parsed out of bytes this browser cryptographically
   * checked — the decrypted plaintext, or the verified signed part.
   *
   * displayBody must branch on this and not on `body`'s truthiness. A signed
   * part can legitimately parse to nothing (an attachment-only signed message),
   * and the failure path deliberately stores an empty body with an empty error
   * so the reader keeps the message when a payload fetch fails. Those two look
   * identical without this flag, and treating the first like the second is what
   * let the server's render of an UNSIGNED third part appear under a
   * "signature verified" badge.
   */
  bodyFromVerifiedPart: boolean;
  /**
   * The address book holds a key for this sender whose fingerprint no longer
   * matches its TOFU pin. The server sends such an entry with no key material,
   * so verification cannot run — but the reason is a changed key, not a missing
   * one, and the badge says so.
   */
  signerConflict: boolean;
};

// AttachmentInfo mirrors the /api/mail/attachments wire shape.
export type AttachmentInfo = {
  index: number;
  name: string;
  mimeType: string;
  size: number;
};

export type ReadPageProps = {
  onOpenDraft?: (payload: { sentTo?: string; cc?: string; bcc?: string; subject?: string; body?: string }) => void;
};

export type InboxResponse = {
  tabs: string[];
  byTab: Record<string, InboxEmail[]>;
};

export type InboxAction = "delete" | "archive" | "spam" | "read";

export type InboxActionResponse = {
  ok: boolean;
  action: InboxAction;
  processed: number;
  failed: Array<{ messageId: string; error: string }>;
};

// KeywordActionResponse is the same /api/inbox/actions response shape used
// for the "label"/"unlabel" actions — a subset of InboxActionResponse since
// those aren't part of the InboxAction union. handleInboxActions always
// returns HTTP 200 and signals per-message failure via `failed`, so callers
// must check it explicitly rather than treating a 200 as success.
export type KeywordActionResponse = {
  failed: Array<{ messageId: string; error: string }>;
};

export type SortKey = "time" | "subject" | "sender";
export type SortDirection = "asc" | "desc";
export const EMAILS_PER_PAGE = 20;
export const SWIPE_HINT_THRESHOLD = 0.15;
export const SWIPE_ACTIVATE_THRESHOLD = 0.5;
export const SWIPE_DISMISS_RATIO = 1.08;
export const SWIPE_MAX_OFFSET_RATIO = 0.92;
export const SWIPE_HAPTICS_STORAGE_KEY = "kypost-read-swipe-haptics-enabled";

export type SwipeTone = "archive" | "delete";
export type SwipeRowState = {
  offset: number;
  phase: "dragging" | "snapback" | "dismiss";
  tone: SwipeTone;
  showHint: boolean;
  armed: boolean;
};

