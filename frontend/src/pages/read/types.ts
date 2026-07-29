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
};

// DecryptedView is one locally-decrypted message: the plaintext body plus
// what the signature check found. Held in component state only, so it is
// gone on reload along with the key that produced it.
export type DecryptedView = {
  body: string;
  signed: boolean;
  verified: boolean;
  signerFingerprint: string;
  error: string;
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

