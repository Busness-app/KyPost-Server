// Shapes App.tsx passes between the shell, the folder sidebar and the
// compose window.

export type BeforeInstallPromptEvent = Event & {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed"; platform: string }>;
};

export type InboxFolder = {
  path: string;
  deletable: boolean;
};

export type InboxFoldersResponse = {
  parent: string;
  folders: InboxFolder[];
};

export type CreateFolderResponse = {
  ok: boolean;
  parent: string;
  name: string;
  folder: string;
};

export type DeleteFolderResponse = {
  ok: boolean;
  parent: string;
  folder: string;
};

export type RenameFolderResponse = {
  ok: boolean;
  folder: string;
  renamed: string;
  parent: string;
};

export type MoveInboxActionResponse = {
  ok: boolean;
  action: "move";
  processed: number;
  failed: Array<{ messageId: string; error: string }>;
  targetMailbox: string;
};

export type DragMessagePayload = {
  messageIds: string[];
  mailbox: string;
};

export type DraftComposePayload = {
  sentTo?: string;
  cc?: string;
  bcc?: string;
  subject?: string;
  body?: string;
};

// ComposeAttachment mirrors the backend's attachment wire shape
// ({name, mimeType, dataBase64}) accepted by /api/mail/send and /api/mail/draft.
// size is kept client-side only, for the chip label and the 25 MB total cap.
export type ComposeAttachment = {
  name: string;
  mimeType: string;
  dataBase64: string;
  size: number;
};

