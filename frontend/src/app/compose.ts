// Attachment reading and the send-error decoding the compose window needs.
// Pure — no React — so the base64 stripping and the 409 shape are testable
// without mounting the app shell.

import { HttpError } from "../api/client";
import type { ComposeAttachment } from "./types";

// Mirror of the backend maxMailAttachmentBytes (25 MB total decoded).
export const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

// readFileAsAttachment reads a File and strips the "data:...;base64," prefix
// that FileReader.readAsDataURL prepends, yielding the raw base64 the API wants.
export function readFileAsAttachment(file: File): Promise<ComposeAttachment> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error(`failed to read ${file.name}`));
    reader.onload = () => {
      const result = typeof reader.result === "string" ? reader.result : "";
      const comma = result.indexOf(",");
      resolve({
        name: file.name,
        mimeType: file.type || "application/octet-stream",
        dataBase64: comma >= 0 ? result.slice(comma + 1) : result,
        size: file.size
      });
    };
    reader.readAsDataURL(file);
  });
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// Pulls the keyless-recipient list out of /api/mail/send's 409 body, if
// that's what this error is. Returns null for anything else (a different
// error shape, a non-JSON body, or a keyless list that came back empty) so
// the caller can fall back to the generic message.
export function keylessRecipientsFrom409(error: unknown): string[] | null {
  if (!(error instanceof HttpError) || error.status !== 409) return null;
  const body = error.body as { keylessRecipients?: unknown } | undefined;
  const list = body?.keylessRecipients;
  if (!Array.isArray(list) || list.length === 0) return null;
  return list.filter((item): item is string => typeof item === "string");
}

