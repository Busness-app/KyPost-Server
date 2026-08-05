// Attachment reading and the send-error decoding the compose window needs.
// Pure — no React — so the base64 stripping and the 409 shape are testable
// without mounting the app shell.

import { HttpError } from "../api/client";
import type { ComposeAttachment } from "./types";

// Mirror of the backend's derived maxMailAttachmentBytes in
// internal/api/server.go: (25 MiB request cap - 1 MiB overhead) * 3/4.
//
// The 3/4 is base64: attachments travel encoded inside the JSON body, so the
// decoded budget is necessarily smaller than the request cap. This previously
// read 25 MiB — the same figure as the request-body cap at the time — which let
// the UI accept a set of attachments the server then refused, with an error
// naming a limit the user had not exceeded.
export const MAX_ATTACHMENT_BYTES = Math.floor(((25 - 1) * 1024 * 1024) / 4) * 3;

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


// Pulls the changed-key recipient list out of /api/mail/send's 409 body.
//
// Deliberately separate from keylessRecipientsFrom409: the two 409s mean
// opposite things. "No key on file" is an absence the pickup fallback exists to
// cover. A CHANGED key is the TOFU pin firing — the one signal that the key
// published for an address may have been substituted — and offering the pickup
// fallback there would mail the plaintext in the clear to whoever is in a
// position to have made the substitution. The server refuses those sends and
// this list is why; the message must not mention the fallback.
export function keyChangedRecipientsFrom409(error: unknown): string[] | null {
  if (!(error instanceof HttpError) || error.status !== 409) return null;
  const body = error.body as { keyChangedRecipients?: unknown } | undefined;
  const list = body?.keyChangedRecipients;
  if (!Array.isArray(list) || list.length === 0) return null;
  return list.filter((item): item is string => typeof item === "string");
}


// --- partial delivery of a client-side encrypted send -----------------------

/**
 * Mails one sealed pickup link per keyless recipient, and reports which ones
 * failed instead of throwing on the first.
 *
 * This runs AFTER the keyed ciphertext has already been posted and delivered,
 * which is what makes the distinction matter. Throwing here used to abandon
 * every recipient after the failing one and surface a bare "send failed" — so
 * the user retried, and the retry delivered the keyed copy a second time while
 * the recipients who had been skipped still got nothing. Neither half of that
 * is recoverable by the caller, so neither is treated as an exception: every
 * address is attempted, and what did not go out comes back as data.
 */
export async function deliverSealedPickupLinks(
  addresses: string[],
  send: (address: string) => Promise<void>
): Promise<string[]> {
  const failed: string[] = [];
  for (const address of addresses) {
    try {
      await send(address);
    } catch {
      failed.push(address);
    }
  }
  return failed;
}

/** Joins the non-empty warnings a single send can produce. */
export function combineWarnings(...parts: string[]): string {
  return parts.filter((p) => p.trim() !== "").join("; ");
}

/**
 * Describes the secure links that never went out. Wording mirrors the server's
 * partialDeliveryWarning so the two send paths read the same, and it names the
 * addresses because the user's only recovery is to reach those people another
 * way — a count alone would not tell them who.
 */
export function secureLinkWarning(failed: string[], total: number): string {
  if (failed.length === 0) return "";
  return `${failed.length} of ${total} secure links could not be sent: ${failed.join(", ")}`;
}
