// pickupCrypto: encrypts a message for a recipient who has no PGP key, so
// the server stores something it cannot read.
//
// The sender's browser picks a random AES-256-GCM key, encrypts locally, and
// uploads only ciphertext. The key travels to the recipient in the URL
// fragment of the pickup link (`.../pickup/<id>?t=<token>#<key>`), and
// browsers never transmit a fragment — so the server that generated and
// relayed that link still never receives the key on the fetch.
//
// What this protects against, precisely: the server's disk, its backups, a
// later compromise, and an operator reading files. The stored blob is
// ciphertext and the key was never written down.
//
// "Never written down" depends on the server not caching the notification
// email that carries the link, which for a while it did — see
// mailcache.warmBody, which now drops Sent bodies and redacts pickup-link
// fragments from everything else it stores. Worth knowing if this claim is
// ever re-checked: it is a property of two files, not of this one.
//
// What it does NOT protect against, and the UI must not imply otherwise:
// anyone who can read the recipient's email has both the link and the key,
// because the key is in the email. And the server sees the key once, in
// flight, when it relays that email over SMTP. This turns a seven-day
// plaintext-at-rest exposure into a momentary in-flight one; it does not
// make the pickup path end-to-end in the sense the PGP path is.

const IV_BYTES = 12;
const KEY_BYTES = 32;

/** The stored envelope. Opaque to the server, which checks only its shape. */
export type SealedPickup = {
  v: 1;
  iv: string;
  ciphertext: string;
};

/** What a pickup link carries: the payload plus the subject, both sealed. */
export type PickupContents = {
  subject: string;
  body: string;
  /** "html" or "plain", so the recipient's page renders it the same way. */
  mode: string;
  from: string;
};

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

/**
 * Seals contents under a fresh random key.
 *
 * Returns the envelope to upload and the base64url key to put in the link
 * fragment. The key is returned, never stored — the caller must place it in
 * the fragment and then forget it.
 */
export async function sealPickup(contents: PickupContents): Promise<{ sealed: SealedPickup; fragmentKey: string }> {
  const rawKey = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await crypto.subtle.importKey("raw", rawKey as BufferSource, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    new TextEncoder().encode(JSON.stringify(contents))
  );
  return {
    sealed: { v: 1, iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(ciphertext)) },
    fragmentKey: toBase64Url(rawKey)
  };
}

/** Reverses sealPickup. Used by the recipient's page. */
export async function openPickup(sealed: SealedPickup, fragmentKey: string): Promise<PickupContents> {
  const rawKey = fromBase64Url(fragmentKey);
  if (rawKey.length !== KEY_BYTES) {
    throw new Error("The key in this link is the wrong length.");
  }
  const key = await crypto.subtle.importKey("raw", rawKey as BufferSource, "AES-GCM", false, ["decrypt"]);
  const iv = Uint8Array.from(atob(sealed.iv), (c) => c.charCodeAt(0));
  const data = Uint8Array.from(atob(sealed.ciphertext), (c) => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, data as BufferSource);
  return JSON.parse(new TextDecoder().decode(plain)) as PickupContents;
}
