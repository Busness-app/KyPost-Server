// keyVault: client-side protection for the user's OpenPGP private key.
//
// The private key is wrapped in the browser under a key derived from the
// user's login password and uploaded as an opaque blob. The server stores it
// and cannot open it: it holds only a scrypt hash of that password, not the
// password, so it cannot derive the wrapping key. That is what makes this
// end-to-end rather than "encrypted at rest next to the key that decrypts
// it".
//
// KDF choice: PBKDF2-HMAC-SHA256 via WebCrypto, 600,000 iterations (the
// OWASP figure for this construction). Argon2id would resist GPU attack
// better, but it is not in WebCrypto and would mean shipping a WASM bundle
// on the critical path of every login. The envelope carries `kdf` and
// `iterations`, so moving to Argon2id later is a format addition and not a
// migration: unwrap dispatches on what the stored envelope says, and rewrap
// always writes the current default.
//
// The unwrapped key lives in module memory only, for the life of the page.
// It is deliberately never written to localStorage or sessionStorage: both
// survive a tab close and are readable by any script that achieves XSS,
// which would hand over exactly what this module exists to protect.

const KDF_PBKDF2_SHA256 = "PBKDF2-SHA256";
const DEFAULT_ITERATIONS = 600_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

export type WrappedKeyEnvelope = {
  v: 2;
  kdf: typeof KDF_PBKDF2_SHA256;
  iterations: number;
  salt: string;
  iv: string;
  ciphertext: string;
};

export class VaultLockedError extends Error {
  constructor() {
    super("Your PGP key is locked. Enter your password to unlock it.");
    this.name = "VaultLockedError";
  }
}

export class WrongPasswordError extends Error {
  constructor() {
    super("That password did not unlock the key.");
    this.name = "WrongPasswordError";
  }
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

async function deriveWrappingKey(password: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Wraps an armored private key under a key derived from password. */
export async function wrapPrivateKey(armoredPrivateKey: string, password: string): Promise<WrappedKeyEnvelope> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveWrappingKey(password, salt, DEFAULT_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    new TextEncoder().encode(armoredPrivateKey)
  );
  return {
    v: 2,
    kdf: KDF_PBKDF2_SHA256,
    iterations: DEFAULT_ITERATIONS,
    salt: toBase64(salt),
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ciphertext))
  };
}

/**
 * Unwraps an envelope produced by wrapPrivateKey.
 *
 * A wrong password surfaces as WrongPasswordError rather than a raw
 * OperationError: AES-GCM authentication failing here means the derived key
 * was wrong, which in practice means the password was.
 */
export async function unwrapPrivateKey(envelope: WrappedKeyEnvelope, password: string): Promise<string> {
  if (envelope?.v !== 2 || envelope.kdf !== KDF_PBKDF2_SHA256) {
    throw new Error("Unsupported wrapped-key format.");
  }
  const key = await deriveWrappingKey(password, fromBase64(envelope.salt), envelope.iterations);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(envelope.iv) as BufferSource },
      key,
      fromBase64(envelope.ciphertext) as BufferSource
    );
  } catch {
    throw new WrongPasswordError();
  }
  return new TextDecoder().decode(plaintext);
}

export function parseEnvelope(raw: string): WrappedKeyEnvelope | null {
  try {
    const parsed = JSON.parse(raw) as WrappedKeyEnvelope;
    return parsed?.v === 2 ? parsed : null;
  } catch {
    return null;
  }
}

// ---- in-memory vault ------------------------------------------------------

let unlockedArmoredKey: string | null = null;
const listeners = new Set<(unlocked: boolean) => void>();

function notify() {
  for (const listener of listeners) {
    listener(unlockedArmoredKey !== null);
  }
}

/** Subscribe to lock/unlock transitions. Returns an unsubscribe function. */
export function onVaultChange(listener: (unlocked: boolean) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function isUnlocked(): boolean {
  return unlockedArmoredKey !== null;
}

/** Unwraps and holds the key in memory for this page's lifetime. */
export async function unlock(envelope: WrappedKeyEnvelope, password: string): Promise<void> {
  unlockedArmoredKey = await unwrapPrivateKey(envelope, password);
  notify();
}

/** Holds an already-unwrapped key, for the generate/import flows. */
export function unlockWithArmoredKey(armoredPrivateKey: string): void {
  unlockedArmoredKey = armoredPrivateKey;
  notify();
}

/**
 * Returns the unwrapped private key, or throws VaultLockedError.
 *
 * Callers must not cache the result: holding it in component state would
 * outlive lock() and defeat the point of being able to lock at all.
 */
export function requireUnlockedKey(): string {
  if (unlockedArmoredKey === null) {
    throw new VaultLockedError();
  }
  return unlockedArmoredKey;
}

/** Drops the in-memory key. Called on logout and on explicit lock. */
export function lock(): void {
  unlockedArmoredKey = null;
  notify();
}
