// keyVault: client-side protection for the user's OpenPGP private key.
//
// The private key is wrapped in the browser under a key derived from the user's
// login password and uploaded as an opaque blob. The server stores it and cannot
// open it, for two reasons that both have to hold:
//
//   1. The password never reaches the server. It is stretched here and split, and
//      only the authentication half is transmitted — see lib/authSecret.ts.
//   2. The two halves use DIFFERENT SALTS. This module derives with a random
//      per-envelope salt stored inside the envelope; authentication derives with
//      the account's login salt. PBKDF2 under one salt reveals nothing about
//      PBKDF2 under another, so the value the server holds cannot produce the
//      wrapping key.
//
// Point 1 is not optional. A build that reverts to POSTing the plaintext
// password hands the server this module's key material on every sign-in, and
// four lines in the login handler would then open every client-protected key on
// the instance. Point 2 alone does not save it.
//
// DO NOT CHANGE THE DERIVATION IN THIS FILE. Every stored envelope was sealed
// with it; redefining it makes them all unopenable, which loses every message
// ever encrypted to those keys. The envelope carries `kdf` and `iterations` so a
// future scheme can be added alongside, and unwrap dispatches on what the stored
// envelope says.
//
// WHAT THIS DOES NOT DEFEND: the server ships this JavaScript. A hostile server
// can serve a modified bundle that exfiltrates the password, and no client-side
// derivation prevents that. This protects against a server that retains too
// much, against the password reaching logs, heap dumps and backups, and against
// compromise of data at rest — the same boundary every browser-delivered
// end-to-end product has.
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

// Bounds on the work factor an envelope may declare.
//
// `iterations` is read back out of a JSON blob the server hands us, so it is
// attacker-controlled input to a deliberately expensive function. Unbounded, a
// value of 4e9 wedges the tab in WebCrypto with no error and no way to reach
// the Security page to fix it, and a value of 1 makes a weakly-derived envelope
// look properly derived to every code path that trusts the field.
//
// The floor is below DEFAULT_ITERATIONS on purpose: it has to keep accepting
// envelopes written by an older default, or raising the default strands keys.
// The ceiling is roughly 20x the default — comfortably above any legitimate
// future increase, and still a few seconds rather than forever.
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 12_000_000;

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

/**
 * The stored envelope is not readable at all — malformed base64 in one of its
 * fields, not a password mismatch.
 *
 * Distinct from WrongPasswordError because the remedies are different and
 * mutually useless: retyping a password cannot fix a corrupt blob, and
 * restoring a blob is not something a user does by guessing again.
 */
export class CorruptEnvelopeError extends Error {
  constructor() {
    super("Your stored PGP key envelope is corrupt and cannot be read.");
    this.name = "CorruptEnvelopeError";
  }
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

// Validated explicitly rather than by catching what atob throws. atob's
// exception is a DOMException from whichever realm supplied the global, so
// `instanceof DOMException` is false under jsdom and true in a browser — a
// check that passes its own test suite and fails in production, or the reverse.
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

function fromBase64(value: string): Uint8Array {
  if (typeof value !== "string" || value.length % 4 !== 0 || !BASE64_RE.test(value)) {
    throw new CorruptEnvelopeError();
  }
  try {
    return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  } catch {
    throw new CorruptEnvelopeError();
  }
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
  if (
    !Number.isInteger(envelope.iterations) ||
    envelope.iterations < MIN_ITERATIONS ||
    envelope.iterations > MAX_ITERATIONS
  ) {
    throw new Error(
      `Wrapped-key envelope declares an unsupported work factor (${String(envelope.iterations)}).`
    );
  }

  // Decode all three fields up front, outside the decrypt's catch. A malformed
  // salt or IV is a corrupt envelope, and folding that into the catch below
  // would report it as a wrong password — sending the user to retype a
  // password that was never the problem.
  const salt = fromBase64(envelope.salt);
  const iv = fromBase64(envelope.iv);
  const ciphertext = fromBase64(envelope.ciphertext);

  let plaintext: ArrayBuffer;
  try {
    const key = await deriveWrappingKey(password, salt, envelope.iterations);
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      key,
      ciphertext as BufferSource
    );
  } catch {
    // AES-GCM authentication failing with a well-formed envelope means the
    // derived key was wrong, which in practice means the password was.
    throw new WrongPasswordError();
  }
  return new TextDecoder().decode(plaintext);
}

/**
 * Parses a stored envelope, or returns null if the blob is not one.
 *
 * Structural checks only — the work factor is validated in unwrapPrivateKey,
 * not here, deliberately: null from this function means "this account has no
 * wrapped key", and reporting a bad `iterations` that way would tell the user
 * their key is missing when it is present and unreadable. Those need different
 * remedies.
 */
export function parseEnvelope(raw: string): WrappedKeyEnvelope | null {
  try {
    const parsed = JSON.parse(raw) as WrappedKeyEnvelope;
    if (parsed?.v !== 2) {
      return null;
    }
    if (
      typeof parsed.salt !== "string" ||
      typeof parsed.iv !== "string" ||
      typeof parsed.ciphertext !== "string"
    ) {
      return null;
    }
    return parsed;
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
