// pgpSession: the client's PGP state for this page load.
//
// The unwrapped private key cannot survive a reload (see keyVault), so every
// page load is a cold start: fetch the bootstrap snapshot, then prompt for an
// unlock the first time something actually needs the key. This module holds
// that snapshot and the derived "can I do PGP right now" answer, so App,
// SecurityPage, ReadPage, and compose all read one source of truth instead of
// each deciding for themselves and disagreeing.

import { getPGPBootstrap, rewrapPGPPrivateKey, type PGPBootstrap } from "../api/pgp";
import {
  isUnlocked,
  lock,
  onVaultChange,
  parseEnvelope,
  requireUnlockedKey,
  unlock,
  unwrapPrivateKey,
  wrapPrivateKey
} from "./keyVault";

export type PGPSessionState = {
  loaded: boolean;
  bootstrap: PGPBootstrap | null;
  unlocked: boolean;
  /** Set when the bootstrap fetch itself failed, so callers can say so
   *  rather than rendering "no PGP identity" for a network error. */
  error: string;
};

let state: PGPSessionState = { loaded: false, bootstrap: null, unlocked: false, error: "" };
const listeners = new Set<(s: PGPSessionState) => void>();

function emit() {
  for (const listener of listeners) {
    listener(state);
  }
}

function setState(patch: Partial<PGPSessionState>) {
  state = { ...state, ...patch };
  emit();
}

// Keep `unlocked` in step with the vault even when something else locks it
// (logout, an explicit lock button).
onVaultChange((unlockedNow) => {
  if (state.unlocked !== unlockedNow) {
    setState({ unlocked: unlockedNow });
  }
});

export function subscribePGPSession(listener: (s: PGPSessionState) => void): () => void {
  listeners.add(listener);
  listener(state);
  return () => listeners.delete(listener);
}

export function pgpSessionState(): PGPSessionState {
  return state;
}

/**
 * Fetches the cold-start snapshot. Safe to call more than once; later calls
 * refresh it (e.g. after generating a key or migrating).
 */
export async function loadPGPSession(): Promise<PGPSessionState> {
  try {
    const bootstrap = await getPGPBootstrap();
    setState({ loaded: true, bootstrap, unlocked: isUnlocked(), error: "" });
  } catch (e) {
    // A failed bootstrap must not read as "this account has no key" — that
    // is how a client ends up offering to generate a second identity over
    // an existing one.
    setState({ loaded: true, bootstrap: null, error: e instanceof Error ? e.message : "failed to load PGP state" });
  }
  return state;
}

export function clearPGPSession(): void {
  lock();
  state = { loaded: false, bootstrap: null, unlocked: false, error: "" };
  emit();
}

/** True when this account holds a key the browser must unwrap itself. */
export function isClientProtected(): boolean {
  return state.bootstrap?.protection === "client";
}

/** True when a PGP operation would need an unlock the user has not done. */
export function needsUnlock(): boolean {
  return isClientProtected() && !state.unlocked;
}

/**
 * Unwraps the stored envelope with password and holds the key for this page.
 * Throws WrongPasswordError from keyVault when the password does not fit.
 */
export async function unlockPGPSession(password: string): Promise<void> {
  const wrapped = state.bootstrap?.wrappedPrivateKey ?? "";
  const envelope = parseEnvelope(wrapped);
  if (!envelope) {
    throw new Error("No wrapped private key is stored for this account.");
  }
  await unlock(envelope, password);
  setState({ unlocked: true });
}

export function lockPGPSession(): void {
  lock();
  setState({ unlocked: false });
}

/**
 * The contact public keys the bootstrap handed over, for verifying inbound
 * signatures. Empty is normal (no contacts have keys yet), not an error.
 */
export function knownSignerKeys(): string[] {
  return state.bootstrap?.signerPublicKeys ?? [];
}

/**
 * Returns the PGP private-key envelope re-sealed under newPassword, or null when
 * there is nothing to re-seal (no key, or a legacy server-held one).
 *
 * The wrapping key is derived from the account password, so changing the
 * password without re-sealing strands the key: the stored envelope still only
 * opens with the old password, and nothing in the UI would say so.
 *
 * This used to return an uploader the caller invoked AFTER the password write,
 * as a second HTTP request. A dropped connection in between left the password
 * changed and the envelope sealed under a password the user no longer had —
 * permanently, because the only rewrap path re-derives from the CURRENT password
 * and so could never open it again. The advertised recovery ("unlock with your
 * PREVIOUS password, then change your password again") could not work. The
 * envelope is now returned as data and written in the SAME request as the
 * credential, so the pair commits together or not at all.
 */
export async function rewrappedEnvelopeFor(
  oldPassword: string,
  newPassword: string
): Promise<string | null> {
  const bootstrap = state.bootstrap ?? (await loadPGPSession()).bootstrap;
  if (!bootstrap || bootstrap.protection !== "client" || !bootstrap.wrappedPrivateKey) {
    return null;
  }
  const envelope = parseEnvelope(bootstrap.wrappedPrivateKey);
  if (!envelope) {
    return null;
  }
  // Unwrapped eagerly, while the old password is known to be correct.
  const armored = await unwrapPrivateKey(envelope, oldPassword);
  return JSON.stringify(await wrapPrivateKey(armored, newPassword));
}

/**
 * Re-seals the ALREADY-UNLOCKED key under password and uploads it.
 *
 * The recovery path for an envelope that is out of step with the account
 * password — which had no way out at all before: every rewrap derived from the
 * current password, and a stale envelope by definition does not open with it.
 * Unlocking with the older password (PgpUnlockDialog) puts the key in memory,
 * and this writes it back under the current one.
 *
 * `password` does double duty and both uses need it to be the CURRENT account
 * password: it is the key the envelope is re-sealed under, and it is the
 * step-up credential the server now requires before overwriting an envelope it
 * cannot itself inspect.
 */
export async function rewrapUnlockedKeyUnder(password: string): Promise<void> {
  const armored = requireUnlockedKey();
  await rewrapPGPPrivateKey(JSON.stringify(await wrapPrivateKey(armored, password)), password);
  await loadPGPSession();
}
