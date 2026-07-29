// The credential half of the auth API: fetching the derivation parameters and
// turning a typed password into the auth secret the server actually receives.
//
// Kept in one place so no page re-implements the handshake. Every caller that
// needs to prove the account password goes through deriveCredential and sends
// what it returns — see lib/authSecret.ts for why the password itself must not
// be transmitted.

import { getJSON } from "./client";
import { defaultIterations, deriveAuthSecret, type LoginParams } from "../lib/authSecret";

/**
 * Fetches this username's derivation parameters.
 *
 * Unauthenticated and deliberately uninformative: the response is the same
 * shape whether or not the account exists (the server returns a stable
 * synthetic salt otherwise), so this cannot be used to enumerate accounts.
 */
export async function getLoginParams(username: string): Promise<LoginParams> {
  // An empty username asks the server to answer for the authenticated caller,
  // which is what the re-authentication flows want: they already hold a session,
  // and echoing their own username back would let a caller pass someone else's.
  const q = username ? `?username=${encodeURIComponent(username)}` : "";
  return getJSON<LoginParams>(`/api/auth/login-params${q}`);
}

/**
 * The fields to send when proving an account password.
 *
 * `password` is still populated because an account that has not been converted
 * yet authenticates with it, and the server picks based on what the ACCOUNT
 * stores rather than on what arrives. Once converted, the server ignores it —
 * and a future release can stop sending it entirely.
 */
export type Credential = {
  password: string;
  authSecret: string;
  loginSalt: string;
  loginIterations: number;
};

/** Derives the credential fields for username/password. */
export async function deriveCredential(username: string, password: string): Promise<Credential> {
  let params: LoginParams;
  try {
    params = await getLoginParams(username);
  } catch {
    // A failed handshake must not silently fall back to sending only the
    // password — that would quietly restore the behaviour this exists to
    // remove. Derive against the default work factor with an empty salt so the
    // request still carries an auth secret; the server will reject it if the
    // account has converted, and the user retries.
    params = { salt: "", iterations: defaultIterations() };
  }
  if (!params.salt) {
    return { password, authSecret: "", loginSalt: "", loginIterations: params.iterations };
  }
  const authSecret = await deriveAuthSecret(password, params);
  return {
    password,
    authSecret,
    loginSalt: params.salt,
    loginIterations: params.iterations
  };
}

/**
 * Derives the credential for a NEW password, against a caller-supplied salt.
 *
 * The salt is chosen client-side for a password change because the server
 * cannot mint one for a credential it will never see: it has to be recorded in
 * the same request that sets the credential, or the two disagree and the account
 * is locked out.
 */
export async function deriveNewCredential(
  password: string,
  salt: string,
  iterations: number
): Promise<string> {
  return deriveAuthSecret(password, { salt, iterations });
}
