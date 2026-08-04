// The credential half of the auth API: fetching the derivation parameters and
// turning a typed password into the auth secret the server actually receives.
//
// Kept in one place so no page re-implements the handshake. Every caller that
// needs to prove the account password goes through deriveCredential and sends
// what it returns — see lib/authSecret.ts for why the password itself must not
// be transmitted.

import { getJSON, postJSON } from "./client";
import { deriveAuthSecret, type LoginParams } from "../lib/authSecret";

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
 * `password` is retained locally for legacy-account callers; credentialFields
 * decides what actually goes on the wire.
 */
export type Credential = {
  password: string;
  authSecret: string;
  loginSalt: string;
  loginIterations: number;
  /**
   * Which form the server said this account stores, when it was willing to say.
   * Only ever populated for an authenticated caller — see handleLoginParams.
   */
  derivation?: "legacy" | "pbkdf2";
};

/**
 * The credential fields to put on the wire.
 *
 * The server picks which form it verifies from what the ACCOUNT stores, never
 * from what arrived (verifyAccountCredential, login_params.go). So the client
 * has to send the form the account actually uses, and sending the wrong one is a
 * hard 401 — which is exactly what broke every legacy account when this function
 * started choosing by itself.
 *
 * It cannot always know. `derivation` is returned only to a caller that has
 * already proved it is the account; disclosing it for an arbitrary username
 * would be the account-existence oracle the synthetic login salt exists to
 * prevent. So:
 *
 *   - derivation known (re-auth, step-up, password change): send exactly that
 *     form, and a converted account's plaintext password never leaves the browser.
 *   - derivation unknown (sign-in, which is unauthenticated by definition): send
 *     both, and let the server pick. A legacy account has no other way to
 *     authenticate — its stored hash covers the plaintext — and the first
 *     successful sign-in converts it, after which the plaintext is never sent
 *     again. This is the "additionally sends the plaintext only while it still
 *     has to" the server's own comment describes.
 */
export function credentialFields(credential: Credential, prefix = ""): Record<string, string> {
  const passwordKey = `${prefix}${prefix ? "Password" : "password"}`;
  const authSecretKey = `${prefix}${prefix ? "AuthSecret" : "authSecret"}`;

  if (credential.derivation === "pbkdf2") {
    return { [authSecretKey]: credential.authSecret };
  }
  if (credential.derivation === "legacy" || !credential.authSecret) {
    return { [passwordKey]: credential.password };
  }
  return { [passwordKey]: credential.password, [authSecretKey]: credential.authSecret };
}

/** Derives the credential fields for username/password. */
export async function deriveCredential(username: string, password: string): Promise<Credential> {
  const params: LoginParams = await getLoginParams(username);
  if (!params.salt) {
    return {
      password,
      authSecret: "",
      loginSalt: "",
      loginIterations: params.iterations,
      derivation: params.derivation
    };
  }
  const authSecret = await deriveAuthSecret(password, params);
  return {
    password,
    authSecret,
    loginSalt: params.salt,
    loginIterations: params.iterations,
    derivation: params.derivation
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

/**
 * Re-proves the account credential and the second factor for the session that
 * already exists. Throws on any failure; the caller shows the message.
 *
 * `code` is a TOTP code, or a one-time recovery code in its place, and is
 * ignored by the server for an account without TOTP. credentialFields selects
 * the account's one valid credential form — see lib/authSecret.ts.
 *
 * This authorises nothing on its own. It answers "is the person at this
 * keyboard the account owner, right now", which is what a screen full of key
 * material wants to know before it draws itself; the operations behind that
 * screen re-verify for themselves regardless.
 */
export async function reauthenticate(password: string, code: string): Promise<void> {
  const credential = await deriveCredential("", password);
  await postJSON("/api/auth/step-up", { ...credentialFields(credential), code });
}
