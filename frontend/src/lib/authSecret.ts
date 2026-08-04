// authSecret: derives the authentication credential from the account password,
// in the browser, so the password itself never reaches the server.
//
// WHY THIS EXISTS
//
// keyVault.ts seals the PGP private key under a key derived from the account
// password, and claims the server "cannot open it" because it stores only a
// scrypt hash of that password. That claim was false: the plaintext password was
// POSTed to /api/auth/login on every single sign-in. The server was handed the
// wrapping key's source material, repeatedly, and merely declined to keep it —
// four lines in the login handler would have opened every client-protected key
// on the instance.
//
// THE SEPARATION
//
// One password, two independent secrets, and the server only ever receives one:
//
//   stretch      = PBKDF2-SHA256(password, LOGIN salt from the server, N)
//   authSecret   = HKDF-SHA256(stretch, info "kypost/auth/v1")   -> sent
//   wrapping key = PBKDF2-SHA256(password, ENVELOPE salt, N)     -> never sent
//
// The load-bearing part is that the two use DIFFERENT SALTS. The login salt
// comes from GET /api/auth/login-params; the envelope salt is 16 random bytes
// generated at wrap time and stored inside the envelope. PBKDF2 with one salt
// reveals nothing about PBKDF2 with another, so possessing authSecret does not
// help open the envelope — recovering the wrapping key from it requires the
// password, which is exactly what the server no longer has.
//
// This is also why keyVault.ts is untouched by this change, and must stay that
// way: it already derives with a per-envelope salt. Redefining ITS derivation
// would make every stored envelope unopenable, which is unrecoverable data loss
// for every message ever encrypted to those keys. The HKDF label above is
// belt-and-braces on the auth side only, where there is no stored history to
// break.
//
// WHAT THIS DOES NOT DEFEND
//
// The server ships the JavaScript. A server that wants the password can serve a
// modified bundle that posts it, and no amount of client-side derivation
// prevents that. This defends against a server that retains too much, against
// the password appearing in logs, heap dumps and backups, and against a
// compromise of data at rest. It does not defend against a hostile server
// actively targeting you — the same trust boundary every browser-delivered
// end-to-end product has.

const AUTH_INFO = "kypost/auth/v1";
const STRETCH_BYTES = 32;
const AUTH_SECRET_BYTES = 32;

/** Server-supplied parameters for deriving this account's auth secret. */
export type LoginParams = {
  salt: string;
  iterations: number;
  /**
   * Which credential form the account stores. Present ONLY when the request was
   * authenticated — the server will not disclose it for an arbitrary username,
   * because that would be an account-existence oracle. See credentialFields.
   */
  derivation?: "legacy" | "pbkdf2";
};

// Mirrors users.MinLoginIterations on the server, which rejects anything lower.
// A downgraded or modified client must not be able to register a credential
// derived at trivial cost.
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 12_000_000;

function fromBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Fresh random salt for a new credential, base64 as the server stores it. */
export function newLoginSalt(): string {
  const raw = crypto.getRandomValues(new Uint8Array(16));
  let binary = "";
  for (const b of raw) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

export function defaultIterations(): number {
  return 600_000;
}

/**
 * Derives the auth secret to send in place of the password.
 *
 * Returns lowercase hex — the wire format the server's
 * users.ValidateAuthSecret expects.
 */
export async function deriveAuthSecret(password: string, params: LoginParams): Promise<string> {
  const iterations = Math.floor(params.iterations);
  if (!Number.isFinite(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new Error(`Server requested an unsupported login work factor (${String(params.iterations)}).`);
  }

  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const stretch = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: fromBase64(params.salt) as BufferSource, iterations, hash: "SHA-256" },
    material,
    STRETCH_BYTES * 8
  );

  // HKDF-Expand over the stretch, labelled, so the authentication half is
  // domain-separated from anything else that might ever be derived from the
  // same stretch.
  const hkdfKey = await crypto.subtle.importKey("raw", stretch, "HKDF", false, ["deriveBits"]);
  const authBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0) as BufferSource,
      info: new TextEncoder().encode(AUTH_INFO) as BufferSource
    },
    hkdfKey,
    AUTH_SECRET_BYTES * 8
  );

  return toHex(new Uint8Array(authBits));
}
