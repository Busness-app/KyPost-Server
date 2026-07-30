import { describe, expect, it } from "vitest";
import { defaultIterations, deriveAuthSecret, newLoginSalt } from "./authSecret";
import { wrapPrivateKey, unwrapPrivateKey } from "./keyVault";

const PASSWORD = "correct-horse-battery-staple";
const SECRET = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nnot-a-real-key\n-----END PGP PRIVATE KEY BLOCK-----";
const TIMEOUT = 60_000;

describe("deriveAuthSecret", () => {
  it("is deterministic for the same password and salt", async () => {
    const salt = newLoginSalt();
    const a = await deriveAuthSecret(PASSWORD, { salt, iterations: defaultIterations() });
    const b = await deriveAuthSecret(PASSWORD, { salt, iterations: defaultIterations() });
    expect(a).toBe(b);
    // 32 bytes as lowercase hex — the wire format users.ValidateAuthSecret wants.
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  }, TIMEOUT);

  it("differs per salt and per password", async () => {
    const saltA = newLoginSalt();
    const saltB = newLoginSalt();
    const it = defaultIterations();
    const a = await deriveAuthSecret(PASSWORD, { salt: saltA, iterations: it });
    const b = await deriveAuthSecret(PASSWORD, { salt: saltB, iterations: it });
    const c = await deriveAuthSecret(PASSWORD + "x", { salt: saltA, iterations: it });
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
  }, TIMEOUT);

  it("refuses a work factor outside the supported range", async () => {
    const salt = newLoginSalt();
    for (const iterations of [1, 1_000, 0, -1, 1e12, NaN]) {
      await expect(deriveAuthSecret(PASSWORD, { salt, iterations })).rejects.toThrow(
        /unsupported login work factor/i
      );
    }
  }, TIMEOUT);

  it("mints a fresh 16-byte salt each time", () => {
    const a = newLoginSalt();
    const b = newLoginSalt();
    expect(a).not.toBe(b);
    expect(atob(a).length).toBe(16);
  });
});

// THE POINT OF THE WHOLE EXERCISE.
//
// The server receives the auth secret. It must not be usable to open the PGP
// envelope, or the "the server cannot read your encrypted mail" claim is false
// again — which is exactly what it was when the plaintext password was posted on
// every login.
describe("auth secret cannot open the PGP envelope", () => {
  it("does not unwrap the key it is derived from the same password as", async () => {
    const envelope = await wrapPrivateKey(SECRET, PASSWORD);
    const authSecret = await deriveAuthSecret(PASSWORD, {
      salt: newLoginSalt(),
      iterations: defaultIterations()
    });

    // Sanity: the real password does open it.
    await expect(unwrapPrivateKey(envelope, PASSWORD)).resolves.toBe(SECRET);
    // The value the server holds does not.
    await expect(unwrapPrivateKey(envelope, authSecret)).rejects.toBeTruthy();
  }, TIMEOUT);

  it("uses a different salt from the envelope, which is what separates them", async () => {
    const envelope = await wrapPrivateKey(SECRET, PASSWORD);
    const loginSalt = newLoginSalt();
    expect(loginSalt).not.toBe(envelope.salt);

    // Even deriving with the ENVELOPE's salt, the labelled HKDF step means the
    // auth secret is not the wrapping key.
    const collide = await deriveAuthSecret(PASSWORD, {
      salt: envelope.salt,
      iterations: envelope.iterations
    });
    await expect(unwrapPrivateKey(envelope, collide)).rejects.toBeTruthy();
  }, TIMEOUT);
});
