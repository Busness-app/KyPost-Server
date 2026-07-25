import { beforeEach, describe, expect, it } from "vitest";
import {
  WrongPasswordError,
  VaultLockedError,
  isUnlocked,
  lock,
  parseEnvelope,
  requireUnlockedKey,
  unlock,
  unlockWithArmoredKey,
  unwrapPrivateKey,
  wrapPrivateKey
} from "./keyVault";

// A stand-in for an armored private key: this module treats it as opaque
// bytes, so its actual OpenPGP validity is irrelevant here.
const SECRET = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nnot-a-real-key\n-----END PGP PRIVATE KEY BLOCK-----";
const PASSWORD = "correct-horse-battery-staple";

// PBKDF2 at 600k iterations is intentionally slow; these tests do a handful
// of derivations.
const TIMEOUT = 30_000;

describe("keyVault wrapping", () => {
  beforeEach(() => lock());

  it(
    "round-trips a private key through the correct password",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, PASSWORD);
      await expect(unwrapPrivateKey(envelope, PASSWORD)).resolves.toBe(SECRET);
    },
    TIMEOUT
  );

  it(
    "rejects the wrong password rather than returning garbage",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, PASSWORD);
      await expect(unwrapPrivateKey(envelope, PASSWORD + "x")).rejects.toBeInstanceOf(WrongPasswordError);
    },
    TIMEOUT
  );

  it(
    "never puts the plaintext key in the envelope",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, PASSWORD);
      const serialized = JSON.stringify(envelope);
      expect(serialized).not.toContain("not-a-real-key");
      expect(serialized).not.toContain("PGP PRIVATE KEY");
    },
    TIMEOUT
  );

  it(
    "uses a fresh salt and IV per wrap, so identical inputs differ",
    async () => {
      const a = await wrapPrivateKey(SECRET, PASSWORD);
      const b = await wrapPrivateKey(SECRET, PASSWORD);
      expect(a.salt).not.toBe(b.salt);
      expect(a.iv).not.toBe(b.iv);
      expect(a.ciphertext).not.toBe(b.ciphertext);
    },
    TIMEOUT
  );

  it(
    "records the KDF and iteration count so the format can move to Argon2id later",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, PASSWORD);
      expect(envelope.v).toBe(2);
      expect(envelope.kdf).toBe("PBKDF2-SHA256");
      // Below the OWASP figure for PBKDF2-HMAC-SHA256 would be a silent
      // downgrade, so pin it.
      expect(envelope.iterations).toBeGreaterThanOrEqual(600_000);
    },
    TIMEOUT
  );

  it("rejects an envelope in an unknown format", async () => {
    await expect(
      unwrapPrivateKey({ v: 1, kdf: "PBKDF2-SHA256", iterations: 1, salt: "", iv: "", ciphertext: "" } as never, PASSWORD)
    ).rejects.toThrow(/Unsupported/);
  });

  it("parseEnvelope returns null for anything that is not a v2 envelope", () => {
    expect(parseEnvelope("not json")).toBeNull();
    expect(parseEnvelope(JSON.stringify({ v: 1 }))).toBeNull();
    expect(parseEnvelope(JSON.stringify({ v: 2, kdf: "PBKDF2-SHA256" }))).not.toBeNull();
  });
});

describe("keyVault lock state", () => {
  beforeEach(() => lock());

  it("starts locked and refuses to hand out a key", () => {
    expect(isUnlocked()).toBe(false);
    expect(() => requireUnlockedKey()).toThrow(VaultLockedError);
  });

  it(
    "unlocks with the right password and locks again on demand",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, PASSWORD);
      await unlock(envelope, PASSWORD);
      expect(isUnlocked()).toBe(true);
      expect(requireUnlockedKey()).toBe(SECRET);

      lock();
      expect(isUnlocked()).toBe(false);
      expect(() => requireUnlockedKey()).toThrow(VaultLockedError);
    },
    TIMEOUT
  );

  it(
    "stays locked when the password is wrong",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, PASSWORD);
      await expect(unlock(envelope, "wrong-password-entirely")).rejects.toBeInstanceOf(WrongPasswordError);
      expect(isUnlocked()).toBe(false);
    },
    TIMEOUT
  );

  it("never persists the key outside memory", () => {
    unlockWithArmoredKey(SECRET);
    // Anything reachable after a tab close is readable by any script that
    // achieves XSS, which is exactly what this module protects against.
    for (const store of [window.localStorage, window.sessionStorage]) {
      for (let i = 0; i < store.length; i++) {
        const value = store.getItem(store.key(i)!) ?? "";
        expect(value).not.toContain("not-a-real-key");
      }
    }
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0);
  });
});
