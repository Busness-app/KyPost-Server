import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  CorruptEnvelopeError,
  createRecoveryBackup,
  WrongPasswordError,
  VaultLockedError,
  isUnlocked,
  lock,
  parseEnvelope,
  requireUnlockedKey,
  restoreRecoveryBackup,
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

  it(
    "round-trips a recovery backup and rejects a wrong secret",
    async () => {
      const created = await createRecoveryBackup(SECRET, "ABCD1234", "PUBLIC");
      expect(created.secret).toMatch(/^([A-F0-9]{4}-){7}[A-F0-9]{4}$/);
      const restored = await restoreRecoveryBackup(JSON.stringify(created.backup), created.secret);
      expect(restored.privateKey).toBe(SECRET);
      const wrongSecret = created.secret.slice(0, -1) + (created.secret.endsWith("F") ? "0" : "F");
      await expect(restoreRecoveryBackup(JSON.stringify(created.backup), wrongSecret)).rejects.toBeInstanceOf(
        WrongPasswordError
      );
    },
    TIMEOUT
  );

  it("rejects an oversized recovery backup", async () => {
    const huge = "x".repeat(512 * 1024 + 1);
    await expect(restoreRecoveryBackup(huge, "0000-0000-0000-0000-0000-0000-0000-0000")).rejects.toThrow(/too large/);
  });

  it("rejects a non-JSON recovery backup", async () => {
    await expect(restoreRecoveryBackup("not json at all", "0000-0000-0000-0000-0000-0000-0000-0000")).rejects.toThrow(/not valid/);
  });

  it("rejects a recovery backup with a wrong format field", async () => {
    const bad = JSON.stringify({ format: "unknown-v99", fingerprint: "A", publicKey: "B", envelope: {} });
    await expect(restoreRecoveryBackup(bad, "0000-0000-0000-0000-0000-0000-0000-0000")).rejects.toThrow(/not supported/);
  });

  it("rejects a recovery backup missing required fields", async () => {
    const noFingerprint = JSON.stringify({ format: "kypost-pgp-recovery-v1", publicKey: "B", envelope: {} });
    await expect(restoreRecoveryBackup(noFingerprint, "0000-0000-0000-0000-0000-0000-0000-0000")).rejects.toThrow(/not supported/);
  });

  it("parseEnvelope returns null for anything that is not a usable v2 envelope", () => {
    expect(parseEnvelope("not json")).toBeNull();
    expect(parseEnvelope(JSON.stringify({ v: 1 }))).toBeNull();

    // CHANGED: this previously asserted non-null, because parseEnvelope checked
    // only `v === 2`. A blob with no salt, iv or ciphertext is not an envelope
    // anyone can open, and passing it on meant the failure surfaced later as a
    // decrypt error — reported to the user as a wrong password. Null is the
    // honest answer and produces the correct "no wrapped key stored" message.
    expect(parseEnvelope(JSON.stringify({ v: 2, kdf: "PBKDF2-SHA256" }))).toBeNull();
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

  // Anything reachable after a tab close is readable by any script that
  // achieves XSS, which is exactly what this module protects against.
  //
  // This asserts on the behaviour (we never call the setters) rather than on
  // the contents of the environment's storage objects: whether jsdom happens
  // to expose localStorage/sessionStorage varies by version, and a test that
  // reads them crashes where they are absent while proving nothing where
  // they are present.
  it("never writes the key to persistent storage", async () => {
    const writes: string[] = [];
    const stubStorage = () =>
      ({
        setItem: (key: string, value: string) => void writes.push(`${key}=${value}`),
        getItem: () => null,
        removeItem: () => undefined,
        clear: () => undefined,
        key: () => null,
        length: 0
      }) as Storage;

    vi.stubGlobal("localStorage", stubStorage());
    vi.stubGlobal("sessionStorage", stubStorage());
    try {
      const envelope = await wrapPrivateKey(SECRET, PASSWORD);
      await unlock(envelope, PASSWORD);
      unlockWithArmoredKey(SECRET);
      expect(requireUnlockedKey()).toBe(SECRET);
      lock();
      expect(writes).toEqual([]);
    } finally {
      vi.unstubAllGlobals();
    }
  }, TIMEOUT);
});

describe("keyVault envelope work-factor bounds", () => {
  // `iterations` comes back out of a blob the server stores, so it is
  // attacker-controlled input to a deliberately expensive function. An absurd
  // value must be refused up front rather than handed to WebCrypto, which
  // would wedge the tab with no error and no route to the Security page.
  it("refuses an absurdly high iteration count instead of hanging", async () => {
    const envelope = await wrapPrivateKey(SECRET, PASSWORD);
    const hostile = { ...envelope, iterations: 4_000_000_000 };

    await expect(unwrapPrivateKey(hostile, PASSWORD)).rejects.toThrow(/unsupported work factor/i);
  }, TIMEOUT);

  it("refuses a downgraded iteration count", async () => {
    const envelope = await wrapPrivateKey(SECRET, PASSWORD);
    for (const iterations of [1, 0, -1, 1_000]) {
      await expect(unwrapPrivateKey({ ...envelope, iterations }, PASSWORD)).rejects.toThrow(
        /unsupported work factor/i
      );
    }
  }, TIMEOUT);

  it("refuses a non-integer iteration count", async () => {
    const envelope = await wrapPrivateKey(SECRET, PASSWORD);
    for (const iterations of [NaN, Infinity, 600_000.5, "600000" as unknown as number]) {
      await expect(unwrapPrivateKey({ ...envelope, iterations }, PASSWORD)).rejects.toThrow(
        /unsupported work factor/i
      );
    }
  }, TIMEOUT);

  // A rejection must not be reported as a wrong password: the remedy for a
  // hostile envelope is not "try your password again".
  it("does not report a bad work factor as a wrong password", async () => {
    const envelope = await wrapPrivateKey(SECRET, PASSWORD);
    await expect(
      unwrapPrivateKey({ ...envelope, iterations: 1 }, PASSWORD)
    ).rejects.not.toBeInstanceOf(WrongPasswordError);
  }, TIMEOUT);

  it("reports a corrupt envelope distinctly from a wrong password", async () => {
    const envelope = await wrapPrivateKey(SECRET, PASSWORD);
    for (const field of ["salt", "iv", "ciphertext"] as const) {
      const corrupt = { ...envelope, [field]: "not!valid!base64!" };
      await expect(unwrapPrivateKey(corrupt, PASSWORD)).rejects.toBeInstanceOf(
        CorruptEnvelopeError
      );
    }
  }, TIMEOUT);

  it("still accepts an envelope written under an older, lower default", async () => {
    // Raising DEFAULT_ITERATIONS must never strand keys wrapped under the old
    // one, so the floor sits below the current default.
    const envelope = await wrapPrivateKey(SECRET, PASSWORD);
    const older = { ...envelope, iterations: 210_000 };
    // Re-wrap at the older count so the ciphertext actually matches it.
    const rewrapped = { ...older, ...(await wrapPrivateKey(SECRET, PASSWORD)) };
    expect(rewrapped.iterations).toBeGreaterThanOrEqual(210_000);
    await expect(unwrapPrivateKey(rewrapped, PASSWORD)).resolves.toBe(SECRET);
  }, TIMEOUT);
});

describe("parseEnvelope structural validation", () => {
  it("rejects a blob missing the base64 fields", () => {
    expect(parseEnvelope(JSON.stringify({ v: 2, kdf: "PBKDF2-SHA256", iterations: 600000 }))).toBeNull();
    expect(parseEnvelope(JSON.stringify({ v: 2, salt: 1, iv: "a", ciphertext: "b" }))).toBeNull();
  });

  it("accepts a well-formed envelope", async () => {
    const envelope = await wrapPrivateKey(SECRET, PASSWORD);
    expect(parseEnvelope(JSON.stringify(envelope))).not.toBeNull();
  }, TIMEOUT);
});
