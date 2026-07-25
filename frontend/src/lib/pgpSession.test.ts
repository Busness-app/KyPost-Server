import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { wrapPrivateKey } from "./keyVault";

// The API module is mocked so these tests exercise the session logic — the
// state machine a cold-starting client depends on — without a server.
const getPGPBootstrap = vi.fn();
const rewrapPGPPrivateKey = vi.fn();

vi.mock("../api/pgp", () => ({
  getPGPBootstrap: (...args: unknown[]) => getPGPBootstrap(...args),
  rewrapPGPPrivateKey: (...args: unknown[]) => rewrapPGPPrivateKey(...args)
}));

const SECRET = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nkey\n-----END PGP PRIVATE KEY BLOCK-----";
const OLD_PASSWORD = "old-account-password";
const NEW_PASSWORD = "new-account-password";
const TIMEOUT = 30_000;

function bootstrapFixture(overrides: Record<string, unknown> = {}) {
  return {
    hasIdentity: true,
    protection: "client",
    fingerprint: "FPR",
    keyId: "KID",
    publicKey: "pub",
    keySource: "generated",
    createdAt: "2026-07-25T00:00:00Z",
    wrappedPrivateKey: "",
    unlockRequired: true,
    canDecryptServerSide: false,
    migrationAvailable: false,
    signerPublicKeys: [],
    suggestedUserIDs: ["me@example.com"],
    displayName: "me",
    payloadEndpoint: "/api/mail/pgp-payload",
    ...overrides
  };
}

let session: typeof import("./pgpSession");

beforeEach(async () => {
  vi.resetModules();
  getPGPBootstrap.mockReset();
  rewrapPGPPrivateKey.mockReset();
  session = await import("./pgpSession");
});

afterEach(() => {
  session.clearPGPSession();
});

describe("cold start", () => {
  it("reports a client-protected account as needing an unlock", async () => {
    getPGPBootstrap.mockResolvedValue(bootstrapFixture({ wrappedPrivateKey: "{}" }));
    await session.loadPGPSession();
    expect(session.isClientProtected()).toBe(true);
    expect(session.needsUnlock()).toBe(true);
  });

  it("does not treat a legacy account as needing an unlock", async () => {
    getPGPBootstrap.mockResolvedValue(
      bootstrapFixture({ protection: "server", unlockRequired: false, migrationAvailable: true })
    );
    await session.loadPGPSession();
    expect(session.isClientProtected()).toBe(false);
    expect(session.needsUnlock()).toBe(false);
  });

  // A failed bootstrap must not look like "this account has no PGP key" —
  // that is how a client offers to generate a second identity over an
  // existing one.
  it("surfaces a fetch failure instead of reporting no identity", async () => {
    getPGPBootstrap.mockRejectedValue(new Error("network down"));
    const state = await session.loadPGPSession();
    expect(state.error).toContain("network down");
    expect(state.bootstrap).toBeNull();
    expect(session.isClientProtected()).toBe(false);
  });

  it(
    "unlocks with the right password and refuses the wrong one",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, OLD_PASSWORD);
      getPGPBootstrap.mockResolvedValue(bootstrapFixture({ wrappedPrivateKey: JSON.stringify(envelope) }));
      await session.loadPGPSession();

      await expect(session.unlockPGPSession("wrong-password-here")).rejects.toBeTruthy();
      expect(session.needsUnlock()).toBe(true);

      await session.unlockPGPSession(OLD_PASSWORD);
      expect(session.needsUnlock()).toBe(false);

      session.lockPGPSession();
      expect(session.needsUnlock()).toBe(true);
    },
    TIMEOUT
  );
});

describe("password change rewrap", () => {
  it(
    "produces an envelope that opens with the new password and not the old",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, OLD_PASSWORD);
      getPGPBootstrap.mockResolvedValue(bootstrapFixture({ wrappedPrivateKey: JSON.stringify(envelope) }));
      await session.loadPGPSession();

      const commit = await session.prepareRewrappedPGPKey(OLD_PASSWORD, NEW_PASSWORD);
      expect(commit).not.toBeNull();

      // Nothing is uploaded until the caller commits: the caller orders this
      // against the password write itself.
      expect(rewrapPGPPrivateKey).not.toHaveBeenCalled();

      rewrapPGPPrivateKey.mockResolvedValue({ ok: true });
      await commit!();
      expect(rewrapPGPPrivateKey).toHaveBeenCalledTimes(1);

      const uploaded = JSON.parse(rewrapPGPPrivateKey.mock.calls[0][0] as string);
      const { unwrapPrivateKey } = await import("./keyVault");
      await expect(unwrapPrivateKey(uploaded, NEW_PASSWORD)).resolves.toBe(SECRET);
      await expect(unwrapPrivateKey(uploaded, OLD_PASSWORD)).rejects.toBeTruthy();
    },
    TIMEOUT
  );

  // Preparing with the wrong current password must fail BEFORE the password
  // is changed, so the caller can abort with nothing half-applied.
  it(
    "fails on a wrong current password without uploading anything",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, OLD_PASSWORD);
      getPGPBootstrap.mockResolvedValue(bootstrapFixture({ wrappedPrivateKey: JSON.stringify(envelope) }));
      await session.loadPGPSession();

      await expect(session.prepareRewrappedPGPKey("not-the-old-password", NEW_PASSWORD)).rejects.toBeTruthy();
      expect(rewrapPGPPrivateKey).not.toHaveBeenCalled();
    },
    TIMEOUT
  );

  it("is a no-op for an account with no client-protected key", async () => {
    getPGPBootstrap.mockResolvedValue(bootstrapFixture({ protection: "server", wrappedPrivateKey: "" }));
    await session.loadPGPSession();
    await expect(session.prepareRewrappedPGPKey(OLD_PASSWORD, NEW_PASSWORD)).resolves.toBeNull();
    expect(rewrapPGPPrivateKey).not.toHaveBeenCalled();
  });
});

describe("logout", () => {
  it(
    "drops the unwrapped key so the next person at this browser cannot read mail",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, OLD_PASSWORD);
      getPGPBootstrap.mockResolvedValue(bootstrapFixture({ wrappedPrivateKey: JSON.stringify(envelope) }));
      await session.loadPGPSession();
      await session.unlockPGPSession(OLD_PASSWORD);

      const { isUnlocked } = await import("./keyVault");
      expect(isUnlocked()).toBe(true);

      session.clearPGPSession();
      expect(isUnlocked()).toBe(false);
      expect(session.pgpSessionState().bootstrap).toBeNull();
    },
    TIMEOUT
  );
});
