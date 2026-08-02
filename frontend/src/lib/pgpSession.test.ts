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
    "returns an envelope that opens with the new password and not the old",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, OLD_PASSWORD);
      getPGPBootstrap.mockResolvedValue(bootstrapFixture({ wrappedPrivateKey: JSON.stringify(envelope) }));
      await session.loadPGPSession();

      const rewrapped = await session.rewrappedEnvelopeFor(OLD_PASSWORD, NEW_PASSWORD);
      expect(rewrapped).not.toBeNull();

      // Nothing is uploaded here at all any more. The envelope is returned as
      // DATA so the caller can send it in the same request as the credential —
      // the two used to be separate requests, and a dropped connection between
      // them stranded the key permanently.
      expect(rewrapPGPPrivateKey).not.toHaveBeenCalled();

      const parsed = JSON.parse(rewrapped!);
      const { unwrapPrivateKey } = await import("./keyVault");
      await expect(unwrapPrivateKey(parsed, NEW_PASSWORD)).resolves.toBe(SECRET);
      await expect(unwrapPrivateKey(parsed, OLD_PASSWORD)).rejects.toBeTruthy();
    },
    TIMEOUT
  );

  // Rewrapping with the wrong current password must fail BEFORE anything is
  // sent, so the caller aborts with nothing half-applied.
  it(
    "fails on a wrong current password without uploading anything",
    async () => {
      const envelope = await wrapPrivateKey(SECRET, OLD_PASSWORD);
      getPGPBootstrap.mockResolvedValue(bootstrapFixture({ wrappedPrivateKey: JSON.stringify(envelope) }));
      await session.loadPGPSession();

      await expect(session.rewrappedEnvelopeFor("not-the-old-password", NEW_PASSWORD)).rejects.toBeTruthy();
      expect(rewrapPGPPrivateKey).not.toHaveBeenCalled();
    },
    TIMEOUT
  );

  it("is a no-op for an account with no client-protected key", async () => {
    getPGPBootstrap.mockResolvedValue(bootstrapFixture({ protection: "server", wrappedPrivateKey: "" }));
    await session.loadPGPSession();
    await expect(session.rewrappedEnvelopeFor(OLD_PASSWORD, NEW_PASSWORD)).resolves.toBeNull();
    expect(rewrapPGPPrivateKey).not.toHaveBeenCalled();
  });
});

// The recovery path for an envelope that is out of step with the account
// password. Before this existed there was none: every rewrap derived from the
// CURRENT password, and a stale envelope by definition does not open with it, so
// the only escape was deleting the identity and losing every message ever
// encrypted to it.
describe("stale-envelope recovery", () => {
  it(
    "re-seals the already-unlocked key under the current password",
    async () => {
      // The stored envelope is sealed under an OLDER password than the account's.
      const stale = await wrapPrivateKey(SECRET, OLD_PASSWORD);
      getPGPBootstrap.mockResolvedValue(bootstrapFixture({ wrappedPrivateKey: JSON.stringify(stale) }));
      await session.loadPGPSession();

      // The user unlocks with the older password, as the UI instructs.
      await session.unlockPGPSession(OLD_PASSWORD);

      rewrapPGPPrivateKey.mockResolvedValue({ ok: true });
      await session.rewrapUnlockedKeyUnder(NEW_PASSWORD);

      expect(rewrapPGPPrivateKey).toHaveBeenCalledTimes(1);
      const uploaded = JSON.parse(rewrapPGPPrivateKey.mock.calls[0][0] as string);
      const { unwrapPrivateKey } = await import("./keyVault");
      await expect(unwrapPrivateKey(uploaded, NEW_PASSWORD)).resolves.toBe(SECRET);
      // The CURRENT account password also goes up as the step-up credential:
      // the server refuses to overwrite an envelope it cannot inspect on a
      // session alone. Sending the old one here would fail the confirmation and
      // leave the stale envelope in place — the exact state this recovers from.
      expect(rewrapPGPPrivateKey.mock.calls[0][1]).toBe(NEW_PASSWORD);
    },
    TIMEOUT
  );

  it("refuses when the vault is locked, rather than uploading garbage", async () => {
    getPGPBootstrap.mockResolvedValue(bootstrapFixture({ wrappedPrivateKey: "" }));
    await session.loadPGPSession();
    session.lockPGPSession();
    await expect(session.rewrapUnlockedKeyUnder(NEW_PASSWORD)).rejects.toBeTruthy();
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
