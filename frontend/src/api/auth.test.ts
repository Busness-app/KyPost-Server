import { beforeEach, describe, expect, it, vi } from "vitest";

const { getJSON, postJSON, deriveAuthSecret } = vi.hoisted(() => ({
  getJSON: vi.fn(),
  postJSON: vi.fn(),
  deriveAuthSecret: vi.fn()
}));

vi.mock("./client", () => ({ getJSON, postJSON }));
vi.mock("../lib/authSecret", () => ({
  defaultIterations: () => 600_000,
  deriveAuthSecret
}));

import { credentialFields, deriveCredential, reauthenticate } from "./auth";

describe("credential serialization", () => {
  beforeEach(() => {
    getJSON.mockReset();
    postJSON.mockReset();
    deriveAuthSecret.mockReset();
  });

  it("does not send a derived-auth password", async () => {
    // reauthenticate() derives with an empty username, so the request carries the
    // session and the server discloses the account's credential form.
    getJSON.mockResolvedValue({ salt: "login-salt", iterations: 600_000, derivation: "pbkdf2" });
    deriveAuthSecret.mockResolvedValue("derived-secret");

    await reauthenticate("plaintext-password", "123456");

    expect(postJSON).toHaveBeenCalledWith("/api/auth/step-up", {
      authSecret: "derived-secret",
      code: "123456"
    });
  });

  it("keeps the password only for legacy accounts", () => {
    expect(credentialFields({ password: "legacy", authSecret: "", loginSalt: "", loginIterations: 0 })).toEqual({
      password: "legacy"
    });
    expect(
      credentialFields(
        { password: "", authSecret: "derived", loginSalt: "salt", loginIterations: 1, derivation: "pbkdf2" },
        "old"
      )
    ).toEqual({ oldAuthSecret: "derived" });
  });

  // The server never returns an empty salt — a legacy or nonexistent account
  // gets a stable SYNTHETIC one so the endpoint cannot be used to enumerate
  // accounts. So "no salt" does not mean "legacy", and a client that inferred it
  // that way sent authSecret-only and locked every legacy account out of sign-in.
  it("sends both forms when the server has not said which the account stores", () => {
    expect(
      credentialFields({ password: "plaintext", authSecret: "derived", loginSalt: "synthetic", loginIterations: 600_000 })
    ).toEqual({ password: "plaintext", authSecret: "derived" });
  });

  it("sends only the password when the server says the account is legacy", () => {
    expect(
      credentialFields({
        password: "plaintext",
        authSecret: "derived",
        loginSalt: "synthetic",
        loginIterations: 600_000,
        derivation: "legacy"
      })
    ).toEqual({ password: "plaintext" });
  });

  it("sign-in sends both forms against a legacy account's synthetic salt", async () => {
    // Exactly what the server hands an unconverted account: a non-empty synthetic
    // salt and NO derivation hint (the request is unauthenticated).
    getJSON.mockResolvedValue({ salt: "c2FsdHNhbHRzYWx0c2FsdA==", iterations: 600_000 });
    deriveAuthSecret.mockResolvedValue("derived-secret");

    const credential = await deriveCredential("someone", "plaintext-password");

    expect(credentialFields(credential)).toEqual({
      password: "plaintext-password",
      authSecret: "derived-secret"
    });
  });

  it("does not post credentials when the handshake fails", async () => {
    getJSON.mockRejectedValue(new Error("offline"));

    await expect(reauthenticate("plaintext-password", "123456")).rejects.toThrow("offline");
    expect(postJSON).not.toHaveBeenCalled();
  });
});
