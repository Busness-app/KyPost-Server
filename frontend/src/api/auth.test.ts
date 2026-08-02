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

import { credentialFields, reauthenticate } from "./auth";

describe("credential serialization", () => {
  beforeEach(() => {
    getJSON.mockReset();
    postJSON.mockReset();
    deriveAuthSecret.mockReset();
  });

  it("does not send a derived-auth password", async () => {
    getJSON.mockResolvedValue({ salt: "login-salt", iterations: 600_000 });
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
      credentialFields({ password: "", authSecret: "derived", loginSalt: "salt", loginIterations: 1 }, "old")
    ).toEqual({ oldAuthSecret: "derived" });
  });

  it("does not post credentials when the handshake fails", async () => {
    getJSON.mockRejectedValue(new Error("offline"));

    await expect(reauthenticate("plaintext-password", "123456")).rejects.toThrow("offline");
    expect(postJSON).not.toHaveBeenCalled();
  });
});
