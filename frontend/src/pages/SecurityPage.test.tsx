import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { SecurityPage } from "./SecurityPage";

const getJSON = vi.fn();
const postJSON = vi.fn();
const putJSON = vi.fn();
const deleteJSON = vi.fn();

vi.mock("../api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  postJSON: (url: string, body: unknown) => postJSON(url, body),
  putJSON: (url: string, body: unknown) => putJSON(url, body),
  deleteJSON: (url: string, body?: unknown) => deleteJSON(url, body),
  toErrorMessage: (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback)
}));

const SESSION = {
  bootstrap: {
    protection: "client" as const,
    publicKey: "PUB",
    suggestedUserIDs: ["gwen@example.com"],
    displayName: "Gwen",
    migrationAvailable: false
  },
  unlocked: true
};

vi.mock("../lib/pgpSession", () => ({
  subscribePGPSession: (fn: (s: unknown) => void) => {
    fn(SESSION);
    return () => {};
  },
  loadPGPSession: async () => SESSION,
  lockPGPSession: () => {},
  unlockPGPSession: async () => {},
  rewrapUnlockedKeyUnder: async () => {}
}));

const createRecoveryBackup = vi.fn(async () => ({
  backup: { v: 1 },
  secret: "SECRET-ABCD-1234"
}));

vi.mock("../lib/keyVault", () => ({
  createRecoveryBackup: (...a: unknown[]) => createRecoveryBackup(...(a as [])),
  requireUnlockedKey: () => "ARMORED",
  restoreRecoveryBackup: async () => ({}),
  wrapPrivateKey: async () => ({}),
  unlockWithArmoredKey: () => {}
}));

vi.mock("../lib/pgpClient", () => ({
  generateIdentity: async () => ({}),
  importIdentity: async () => ({})
}));

afterEach(cleanup);

beforeEach(() => {
  vi.clearAllMocks();
  // jsdom has no object URL implementation; saveRecoveryBackup needs one.
  (URL as unknown as { createObjectURL: unknown }).createObjectURL = () => "blob:x";
  (URL as unknown as { revokeObjectURL: unknown }).revokeObjectURL = () => {};

  getJSON.mockImplementation((url: string) => {
    if (url === "/api/mfa/status") {
      return Promise.resolve({
        totpEnabled: true,
        recoveryCodesRemaining: 8,
        pushMfaEnabled: false,
        approverDevices: []
      });
    }
    if (url === "/api/pgp/identity") {
      return Promise.resolve({
        fingerprint: "ABCDEF0123456789",
        keyId: "0123456789",
        publicKey: "PUB",
        source: "generated",
        createdAt: "2026-01-01T00:00:00Z"
      });
    }
    if (url === "/api/pgp/discovery") {
      return Promise.resolve({
        autoEncryptWhenKeyKnown: true,
        storeDiscoveredKeys: true,
        advertiseAutocrypt: true,
        publishWKD: true
      });
    }
    if (url.startsWith("/api/pgp/discovery/suppressions")) {
      return Promise.resolve({ suppressions: [] });
    }
    if (url.startsWith("/api/notifications/native/devices")) {
      return Promise.resolve({ devices: [], deliveryMode: "push" });
    }
    if (url.startsWith("/api/contacts")) {
      return Promise.resolve([]);
    }
    return Promise.resolve({});
  });
});

function renderPage(tab = "mail") {
  return render(
    <MemoryRouter initialEntries={[`/security?tab=${tab}`]}>
      <SecurityPage />
    </MemoryRouter>
  );
}

describe("recoverySecret survives a tab switch", () => {
  it("still shows the one-time secret after leaving and returning to Mail", async () => {
    const user = userEvent.setup();
    renderPage("mail");

    await screen.findByRole("button", { name: "Download recovery backup" });
    await user.click(screen.getByRole("button", { name: "Download recovery backup" }));

    await screen.findByText("SECRET-ABCD-1234");

    await user.click(screen.getByRole("tab", { name: "Devices" }));
    expect(screen.queryByText("SECRET-ABCD-1234")).toBeNull();

    await user.click(screen.getByRole("tab", { name: "Mail" }));
    await screen.findByText("SECRET-ABCD-1234");

    // Only one backup was ever created — the secret came back from state,
    // not from a second createRecoveryBackup() call.
    expect(createRecoveryBackup).toHaveBeenCalledTimes(1);
  });
});

describe("SIBLING: recovery codes survive a tab switch", () => {
  it("keeps just-issued recovery codes across Sign-in -> Devices -> Sign-in", async () => {
    const user = userEvent.setup();
    getJSON.mockImplementation((url: string) => {
      if (url === "/api/mfa/status") {
        return Promise.resolve({
          totpEnabled: true,
          recoveryCodesRemaining: 8,
          pushMfaEnabled: false,
          approverDevices: []
        });
      }
      if (url === "/api/pgp/identity") return Promise.reject(new Error("none"));
      if (url.startsWith("/api/notifications/native/devices")) {
        return Promise.resolve({ devices: [], deliveryMode: "push" });
      }
      return Promise.resolve({});
    });
    postJSON.mockImplementation((url: string) => {
      if (url === "/api/mfa/recovery-codes/regenerate") {
        return Promise.resolve({ ok: true, recoveryCodes: ["CODE-AAAA", "CODE-BBBB"] });
      }
      return Promise.resolve({});
    });

    renderPage("signin");
    await user.click(await screen.findByRole("button", { name: "Regenerate recovery codes" }));
    const pw = document.querySelector("form.sec-inline-form input[type=password]") as HTMLInputElement;
    await user.type(pw, "hunter2");
    await user.click(screen.getByRole("button", { name: "Regenerate" }));

    await screen.findByText("CODE-AAAA");

    await user.click(screen.getByRole("tab", { name: "Devices" }));
    await user.click(screen.getByRole("tab", { name: "Sign-in" }));
    await waitFor(() => expect(screen.queryByText("CODE-AAAA")).not.toBeNull());
  });
});

describe("SIBLING: TOTP enrollment secret across a tab switch", () => {
  it("keeps the scanned setup secret across Sign-in -> Devices -> Sign-in", async () => {
    const user = userEvent.setup();
    getJSON.mockImplementation((url: string) => {
      if (url === "/api/mfa/status") {
        return Promise.resolve({
          totpEnabled: false,
          recoveryCodesRemaining: 0,
          pushMfaEnabled: false,
          approverDevices: []
        });
      }
      if (url === "/api/pgp/identity") return Promise.reject(new Error("none"));
      if (url.startsWith("/api/notifications/native/devices")) {
        return Promise.resolve({ devices: [], deliveryMode: "push" });
      }
      return Promise.resolve({});
    });
    postJSON.mockImplementation((url: string) => {
      if (url === "/api/mfa/totp/setup") {
        return Promise.resolve({ secret: "TOTPSECRET123", otpauthUri: "otpauth://totp/x?secret=TOTPSECRET123" });
      }
      return Promise.resolve({});
    });

    renderPage("signin");
    await user.click(await screen.findByRole("button", { name: "Enable 2FA" }));
    await screen.findByText("TOTPSECRET123");

    await user.click(screen.getByRole("tab", { name: "Devices" }));
    await user.click(screen.getByRole("tab", { name: "Sign-in" }));

    // The secret is still there — a naive fix would need a second
    // POST /api/mfa/totp/setup to show something here, and that call mints
    // a DIFFERENT secret, orphaning whatever the user already scanned into
    // their authenticator app.
    await screen.findByText("TOTPSECRET123");
    expect(postJSON).toHaveBeenCalledTimes(1);
  });
});

describe("no two page-level status regions at once", () => {
  it("shows one message region, from either tab", async () => {
    const user = userEvent.setup();
    putJSON.mockRejectedValue(new Error("boom"));
    renderPage("devices");
    await screen.findByRole("button", { name: "App Pull" });
    await user.click(screen.getByRole("button", { name: "App Pull" }));
    await waitFor(() => {
      const notices = document.querySelectorAll(".notice");
      expect(notices.length).toBe(1);
    });
  });
});
