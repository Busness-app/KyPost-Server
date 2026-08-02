import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthContext } from "../auth";
import { ReauthGate, clearReauth } from "./ReauthGate";

// The gate exists for the unattended session: a signed-in browser someone else
// walked up to. What it protects is a screen showing key fingerprints, paired
// devices and a downloadable backup of the PGP private key — so the thing worth
// pinning is that the children do not render until the server has said yes, and
// that the confirmation does not outlive the user it was given for.

const getJSON = vi.fn();
const reauthenticate = vi.fn();

vi.mock("../api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  toErrorMessage: (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback)
}));

vi.mock("../api/auth", () => ({
  reauthenticate: (password: string, code: string) => reauthenticate(password, code)
}));

afterEach(cleanup);

beforeEach(() => {
  getJSON.mockReset();
  reauthenticate.mockReset();
  getJSON.mockResolvedValue({ totpEnabled: true });
  reauthenticate.mockResolvedValue(undefined);
  clearReauth();
});

function renderGate(username = "gwen") {
  return render(
    <AuthContext.Provider value={{ authenticated: true, userId: "u1", username }}>
      <ReauthGate what="your security settings">
        <p>secret settings</p>
      </ReauthGate>
    </AuthContext.Provider>
  );
}

describe("ReauthGate", () => {
  it("hides the page until the step-up succeeds", async () => {
    renderGate();
    expect(screen.queryByText("secret settings")).toBeNull();

    await userEvent.type(screen.getByLabelText("Account password"), "hunter2");
    await userEvent.type(await screen.findByLabelText("Two-factor code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await waitFor(() => expect(screen.getByText("secret settings")).toBeTruthy());
    expect(reauthenticate).toHaveBeenCalledWith("hunter2", "123456");
  });

  it("keeps the page hidden when the server refuses", async () => {
    reauthenticate.mockRejectedValue(new Error("invalid code"));
    renderGate();

    await userEvent.type(screen.getByLabelText("Account password"), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("invalid code"));
    expect(screen.queryByText("secret settings")).toBeNull();
  });

  it("does not ask for a code on an account without TOTP", async () => {
    getJSON.mockResolvedValue({ totpEnabled: false });
    renderGate();

    await waitFor(() => expect(screen.queryByLabelText("Two-factor code")).toBeNull());
  });

  it("still asks for a code when the status call fails", async () => {
    getJSON.mockRejectedValue(new Error("offline"));
    renderGate();

    expect(await screen.findByLabelText("Two-factor code")).toBeTruthy();
  });

  it("does not let one user's confirmation answer for another", async () => {
    renderGate("gwen");
    await userEvent.type(screen.getByLabelText("Account password"), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await waitFor(() => expect(screen.getByText("secret settings")).toBeTruthy());
    cleanup();

    // Same tab, same module memory, different account — the module never
    // reloads across an SPA logout and second sign-in.
    renderGate("hugo");
    expect(screen.queryByText("secret settings")).toBeNull();
  });
});
