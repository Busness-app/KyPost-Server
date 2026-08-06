import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AuthContext, type AuthState } from "../auth";
import { ConfigPage } from "./ConfigPage";

const getJSON = vi.fn();
const postJSON = vi.fn();
const putJSON = vi.fn();
const deleteJSON = vi.fn();

// A single mock of the low-level client covers every section: they all
// (directly or via api/contacts, api/sendas, api/pgp) route through these
// same four functions, which vitest intercepts by resolved module path
// regardless of how deep the importer's relative path is.
vi.mock("../api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  postJSON: (url: string, body: unknown) => postJSON(url, body),
  putJSON: (url: string, body: unknown) => putJSON(url, body),
  deleteJSON: (url: string, body?: unknown) => deleteJSON(url, body),
  toErrorMessage: (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback)
}));

afterEach(cleanup);

function renderConfigPage(role: AuthState["role"] = "user") {
  return render(
    <MemoryRouter>
      <AuthContext.Provider value={{ authenticated: true, userId: "u1", username: "gwen", role }}>
        <ConfigPage />
      </AuthContext.Provider>
    </MemoryRouter>
  );
}

function isSelected(tabName: string): boolean {
  return screen.getByRole("tab", { name: tabName }).getAttribute("aria-selected") === "true";
}

beforeEach(() => {
  getJSON.mockReset();
  postJSON.mockReset();
  putJSON.mockReset();
  deleteJSON.mockReset();

  getJSON.mockImplementation((url: string) => {
    if (url === "/api/contacts/dav-password") {
      return Promise.resolve({ configured: false });
    }
    // Every other GET (config, labels, imap status, send-as aliases,
    // carddav-client config, ...) just needs to resolve so mount effects
    // don't reject; each caller already tolerates a sparse/empty body.
    return Promise.resolve({});
  });
  postJSON.mockImplementation((url: string) => {
    if (url === "/api/contacts/dav-password") {
      return Promise.resolve({ password: "generated-app-password", createdAt: "2026-08-05T00:00:00Z" });
    }
    return Promise.resolve({ ok: true });
  });
});

describe("ConfigPage — CardDAV password tab-switch guard", () => {
  it("blocks a tab switch while a generated password is on screen, and keeps it visible", async () => {
    renderConfigPage("user");

    await waitFor(() => expect(screen.getByRole("tab", { name: "Email Settings" })).toBeTruthy());

    await userEvent.click(screen.getByRole("tab", { name: "CardDAV" }));
    await waitFor(() => expect(isSelected("CardDAV")).toBe(true));

    await userEvent.click(await screen.findByRole("button", { name: /generate password/i }));
    expect(await screen.findByText("generated-app-password")).toBeTruthy();

    // Attempt to switch away — this must be blocked.
    await userEvent.click(screen.getByRole("tab", { name: "Email Settings" }));

    expect(isSelected("CardDAV")).toBe(true);
    expect(isSelected("Email Settings")).toBe(false);
    expect(screen.getByText("generated-app-password")).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toMatch(/before switching tabs/i);
  });

  it("unblocks the switch once the password is dismissed", async () => {
    renderConfigPage("user");

    await waitFor(() => expect(screen.getByRole("tab", { name: "Email Settings" })).toBeTruthy());
    await userEvent.click(screen.getByRole("tab", { name: "CardDAV" }));
    await waitFor(() => expect(isSelected("CardDAV")).toBe(true));
    await userEvent.click(await screen.findByRole("button", { name: /generate password/i }));
    expect(await screen.findByText("generated-app-password")).toBeTruthy();

    // Blocked, same as the previous test.
    await userEvent.click(screen.getByRole("tab", { name: "Email Settings" }));
    expect(isSelected("CardDAV")).toBe(true);

    // The keyboard-accessible way out: acknowledge the password is saved.
    await userEvent.click(screen.getByRole("button", { name: /done/i }));
    await userEvent.click(screen.getByRole("tab", { name: "Email Settings" }));

    await waitFor(() => expect(isSelected("Email Settings")).toBe(true));
  });
});
