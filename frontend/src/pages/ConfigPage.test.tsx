import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router";
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

// Lands directly on a given tab via the URL, the same way a bookmarked link
// or reload would, instead of clicking through the tab strip after mount.
function renderConfigPageAt(tab: string, role: AuthState["role"] = "admin") {
  return render(
    <MemoryRouter initialEntries={[`/config?tab=${tab}`]}>
      <AuthContext.Provider value={{ authenticated: true, userId: "u1", username: "admin", role }}>
        <ConfigPage />
      </AuthContext.Provider>
    </MemoryRouter>
  );
}

// Reproduces App.tsx:1263's <Route path="/config" element={<ConfigPage />} />
// alongside a sidebar-style <Link to="/config"> (App.tsx:1219-1225): both
// point at the SAME route, so clicking the link while already on /config
// re-renders ConfigPage in place (never unmounting it) but drops the
// ?tab=... query, which does unmount CardDavAccess.
function renderConfigPageAtRoute(role: AuthState["role"] = "user") {
  return render(
    <MemoryRouter initialEntries={["/config"]}>
      <Link to="/config">Configuration</Link>
      <AuthContext.Provider value={{ authenticated: true, userId: "u1", username: "gwen", role }}>
        <Routes>
          <Route path="/config" element={<ConfigPage />} />
        </Routes>
      </AuthContext.Provider>
    </MemoryRouter>
  );
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

  it("unblocks the switch once the password has been copied", async () => {
    renderConfigPage("user");

    await waitFor(() => expect(screen.getByRole("tab", { name: "Email Settings" })).toBeTruthy());
    await userEvent.click(screen.getByRole("tab", { name: "CardDAV" }));
    await waitFor(() => expect(isSelected("CardDAV")).toBe(true));
    await userEvent.click(await screen.findByRole("button", { name: /generate password/i }));
    expect(await screen.findByText("generated-app-password")).toBeTruthy();

    // Blocked before copying, matching the alert's own "Copy or dismiss" wording.
    await userEvent.click(screen.getByRole("tab", { name: "Email Settings" }));
    expect(isSelected("CardDAV")).toBe(true);

    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
    await userEvent.click(screen.getByRole("button", { name: /^copy$/i }));
    await screen.findByText("Copied to clipboard.");

    // Copying is the other acknowledged-it path — the switch works now, and
    // (unlike Done) the password is still on screen, since Copy doesn't hide it.
    await userEvent.click(screen.getByRole("tab", { name: "Email Settings" }));
    await waitFor(() => expect(isSelected("Email Settings")).toBe(true));
  });

  it("does not permanently lock the tab strip if the section unmounts via a same-route navigation while a password is unacknowledged", async () => {
    // Reproduces the reviewer's finding: the settings sidebar's Link to
    // "/config" matches the same <Route> ConfigPage already renders under,
    // so ConfigPage itself never unmounts — only its ?tab=carddav search
    // param is dropped, which unmounts CardDavAccess without it ever
    // getting a chance to explicitly clear the guard via user action.
    renderConfigPageAtRoute("user");

    await waitFor(() => expect(screen.getByRole("tab", { name: "Email Settings" })).toBeTruthy());
    await userEvent.click(screen.getByRole("tab", { name: "CardDAV" }));
    await waitFor(() => expect(isSelected("CardDAV")).toBe(true));
    await userEvent.click(await screen.findByRole("button", { name: /generate password/i }));
    expect(await screen.findByText("generated-app-password")).toBeTruthy();

    // Same-route navigation, bypassing ConfigPage's own setActiveTab guard entirely.
    await userEvent.click(screen.getByRole("link", { name: "Configuration" }));

    // CardDavAccess is gone — its unmount cleanup must have un-armed the guard.
    await waitFor(() => expect(screen.queryByText("generated-app-password")).toBeNull());
    expect(screen.queryByRole("alert")).toBeNull();

    // The tab strip must be usable again, not stuck forever.
    await userEvent.click(screen.getByRole("tab", { name: "CardDAV" }));
    await waitFor(() => expect(isSelected("CardDAV")).toBe(true));
  });
});

describe("ConfigPage — Remote LLM save reads config fresh", () => {
  it("does not revert fields another panel saved in the meantime, because it re-reads /api/config instead of reusing its stale mount-time copy", async () => {
    // ConfigPage never unmounts on a tab switch (the tab lives in a query
    // param on the same route — see the CardDAV guard tests above), so its
    // own `cfg`, captured once at mount, would otherwise still say
    // timezone: "UTC" even after ApplicationRuntime independently saves a
    // change via saveConfigPatch. Mutating this object between mount and
    // Remote LLM's own save stands in for exactly that.
    const serverConfig = {
      timezone: "UTC",
      logLevel: "info",
      scan: { intervalSeconds: 90 },
      rateLimits: { perMinute: 10, perHour: 20 },
      labels: { allowlist: [] as string[], keywordMappings: {} },
      classifier: { baseUrl: "", apiKey: "", classifyPath: "", apiKeySet: false }
    };
    getJSON.mockImplementation((url: string) => {
      if (url === "/api/config") {
        return Promise.resolve({ ...serverConfig });
      }
      return Promise.resolve({});
    });

    renderConfigPageAt("llm");
    await screen.findByRole("heading", { name: "Remote LLM Model" });

    // Simulate ApplicationRuntime (or LabelRules) having saved elsewhere
    // while the admin stayed on this tab.
    serverConfig.timezone = "Europe/London";
    serverConfig.labels = { allowlist: ["Later"], keywordMappings: {} };

    await userEvent.click(screen.getByRole("button", { name: /save configuration/i }));

    await waitFor(() => expect(putJSON).toHaveBeenCalledWith("/api/config", expect.anything()));
    const [, body] = putJSON.mock.calls[0];
    expect(body.timezone).toBe("Europe/London");
    expect(body.labels.allowlist).toEqual(["Later"]);
  });
});

describe("ConfigPage — page-level status does not duplicate a section's own status", () => {
  it("never shows two 'Configuration saved.' notices at once across a tab switch", async () => {
    renderConfigPageAt("llm");
    await screen.findByRole("heading", { name: "Remote LLM Model" });

    await userEvent.click(screen.getByRole("button", { name: /save configuration/i }));
    await screen.findByText("Configuration saved.");

    await userEvent.click(screen.getByRole("tab", { name: "Application" }));
    await screen.findByRole("heading", { name: "Application" });

    await userEvent.click(screen.getByRole("button", { name: /save configuration/i }));

    await waitFor(() => expect(screen.getAllByText("Configuration saved.")).toHaveLength(1));
  });
});
