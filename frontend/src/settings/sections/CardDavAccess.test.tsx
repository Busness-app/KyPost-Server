import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CardDavAccess } from "./CardDavAccess";
import { releaseSecretHold, secretHoldReason } from "../../lib/secretHold";

const getJSON = vi.fn();
const postJSON = vi.fn();
const deleteJSON = vi.fn();

vi.mock("../../api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  postJSON: (url: string, body: unknown) => postJSON(url, body),
  deleteJSON: (url: string) => deleteJSON(url),
  toErrorMessage: (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback)
}));

afterEach(() => {
  cleanup();
  releaseSecretHold();
});

beforeEach(() => {
  getJSON.mockReset();
  postJSON.mockReset();
  deleteJSON.mockReset();
  getJSON.mockResolvedValue({ configured: false });
  postJSON.mockResolvedValue({ password: "generated-app-password" });
});

describe("CardDavAccess", () => {
  it("reveals a generated password, and never asks the server to hand it back", async () => {
    render(<CardDavAccess setConfigStatus={vi.fn()} />);
    await waitFor(() => expect(getJSON).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: /generate/i }));

    expect(await screen.findByText("generated-app-password")).toBeTruthy();
    // The status endpoint (GET /api/contacts/dav-password) shares its base
    // path with the POST that generates the password — they differ only by
    // HTTP method — so this pins the exact set of GET calls made rather than
    // inspecting response bodies (a fixture-shape check can't fail no matter
    // what the component does with the response, since the test itself
    // controls the fixture). Any GET beyond the status check — e.g. a
    // "/reveal" endpoint the component reads the password back from — fails
    // this.
    expect(getJSON.mock.calls.map(([url]) => url)).toEqual([
      "/api/contacts/dav-password",
      "/api/contacts/dav-password"
    ]);
  });
});

// The sidebar bypass. The page-level guard only covers a tab strip; a sidebar
// link is a route change that unmounts this component and destroys the only
// copy of the password without ever reaching that guard. This section holds
// navigation itself, at the source, so the protection applies wherever it is
// rendered.
describe("CardDavAccess navigation hold", () => {
  it("holds navigation while an unacknowledged password is on screen", async () => {
    postJSON.mockResolvedValue({ password: "generated-app-password" });
    render(<CardDavAccess />);
    await waitFor(() => expect(getJSON).toHaveBeenCalled());

    expect(secretHoldReason()).toBe("");
    await userEvent.click(screen.getByRole("button", { name: /generate/i }));
    await screen.findByText("generated-app-password");

    expect(secretHoldReason()).toContain("before leaving");
  });

  it("releases the hold on unmount, so navigating away cannot strand it", async () => {
    postJSON.mockResolvedValue({ password: "generated-app-password" });
    const view = render(<CardDavAccess />);
    await waitFor(() => expect(getJSON).toHaveBeenCalled());
    await userEvent.click(screen.getByRole("button", { name: /generate/i }));
    await screen.findByText("generated-app-password");

    view.unmount();

    // A hold that outlived its holder would block every link in the app with
    // no way to clear it.
    expect(secretHoldReason()).toBe("");
  });
});

describe("CardDavAccess copy edge cases", () => {
  it("explains itself when the Clipboard API is absent, rather than doing nothing", async () => {
    // No clipboard is the normal case on a non-secure origin — plain-HTTP LAN
    // access to a self-hosted server. The guard tells the user to copy or
    // dismiss, so a Copy button that silently no-ops is a dead end.
    const originalClipboard = navigator.clipboard;
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
    try {
      postJSON.mockResolvedValue({ password: "generated-app-password" });
      render(<CardDavAccess />);
      await waitFor(() => expect(getJSON).toHaveBeenCalled());
      await userEvent.click(screen.getByRole("button", { name: /generate/i }));
      await screen.findByText("generated-app-password");

      await userEvent.click(screen.getByRole("button", { name: "Copy" }));

      expect(await screen.findByText(/secure \(HTTPS\) connection/i)).toBeTruthy();
      // Still armed: nothing was copied, so nothing was saved.
      expect(secretHoldReason()).toContain("before leaving");
    } finally {
      Object.defineProperty(navigator, "clipboard", { value: originalClipboard, configurable: true });
    }
  });

  it("does not let a late copy acknowledge a newer password", async () => {
    let settleCopy: () => void = () => {};
    const writeText = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          settleCopy = resolve;
        })
    );
    const originalClipboard = navigator.clipboard;
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    try {
      postJSON.mockResolvedValueOnce({ password: "password-one" });
      render(<CardDavAccess />);
      await waitFor(() => expect(getJSON).toHaveBeenCalled());
      await userEvent.click(screen.getByRole("button", { name: /generate/i }));
      await screen.findByText("password-one");

      await userEvent.click(screen.getByRole("button", { name: "Copy" }));

      // A second password arrives before the clipboard promise settles.
      postJSON.mockResolvedValueOnce({ password: "password-two" });
      await userEvent.click(screen.getByRole("button", { name: /generate/i }));
      await screen.findByText("password-two");

      settleCopy();
      await waitFor(() => expect(writeText).toHaveBeenCalledWith("password-one"));

      // password-two was never copied, so the guard must stay armed and the
      // screen must not claim it reached the clipboard.
      expect(secretHoldReason()).toContain("before leaving");
      expect(screen.queryByText("Copied to clipboard.")).toBeNull();
    } finally {
      Object.defineProperty(navigator, "clipboard", { value: originalClipboard, configurable: true });
    }
  });
});
