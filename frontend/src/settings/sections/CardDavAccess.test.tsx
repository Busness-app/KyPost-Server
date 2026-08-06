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
