import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CardDavAccess } from "./CardDavAccess";

const getJSON = vi.fn();
const postJSON = vi.fn();
const deleteJSON = vi.fn();

vi.mock("../../api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  postJSON: (url: string, body: unknown) => postJSON(url, body),
  deleteJSON: (url: string) => deleteJSON(url),
  toErrorMessage: (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback)
}));

afterEach(cleanup);

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
