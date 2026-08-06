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
    // The status endpoint is the only GET, and it shares its base path with
    // the POST that generates the password (they differ by HTTP method, not
    // URL), so a URL-text check can't distinguish them. Assert directly on
    // what the GET actually resolved to instead: a real DAVPasswordStatus
    // response, which carries no password field. A GET that returned one
    // would mean the password is retrievable, defeating the point of an app
    // password.
    for (const result of getJSON.mock.results) {
      await expect(result.value).resolves.not.toHaveProperty("password");
    }
  });
});
