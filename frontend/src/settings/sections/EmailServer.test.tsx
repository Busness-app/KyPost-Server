import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EmailServer } from "./EmailServer";

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
  getJSON.mockResolvedValue({ configured: true, host: "imap.example.com", port: 993, username: "gwen", mailbox: "INBOX" });
  postJSON.mockResolvedValue({ ok: true });
});

describe("EmailServer", () => {
  it("loads the stored settings on mount without being told to", async () => {
    render(<EmailServer refreshLabels={vi.fn().mockResolvedValue(undefined)} />);
    await waitFor(() => expect(screen.getByDisplayValue("imap.example.com")).toBeTruthy());
  });

  it("saves the form on its own, with no parent involvement", async () => {
    const refreshLabels = vi.fn().mockResolvedValue(undefined);
    render(<EmailServer refreshLabels={refreshLabels} />);
    await waitFor(() => expect(screen.getByDisplayValue("imap.example.com")).toBeTruthy());
    await userEvent.type(screen.getByLabelText(/password/i), "app-password");
    await userEvent.click(screen.getByRole("button", { name: /save email settings/i }));

    await waitFor(() => expect(postJSON).toHaveBeenCalled());
  });
});
