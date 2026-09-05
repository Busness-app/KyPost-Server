import { afterEach, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { Backup } from "./Backup";
import { getJSON, postJSON } from "../../api/client";
vi.mock("../../api/client", () => ({
  getJSON: vi.fn(),
  postJSON: vi.fn(),
  putJSON: vi.fn(),
  deleteJSON: vi.fn(),
  postBlob: vi.fn(),
  toErrorMessage: (e: unknown) => String(e),
}));
vi.mock("../../api/auth", () => ({
  deriveCredential: vi.fn(async () => ({ authSecret: "derived-test-only" })),
  credentialFields: () => ({ authSecret: "derived-test-only" }),
}));
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
it("requires a credential and sends the derived form for backup", async () => {
  vi.mocked(getJSON).mockResolvedValue({
    keyId: "test-key",
    paired: false,
    localDir: "/backups",
    localCopies: [],
    intervalSec: 0,
    recent: [],
    excluded: "IMAP mail excluded",
  });
  vi.mocked(postJSON).mockResolvedValue({});
  render(<Backup />);
  await screen.findByText("test-key");
  const run = screen.getByRole("button", { name: "Back up now" });
  expect(run.hasAttribute("disabled")).toBe(true);
  fireEvent.change(screen.getByLabelText("Account password"), {
    target: { value: "local-password" },
  });
  fireEvent.click(run);
  await waitFor(() => expect(postJSON).toHaveBeenCalled());
  expect(vi.mocked(postJSON).mock.calls[0]?.[0]).toBe("/api/admin/backup/run");
  const body = vi.mocked(postJSON).mock.calls[0]?.[1];
  expect(JSON.stringify(body)).toContain("derived-test-only");
  expect(JSON.stringify(body)).not.toContain("local-password");
  await waitFor(() =>
    expect(
      screen.getByLabelText("Account password").getAttribute("value"),
    ).toBe(""),
  );
});
