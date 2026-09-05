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
  await screen.findByText("Recovery key: test-key");
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

it("keeps paired setup and history collapsed while backup actions stay visible", async () => {
  vi.mocked(getJSON).mockResolvedValue({
    keyId: "paired-key",
    paired: true,
    kyrecoveryUrl: "https://recovery.example.com",
    localCopies: [],
    intervalSec: 900,
    recent: [],
    excluded: "IMAP mail excluded",
  });
  render(<Backup />);
  await screen.findByText("https://recovery.example.com");
  for (const title of [
    "Schedule",
    "Recovery setup and key",
    "Pin the suite key by hand",
    "Recent backup activity",
  ]) {
    const summary = Array.from(document.querySelectorAll("summary")).find(
      (node) => node.textContent === title,
    );
    expect(summary?.parentElement?.hasAttribute("open")).toBe(false);
  }
  expect(screen.getByRole("button", { name: "Back up now" })).toBeDefined();
  expect(
    screen.getByRole("button", { name: "Download capsule" }),
  ).toBeDefined();
});

it("opens setup for a first pairing and leaves the manual key form collapsed", async () => {
  vi.mocked(getJSON).mockResolvedValue({
    paired: false,
    localCopies: [],
    intervalSec: 0,
    recent: [],
  });
  render(<Backup />);
  await waitFor(() =>
    expect(
      screen
        .getByText("Recovery setup and key")
        .parentElement?.hasAttribute("open"),
    ).toBe(true),
  );
  expect(
    screen
      .getByText("Pin the suite key by hand")
      .parentElement?.hasAttribute("open"),
  ).toBe(false);
});

it("shows the pinned fingerprint after pairing collapses setup", async () => {
  const initial = {
    paired: false,
    localCopies: [],
    intervalSec: 0,
    recent: [],
    excluded: "server exclusion sentinel",
  };
  vi.mocked(getJSON)
    .mockResolvedValueOnce(initial)
    .mockResolvedValue({
      ...initial,
      paired: true,
      keyId: "verify-this-fingerprint",
    });
  vi.mocked(postJSON).mockResolvedValue({});
  render(<Backup />);
  await waitFor(() =>
    expect(
      screen
        .getByText("Recovery setup and key")
        .parentElement?.hasAttribute("open"),
    ).toBe(true),
  );
  fireEvent.change(screen.getByLabelText("Account password"), {
    target: { value: "test-password" },
  });
  fireEvent.change(screen.getByLabelText("KyRecovery URL"), {
    target: { value: "https://recovery.example.com" },
  });
  fireEvent.change(screen.getByLabelText("Six-digit pairing code"), {
    target: { value: "123456" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Pair" }));
  await waitFor(() =>
    expect(screen.getByRole("status").textContent).toContain(
      "Fingerprint: verify-this-fingerprint",
    ),
  );
  expect(
    screen.getByText("server exclusion sentinel").closest("details"),
  ).toBeNull();
});

it("renders stored failure reasons as text without breaking on malformed details", async () => {
  vi.mocked(getJSON).mockResolvedValue({
    paired: true,
    keyId: "key",
    localCopies: [],
    intervalSec: 0,
    recent: [
      {
        id: 1,
        action: "admin.backup_run",
        outcome: "failure",
        details: JSON.stringify({ error: "collect failed <img src=x>" }),
      },
      {
        id: 2,
        action: "admin.backup_run",
        outcome: "failure",
        details: "invalid JSON",
      },
      {
        id: 3,
        action: "admin.backup_run",
        outcome: "failure",
        details: '{"error":{}}',
      },
    ],
  });
  render(<Backup />);
  await screen.findByText("collect failed <img src=x>");
  expect(document.querySelector("img")).toBeNull();
  expect(document.querySelectorAll("li")).toHaveLength(3);
});

it("does not claim exclusions when status is unavailable", async () => {
  vi.mocked(getJSON).mockRejectedValue(new Error("status unavailable"));
  render(<Backup />);
  await screen.findByRole("alert");
  expect(screen.queryByText(/IMAP mail is excluded/)).toBeNull();
});
