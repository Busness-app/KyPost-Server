import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";

// Deleting a message felt slow because the row survived until a full inbox
// reload came back, and that reload could not be served from cache: the browser
// asks for limit=500, and mailcache.Snapshot only reports a window warm when it
// holds at least `limit` entries, so any mailbox under 500 messages re-fetched
// every body from IMAP on every load. These tests pin both halves of the fix —
// the row goes immediately, and the reload asks for a delta instead of the lot.

const getJSON = vi.fn();
const postJSON = vi.fn();

vi.mock("../api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  postJSON: (url: string, body: unknown) => postJSON(url, body),
  toErrorMessage: (_e: unknown, fallback: string) => fallback
}));

vi.mock("../api/pgp", () => ({ getPGPMessagePayload: vi.fn() }));
vi.mock("../lib/pgpClient", () => ({ decryptMessage: vi.fn(), verifySignedMessage: vi.fn() }));
vi.mock("../lib/pgpSession", () => ({
  isClientProtected: () => false,
  needsUnlock: () => false,
  subscribePGPSession: () => () => {}
}));
vi.mock("../components/PgpUnlockDialog", () => ({ PgpUnlockDialog: () => null }));

import { ReadPage } from "./ReadPage";

afterEach(cleanup);

const keeper = {
  messageId: "10",
  sender: "a@example.com",
  subject: "Keep This",
  status: "read",
  atUtc: "2026-08-01T10:00:00Z"
};
const doomed = {
  messageId: "11",
  sender: "b@example.com",
  subject: "Delete This",
  status: "read",
  atUtc: "2026-08-01T11:00:00Z"
};

function inboxUrls(): string[] {
  return getJSON.mock.calls.map((c) => String(c[0])).filter((u) => u.startsWith("/api/inbox?"));
}

async function selectAndDelete(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByLabelText("Select email Delete This"));
  await user.click(screen.getByRole("button", { name: "Delete" }));
}

describe("deleting a message does not wait on a full inbox reload", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    postJSON.mockResolvedValue({ ok: true, action: "delete", processed: 1, failed: [] });
  });

  it("drops the row as soon as the server accepts the action", async () => {
    let loads = 0;
    getJSON.mockImplementation((url: string) => {
      if (url.startsWith("/api/inbox?")) {
        loads += 1;
        // The reload after the delete never comes back. The row must still go.
        if (loads > 1) return new Promise(() => {});
        return Promise.resolve({
          tabs: ["Primary"],
          byTab: { Primary: [keeper, doomed] },
          cursor: 100
        });
      }
      if (url.startsWith("/api/labels")) return Promise.resolve({ configured: [], imap: [] });
      return Promise.resolve({});
    });

    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ReadPage />
      </MemoryRouter>
    );

    await screen.findByText("Delete This");
    await selectAndDelete(user);

    await waitFor(() => expect(screen.queryByText("Delete This")).toBeNull());
    expect(screen.getByText("Keep This")).toBeDefined();
  });
});

describe("the inbox list syncs by cursor instead of refetching the window", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    postJSON.mockResolvedValue({ ok: true, action: "delete", processed: 1, failed: [] });
  });

  it("sends since=0 on the first load and the returned cursor after that", async () => {
    getJSON.mockImplementation((url: string) => {
      if (url.startsWith("/api/inbox?")) {
        return Promise.resolve({
          tabs: ["Primary"],
          byTab: { Primary: [keeper, doomed] },
          delta: false,
          cursor: 100,
          removed: []
        });
      }
      if (url.startsWith("/api/labels")) return Promise.resolve({ configured: [], imap: [] });
      return Promise.resolve({});
    });

    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ReadPage />
      </MemoryRouter>
    );

    await screen.findByText("Delete This");
    expect(inboxUrls()[0]).toContain("since=0");

    await selectAndDelete(user);

    await waitFor(() => expect(inboxUrls().length).toBeGreaterThan(1));
    expect(inboxUrls()[inboxUrls().length - 1]).toContain("since=100");
  });

  it("prunes rows the delta reports as removed and keeps the ones it does not mention", async () => {
    let loads = 0;
    getJSON.mockImplementation((url: string) => {
      if (url.startsWith("/api/inbox?")) {
        loads += 1;
        if (loads === 1) {
          return Promise.resolve({
            tabs: ["Primary"],
            byTab: { Primary: [keeper, doomed] },
            delta: false,
            cursor: 100,
            removed: []
          });
        }
        // A delta carries only what changed. "Keep This" is absent and must survive.
        return Promise.resolve({
          tabs: ["Primary"],
          byTab: { Primary: [] },
          delta: true,
          cursor: 101,
          removed: ["11"]
        });
      }
      if (url.startsWith("/api/labels")) return Promise.resolve({ configured: [], imap: [] });
      return Promise.resolve({});
    });

    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ReadPage />
      </MemoryRouter>
    );

    await screen.findByText("Delete This");
    await selectAndDelete(user);

    await waitFor(() => expect(screen.queryByText("Delete This")).toBeNull());
    expect(screen.getByText("Keep This")).toBeDefined();
  });
});
