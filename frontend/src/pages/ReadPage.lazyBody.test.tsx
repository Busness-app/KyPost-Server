import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";

// The inbox list stopped carrying message bodies: 500 of them to render one
// measured 13.3 MiB per load against 184 KiB without, and the SPA re-requests
// that window every 15 seconds. These tests pin the two halves of the trade —
// the list must ask for no bodies, and the opened message must go and get its
// own — because either half alone is a broken reader.

const getJSON = vi.fn();
const postJSON = vi.fn();

vi.mock("../api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  postJSON: (url: string, body: unknown) => postJSON(url, body),
  toErrorMessage: (_e: unknown, fallback: string) => fallback
}));

vi.mock("../api/pgp", () => ({
  getPGPMessagePayload: vi.fn()
}));

vi.mock("../lib/pgpClient", () => ({
  decryptMessage: vi.fn(),
  verifySignedMessage: vi.fn()
}));

vi.mock("../lib/pgpSession", () => ({
  isClientProtected: () => false,
  needsUnlock: () => false,
  subscribePGPSession: () => () => {}
}));

vi.mock("../components/PgpUnlockDialog", () => ({
  PgpUnlockDialog: () => null
}));

import { ReadPage } from "./ReadPage";

afterEach(cleanup);

// As the server now sends it: metadata only, no body, no bodyMode.
const listed = {
  messageId: "41",
  sender: "news@publisher.example",
  subject: "Weekly Digest",
  status: "read",
  atUtc: "2026-07-27T10:00:00Z"
};

// Search has never carried bodies either (server_inbox.go builds its rows from
// Overview), so opening a result used to show "No message body available."
const found = {
  messageId: "77",
  sender: "someone@example.com",
  subject: "Invoice attached",
  status: "unread",
  atUtc: "2026-07-27T11:00:00Z"
};

function mockEndpoints(bodyResponse: () => Promise<unknown>) {
  getJSON.mockImplementation((url: string) => {
    if (url.startsWith("/api/inbox")) {
      return Promise.resolve({ tabs: ["Primary"], byTab: { Primary: [listed] } });
    }
    if (url.startsWith("/api/mail/body")) {
      return bodyResponse();
    }
    if (url.startsWith("/api/mail/search")) {
      return Promise.resolve({ results: [found] });
    }
    if (url.startsWith("/api/mail/attachments")) {
      return Promise.resolve({ ok: true, attachments: [] });
    }
    return Promise.resolve({});
  });
  postJSON.mockResolvedValue({ ok: true, results: [] });
}

function renderReadPage() {
  return render(
    <MemoryRouter>
      <ReadPage />
    </MemoryRouter>
  );
}

function readerBodyHtml(): string {
  const block = document.querySelector(".email-reader-body-frame, .email-reader-body-block");
  if (!block) throw new Error("no message body is rendered");
  return block instanceof HTMLIFrameElement ? (block.getAttribute("srcdoc") ?? "") : block.innerHTML;
}

function bodyRequests(): string[] {
  return getJSON.mock.calls.map((c) => String(c[0])).filter((u) => u.startsWith("/api/mail/body"));
}

describe("the inbox list no longer carries message bodies", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEndpoints(() => Promise.resolve({ body: "<p>Hello</p>", bodyMode: "html" }));
  });

  it("asks the server for a list without bodies", async () => {
    renderReadPage();
    await waitFor(() => expect(getJSON).toHaveBeenCalled());

    const inboxUrls = getJSON.mock.calls.map((c) => String(c[0])).filter((u) => u.startsWith("/api/inbox?"));
    expect(inboxUrls.length).toBeGreaterThan(0);
    for (const url of inboxUrls) {
      expect(url).toContain("bodies=0");
    }
  });

  it("does not fetch any body until a message is opened", async () => {
    renderReadPage();
    await screen.findByText("Weekly Digest");
    expect(bodyRequests()).toEqual([]);
  });

  it("fetches the opened message's body and renders it", async () => {
    const user = userEvent.setup();
    renderReadPage();

    await user.click(await screen.findByText("Weekly Digest"));
    await waitFor(() => expect(readerBodyHtml()).toContain("Hello"));

    expect(bodyRequests()).toEqual(["/api/mail/body?messageId=41"]);
  });

  it("renders a body opened from search, which never carried one", async () => {
    const user = userEvent.setup();
    renderReadPage();
    await screen.findByText("Weekly Digest");

    await user.type(screen.getByPlaceholderText("Search..."), "invoice");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await user.click(await screen.findByText("Invoice attached"));

    await waitFor(() => expect(readerBodyHtml()).toContain("Hello"));
    expect(bodyRequests()).toContain("/api/mail/body?messageId=77");
  });
});

describe("a body that will not load says so", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEndpoints(() => Promise.reject(new Error("boom")));
  });

  // A failed fetch must not be sticky: the message is reopenable and the
  // second attempt has to actually go out.
  it("retries when the same message is reopened", async () => {
    const user = userEvent.setup();
    renderReadPage();

    await user.click(await screen.findByText("Weekly Digest"));
    await waitFor(() => expect(readerBodyHtml()).toContain("could not load this message"));
    await user.click(screen.getByRole("button", { name: "Close" }));

    // The retry succeeds this time.
    mockEndpoints(() => Promise.resolve({ body: "recovered", bodyMode: "plain" }));
    await user.click(await screen.findByText("Weekly Digest"));
    await waitFor(() => expect(readerBodyHtml()).toContain("recovered"));
  });

  // An empty pane reading "No message body available." would report the
  // message as empty when it is the fetch that failed — the one outcome this
  // change must not introduce.
  it("shows the failure rather than an empty message", async () => {
    const user = userEvent.setup();
    renderReadPage();

    await user.click(await screen.findByText("Weekly Digest"));
    await waitFor(() => expect(readerBodyHtml()).toContain("could not load this message"));
    expect(readerBodyHtml()).not.toContain("No message body available.");
  });
});
