import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";

// run-4 finding M7: the "Show Remote Content" opt-in was a bare boolean cleared
// by openEmailDetails, so it was only correct for messages opened through that
// one function. The search-results table called setSelected directly. A user
// who unblocked a newsletter's images and then opened an attacker's message
// from search rendered it through the permissive branch having never opted in
// for it — firing every tracking pixel in it, and (with M6) its CSS too.
//
// These are the first component tests in this project. They exist because the
// bug was not in either piece of logic — processEmailHtml is well covered, and
// openEmailDetails does the right thing — but in the wiring between them, which
// is only observable by driving the component.

const getJSON = vi.fn();
const postJSON = vi.fn();

vi.mock("../api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  postJSON: (url: string, body: unknown) => postJSON(url, body),
  toErrorMessage: (_e: unknown, fallback: string) => fallback
}));

const getPGPMessagePayload = vi.fn();
const verifySignedMessage = vi.fn();

vi.mock("../api/pgp", () => ({
  getPGPMessagePayload: (mailbox: string, id: string) => getPGPMessagePayload(mailbox, id)
}));

// The crypto itself is pgpClient.test.ts's business; these tests are about the
// wiring — that a signed message triggers a check at all, and that what the
// check returns is what the reader renders.
vi.mock("../lib/pgpClient", () => ({
  decryptMessage: vi.fn(),
  verifySignedMessage: (part: string, sig: string, keys: unknown[], sender: string) =>
    verifySignedMessage(part, sig, keys, sender)
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

// Testing Library only registers auto-cleanup when vitest runs with globals
// enabled, which this project does not. Without it each test inherits the
// previous one's mounted tree and every query matches twice.
afterEach(cleanup);

const TRACKER = "https://tracker.example/pixel.gif";

// The newsletter the user legitimately unblocks.
const newsletter = {
  messageId: "msg-newsletter",
  sender: "news@publisher.example",
  subject: "Weekly Digest",
  body: `<p>Hello</p><img src="${TRACKER}">`,
  status: "read",
  atUtc: "2026-07-27T10:00:00Z"
};

// The message the attacker wants rendered without an opt-in. Only reachable
// through search, which is the path that used to bypass the reset.
const hostile = {
  messageId: "msg-hostile",
  sender: "attacker@evil.example",
  subject: "Invoice attached",
  body: `<p>Pay now</p><img src="${TRACKER}">`,
  status: "unread",
  atUtc: "2026-07-27T11:00:00Z"
};

function mockEndpoints() {
  getJSON.mockImplementation((url: string) => {
    if (url.startsWith("/api/inbox")) {
      return Promise.resolve({ tabs: ["Primary"], byTab: { Primary: [newsletter] } });
    }
    if (url.startsWith("/api/labels")) {
      return Promise.resolve({ configured: [], imap: [] });
    }
    if (url.startsWith("/api/mail/search")) {
      return Promise.resolve({ results: [hostile] });
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

/**
 * The markup the open reader is showing for the message body.
 *
 * An HTML body renders inside a sandboxed iframe (read/EmailBodyFrame.tsx), so
 * the content lives in the frame's srcdoc rather than in the app's own DOM.
 * Asserting through it keeps these tests about what the user sees rather than
 * about which element holds it.
 */
function readerBodyHtml(): string {
  const block = document.querySelector(".email-reader-body-frame, .email-reader-body-block");
  if (!block) throw new Error("no message body is rendered");
  return block instanceof HTMLIFrameElement ? (block.getAttribute("srcdoc") ?? "") : block.innerHTML;
}

describe("remote-content opt-in is per message (run-4 M7)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEndpoints();
  });

  it("does not carry an opt-in from an inbox message to one opened from search", async () => {
    const user = userEvent.setup();
    renderReadPage();

    // 1. Open the newsletter from the inbox and unblock its images, exactly as
    //    a user reasonably would.
    await user.click(await screen.findByText("Weekly Digest"));
    await waitFor(() => expect(readerBodyHtml()).toContain("[Image Blocked]"));

    await user.click(screen.getByRole("button", { name: "Show Remote Content" }));
    await waitFor(() => expect(readerBodyHtml()).toContain(TRACKER));

    await user.click(screen.getByRole("button", { name: "Close" }));

    // 2. Find the hostile message by search and open it from the results.
    await user.type(screen.getByPlaceholderText("Search..."), "invoice");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await user.click(await screen.findByText("Invoice attached"));

    // 3. It must render blocked. The user never opted in for THIS message.
    await waitFor(() => expect(readerBodyHtml()).toContain("Pay now"));
    expect(readerBodyHtml()).not.toContain(TRACKER);
    expect(readerBodyHtml()).toContain("[Image Blocked]");
    expect(screen.getByRole("button", { name: "Show Remote Content" })).toBeDefined();
  });

  it("re-blocks a message that was unblocked earlier in the session", async () => {
    const user = userEvent.setup();
    renderReadPage();

    await user.click(await screen.findByText("Weekly Digest"));
    await user.click(screen.getByRole("button", { name: "Show Remote Content" }));
    await waitFor(() => expect(readerBodyHtml()).toContain(TRACKER));
    await user.click(screen.getByRole("button", { name: "Close" }));

    // Reopening costs another deliberate click — the grant does not persist
    // across opens, even for the same message.
    await user.click(await screen.findByText("Weekly Digest"));
    await waitFor(() => expect(readerBodyHtml()).toContain("[Image Blocked]"));
    expect(readerBodyHtml()).not.toContain(TRACKER);
  });

  it("still lets the user unblock the message opened from search", async () => {
    const user = userEvent.setup();
    renderReadPage();

    await user.type(screen.getByPlaceholderText("Search..."), "invoice");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await user.click(await screen.findByText("Invoice attached"));

    await waitFor(() => expect(readerBodyHtml()).toContain("[Image Blocked]"));
    await user.click(screen.getByRole("button", { name: "Show Remote Content" }));
    await waitFor(() => expect(readerBodyHtml()).toContain(TRACKER));
  });
});

describe("opening from search goes through openEmailDetails (run-4 M7)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEndpoints();
  });

  // The other half of M7: setSelected left the previous message's attachment
  // list in place and never loaded the new message's, so the reader showed the
  // OLD message's filenames while every download link's href pointed at the
  // NEW message — a link labelled statement.pdf fetching attachment #0 of the
  // attacker's message. Both messages need attachments for this to be visible,
  // since the section only renders when hasAttachments is set.
  it("loads the opened message's attachments instead of keeping the previous message's", async () => {
    getJSON.mockImplementation((url: string) => {
      if (url.startsWith("/api/inbox")) {
        return Promise.resolve({
          tabs: ["Primary"],
          byTab: { Primary: [{ ...newsletter, hasAttachments: true }] }
        });
      }
      if (url.startsWith("/api/labels")) return Promise.resolve({ configured: [], imap: [] });
      if (url.startsWith("/api/mail/search")) {
        return Promise.resolve({ results: [{ ...hostile, hasAttachments: true }] });
      }
      if (url.startsWith("/api/mail/attachments")) {
        const name = url.includes("msg-hostile") ? "payload.exe" : "statement.pdf";
        return Promise.resolve({
          ok: true,
          attachments: [{ index: 0, name, mimeType: "application/octet-stream", size: 1024 }]
        });
      }
      return Promise.resolve({});
    });

    const user = userEvent.setup();
    renderReadPage();

    await user.click(await screen.findByText("Weekly Digest"));
    await waitFor(() => expect(screen.getByText(/statement\.pdf/)).toBeDefined());
    await user.click(screen.getByRole("button", { name: "Close" }));

    await user.type(screen.getByPlaceholderText("Search..."), "invoice");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await user.click(await screen.findByText("Invoice attached"));

    await waitFor(() => expect(screen.getByText(/payload\.exe/)).toBeDefined());
    expect(screen.queryByText(/statement\.pdf/)).toBeNull();
  });

  // Opening from search is opening: it marks the message read, which
  // setSelected did not do.
  it("marks a message opened from search as read", async () => {
    const user = userEvent.setup();
    renderReadPage();

    await user.type(screen.getByPlaceholderText("Search..."), "invoice");
    await user.click(screen.getByRole("button", { name: "Search" }));
    await user.click(await screen.findByText("Invoice attached"));

    await waitFor(() =>
      expect(
        postJSON.mock.calls.some(
          ([url, body]) =>
            url === "/api/inbox/actions" &&
            (body as { action?: string; messageIds?: string[] }).action === "read" &&
            (body as { messageIds?: string[] }).messageIds?.includes("msg-hostile")
        )
      ).toBe(true)
    );
  });
});

// Guards the assumption the search half of M7 rests on: search is scoped to the
// current mailbox, so routing its clicks through openEmailDetails — which marks
// the message read via the current-mailbox action endpoint — acts on the right
// message. If search ever spans mailboxes, that read action becomes wrong and
// this test should fail loudly rather than the bug being found in production.
describe("search scope", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEndpoints();
  });

  it("scopes the search request to a single mailbox", async () => {
    const user = userEvent.setup();
    renderReadPage();

    await user.type(await screen.findByPlaceholderText("Search..."), "invoice");
    await user.click(screen.getByRole("button", { name: "Search" }));

    await waitFor(() => {
      const searchCall = getJSON.mock.calls.map(([url]) => url).find((url: string) => url.startsWith("/api/mail/search"));
      expect(searchCall).toBeDefined();
      expect(searchCall).toContain("mailbox=");
    });
  });
});

// A signed message that is NOT encrypted. This population — mail that is
// authenticated without being secret — is what showed no indicator at all,
// because the whole badge block was nested inside `selected.pgpEncrypted ?`.
const signedMail = {
  messageId: "msg-signed",
  sender: "Sender <sender@example.com>",
  subject: "Signed Notice",
  body: "<p>server copy</p>",
  status: "unread",
  atUtc: "2026-08-11T10:00:00Z",
  pgpSigned: true,
  pgpEncrypted: false
};

describe("signature status on unencrypted signed mail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getJSON.mockImplementation((url: string) => {
      if (url.startsWith("/api/inbox")) {
        return Promise.resolve({ tabs: ["Primary"], byTab: { Primary: [signedMail] } });
      }
      if (url.startsWith("/api/labels")) return Promise.resolve({ configured: [], imap: [] });
      if (url.startsWith("/api/mail/attachments")) return Promise.resolve({ ok: true, attachments: [] });
      return Promise.resolve({});
    });
    postJSON.mockResolvedValue({ ok: true, results: [] });
    getPGPMessagePayload.mockResolvedValue({
      messageId: 1,
      mailbox: "INBOX",
      encryptedPayload: "",
      signaturePayload: "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----",
      signedPartBase64: "cGFydA==",
      body: "server copy",
      signerKeys: []
    });
  });

  it("shows a signature badge, with no encryption badge", async () => {
    verifySignedMessage.mockResolvedValue({
      body: "signed copy",
      bodyMode: "plain",
      signed: true,
      verified: true,
      signerFingerprint: "ABCDEF0123456789",
      signerConflict: false
    });
    const user = userEvent.setup();
    renderReadPage();

    await user.click(await screen.findByText("Signed Notice"));

    expect(await screen.findByText("signature verified")).toBeDefined();
    expect(screen.queryByText("PGP: encrypted")).toBeNull();
  });

  // The badge must describe the bytes on screen. Rendering the server's copy
  // under a verdict computed over a different copy is what makes a signature
  // indicator meaningless.
  it("renders the body parsed out of the verified part, not the server's", async () => {
    verifySignedMessage.mockResolvedValue({
      body: "signed copy",
      bodyMode: "plain",
      signed: true,
      verified: true,
      signerFingerprint: "ABCDEF0123456789",
      signerConflict: false
    });
    const user = userEvent.setup();
    renderReadPage();

    await user.click(await screen.findByText("Signed Notice"));

    await waitFor(() => expect(readerBodyHtml()).toContain("signed copy"));
    expect(readerBodyHtml()).not.toContain("server copy");
  });

  // No key for this sender is the ordinary case for a first-time
  // correspondent, not evidence of forgery — so the copy admits a gap rather
  // than accusing anyone.
  it("distinguishes an unverifiable signature from a mismatched one", async () => {
    verifySignedMessage.mockResolvedValue({
      body: "signed copy",
      bodyMode: "plain",
      signed: true,
      verified: false,
      signerFingerprint: "",
      signerConflict: false
    });
    const user = userEvent.setup();
    renderReadPage();

    await user.click(await screen.findByText("Signed Notice"));

    expect(
      await screen.findByText("signature could not be checked")
    ).toBeDefined();
    expect(screen.queryByText("signature does not match sender")).toBeNull();
  });

  it("keeps the message readable when the payload fetch fails", async () => {
    getPGPMessagePayload.mockRejectedValue(new Error("network"));
    const user = userEvent.setup();
    renderReadPage();

    await user.click(await screen.findByText("Signed Notice"));

    await waitFor(() => expect(readerBodyHtml()).toContain("server copy"));
    expect(
      await screen.findByText("signature could not be checked")
    ).toBeDefined();
  });
});
