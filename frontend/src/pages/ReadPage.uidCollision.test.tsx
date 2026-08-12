// Regression test for the cross-mailbox verdict collision.
//
// `messageId` on the wire is a bare IMAP UID (adapters/imap/client.go:657,
// `MessageID: strconv.Itoa(uid)`), which is unique only WITHIN a mailbox. The
// local-verdict map used to be keyed on it alone and was never cleared on a
// mailbox change — and because mailbox switching is a search-param navigation
// on /read with no `key`, the component never remounts. Opening UID 42 in one
// folder and then UID 42 in another served the first message's body and its
// green "signature verified" badge for the second.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router";

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

vi.mock("../components/PgpUnlockDialog", () => ({ PgpUnlockDialog: () => null }));

import { ReadPage } from "./ReadPage";

afterEach(cleanup);

// UID 42 in the default folder: a message the attacker really did sign, with
// their own key. Its green badge is correct.
const attackerSigned = {
  messageId: "42",
  sender: "Mallory <mallory@evil.example>",
  subject: "Hello from Mallory",
  body: "<p>server copy of mallory</p>",
  status: "unread",
  atUtc: "2026-08-11T10:00:00Z",
  pgpSigned: true,
  pgpEncrypted: false
};

// UID 42 in Archive: a different message entirely. It carries pgpSigned only
// because pgpDetectSignature matches an armor header in any attachment, which
// any sender can arrange — that is what makes the badge block render at all.
const bankStatement = {
  messageId: "42",
  sender: "Bank <statements@bank.example>",
  subject: "Your March statement",
  body: "<p>real statement</p>",
  status: "read",
  atUtc: "2026-03-01T10:00:00Z",
  pgpSigned: true,
  pgpEncrypted: false
};

function mockEndpoints() {
  getJSON.mockImplementation((url: string) => {
    if (url.startsWith("/api/inbox")) {
      const list = url.includes("mailbox=Archive") ? [bankStatement] : [attackerSigned];
      return Promise.resolve({ tabs: ["Primary"], byTab: { Primary: list } });
    }
    if (url.startsWith("/api/labels")) return Promise.resolve({ configured: [], imap: [] });
    if (url.startsWith("/api/mail/attachments")) return Promise.resolve({ ok: true, attachments: [] });
    return Promise.resolve({});
  });
  postJSON.mockResolvedValue({ ok: true, results: [] });
  getPGPMessagePayload.mockResolvedValue({
    messageId: 42,
    mailbox: "",
    encryptedPayload: "",
    signaturePayload: "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----",
    signedPartBase64: "cGFydA==",
    body: "",
    signerKeys: []
  });
}

function readerBodyHtml(): string {
  const block = document.querySelector(".email-reader-body-frame, .email-reader-body-block");
  if (!block) throw new Error("no message body is rendered");
  return block instanceof HTMLIFrameElement ? (block.getAttribute("srcdoc") ?? "") : block.innerHTML;
}

function renderApp() {
  return render(
    <MemoryRouter initialEntries={["/read"]}>
      <Routes>
        <Route
          path="/read"
          element={
            <>
              <Link to="/read?mailbox=Archive">go-archive</Link>
              <ReadPage />
            </>
          }
        />
      </Routes>
    </MemoryRouter>
  );
}

// Two fixes independently satisfy the first test below — the mailbox-qualified
// cache key and the clear on mailbox change. It fails only when BOTH are
// removed, which is checked and is the point: it pins the user-visible property
// rather than one implementation of it. The composite key is the structural
// half, since a future route could change mailbox without running that effect.
describe("a verified verdict does not cross mailboxes on a shared UID", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEndpoints();
    verifySignedMessage.mockResolvedValue({
      body: "<h1>MALLORY CONTROLLED BODY</h1>",
      bodyMode: "html",
      signed: true,
      verified: true,
      signerFingerprint: "DEADBEEFDEADBEEF"
    });
  });

  it("re-verifies the colliding message instead of reusing the cached verdict", async () => {
    const user = userEvent.setup();
    renderApp();

    await user.click(await screen.findByText("Hello from Mallory"));
    await waitFor(() => expect(readerBodyHtml()).toContain("MALLORY CONTROLLED BODY"));
    expect(getPGPMessagePayload).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "Close" }));
    await user.click(screen.getByText("go-archive"));
    await user.click(await screen.findByText("Your March statement"));

    // The second message must get its own check. Reusing the first message's
    // entry is the bug: it never re-fetched and never re-verified.
    await waitFor(() => expect(getPGPMessagePayload).toHaveBeenCalledTimes(2));
    expect(getPGPMessagePayload).toHaveBeenLastCalledWith("Archive", "42");
  });

  it("asks the server for the mailbox the listing actually used", async () => {
    const user = userEvent.setup();
    renderApp();

    await user.click(await screen.findByText("Hello from Mallory"));
    await waitFor(() => expect(getPGPMessagePayload).toHaveBeenCalled());

    // The default view sends no mailbox parameter and lets the server resolve
    // the account's configured folder. Substituting "INBOX" here made the
    // payload describe a different folder's UID 42.
    expect(getPGPMessagePayload).toHaveBeenLastCalledWith("", "42");
  });
});
