// The routes and the compose editor are loaded on demand (React.lazy and a
// dynamic import of Quill), which the type checker and the bundler both accept
// without ever proving a page actually arrives. These two cases render the
// real App and wait for it.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { App } from "./App";

const getJSON = vi.fn();

vi.mock("./api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  postJSON: async () => ({}),
  putJSON: async () => ({}),
  deleteJSON: async () => ({}),
  HttpError: class HttpError extends Error {
    status = 0;
    body: unknown = null;
  },
  toErrorMessage: (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback)
}));

// The key session is irrelevant here and its real form pulls in openpgp.
vi.mock("./lib/pgpSession", () => ({
  subscribePGPSession: () => () => {},
  loadPGPSession: async () => ({ bootstrap: null, unlocked: false }),
  clearPGPSession: () => {},
  isClientProtected: () => false,
  needsUnlock: () => false
}));

afterEach(cleanup);

beforeEach(() => {
  vi.clearAllMocks();
  getJSON.mockImplementation(async (url: string) => {
    if (url === "/api/auth/me") {
      return { authenticated: true, userId: "u1", username: "gwen", role: "user" };
    }
    if (url.startsWith("/api/inbox/folders")) return { folders: [] };
    if (url.startsWith("/api/sendas")) return { aliases: [] };
    return {};
  });
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>
  );
}

describe("lazy loading", () => {
  it("resolves a route chunk into a rendered page", async () => {
    renderAt("/settings/appearance");
    expect(await screen.findByRole("heading", { level: 2, name: "Appearance" })).toBeTruthy();
  });

  it("builds the compose editor once the Quill chunk arrives", async () => {
    const user = userEvent.setup();
    const { container } = renderAt("/read");

    await user.click(await screen.findByRole("button", { name: "New Email" }));

    // .ql-editor is Quill's own doing: it exists only if the module loaded and
    // the constructor ran against the compose div.
    await vi.waitFor(() => {
      expect(container.querySelector(".ql-editor")).toBeTruthy();
    });
  });
});
