import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import type { AuthState } from "../auth";

// A login 401 body is always one of "invalid credentials", "captcha
// verification failed", "security check expired, please try again", or the
// pow wrong-address message. Before this fix, LoginPage discarded the body
// and rendered the same "Login failed. Check username and password." for
// every one of them — so a user whose challenge timed out, or whose phone
// hopped from wifi to cellular mid-solve, was told their *password* was
// wrong, on exactly the two paths where the server had just refunded their
// lockout strike because it was not a credential problem.
//
// These tests exercise the real requestJSON/HttpError (see api/client.ts)
// against a stubbed fetch, rather than mocking the api/client module,
// because the fix depends on HttpError's real .message shape
// (`request failed: ${status} - ${detail}`), which a mock would paper over.

import { LoginPage } from "./LoginPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const auth: AuthState = { authenticated: false };

function renderLoginPage() {
  return render(
    <MemoryRouter>
      <LoginPage auth={auth} onAuthChanged={() => {}} />
    </MemoryRouter>
  );
}

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => "application/json" },
    json: async () => body,
    text: async () => JSON.stringify(body)
  } as unknown as Response;
}

// The real login handler answers with http.Error, which is plain text, not
// JSON — matching that here is what makes this a faithful test of the
// prefix-stripping in loginServerMessage rather than an easier JSON path
// the server never actually takes.
function plainTextResponse(status: number, text: string): Response {
  return {
    ok: false,
    status,
    headers: { get: () => "text/plain; charset=utf-8" },
    text: async () => text
  } as unknown as Response;
}

function stubFetch(loginResponse: Response) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.startsWith("/api/auth/captcha-config")) {
        // No provider configured: the form must not wait on this to submit.
        return Promise.resolve(jsonResponse(404, { error: "not found" }));
      }
      if (url.startsWith("/api/auth/login")) {
        return Promise.resolve(loginResponse);
      }
      return Promise.resolve(jsonResponse(200, {}));
    })
  );
}

async function submit(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText("Username"), "alice");
  await user.type(screen.getByLabelText("Password"), "whatever");
  await user.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("login failure surfaces the server's own message", () => {
  it("shows the pow expiry message instead of the generic credentials message", async () => {
    stubFetch(plainTextResponse(401, "security check expired, please try again"));
    const user = userEvent.setup();
    renderLoginPage();

    await submit(user);

    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toBe("security check expired, please try again")
    );
    expect(screen.queryByText("Login failed. Check username and password.")).toBeNull();
  });

  it("shows the pow wrong-address message instead of the generic credentials message", async () => {
    stubFetch(
      plainTextResponse(401, "your network address changed during the security check, please try again")
    );
    const user = userEvent.setup();
    renderLoginPage();

    await submit(user);

    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toBe(
        "your network address changed during the security check, please try again"
      )
    );
  });

  it("still falls back to the generic message when the server sends no body", async () => {
    // A gateway/CDN 401 with no usable text, or a non-auth 401 shape — the
    // fallback this fix must not remove.
    stubFetch({
      ok: false,
      status: 401,
      headers: { get: () => "text/html" },
      text: async () => "<html><body>blocked</body></html>"
    } as unknown as Response);
    const user = userEvent.setup();
    renderLoginPage();

    await submit(user);

    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toBe("Login failed. Check username and password.")
    );
  });

  it("still shows the rate-limit message for a 429, not the server body", async () => {
    stubFetch(jsonResponse(429, { error: "too many failed attempts, try again later", retryAfterSeconds: 60 }));
    const user = userEvent.setup();
    renderLoginPage();

    await submit(user);

    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toBe(
        "Too many failed attempts. Please wait a few minutes before trying again."
      )
    );
  });
});

it("shows the password form directly to a session that must change its password", () => {
  render(
    <MemoryRouter initialEntries={["/password"]}>
      <LoginPage
        auth={{ authenticated: true, userId: "u1", username: "gwen", mustChangePassword: true }}
        onAuthChanged={async () => {}}
        mode="password"
      />
    </MemoryRouter>
  );

  // No reauth prompt: a user being forced to fix their credential cannot be
  // asked to re-authenticate with the credential they are being made to change.
  expect(screen.getByLabelText("New password")).toBeTruthy();
  expect(screen.queryByText(/confirm it.s you/i)).toBeNull();
});
