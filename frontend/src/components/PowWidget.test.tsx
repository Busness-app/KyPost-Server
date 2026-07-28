import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PowWidget } from "./PowWidget";

const encoder = new TextEncoder();

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function challengeFor(number: number, maxnumber = 50) {
  const salt = "abcdef0123456789abcdef0123456789";
  return {
    algorithm: "SHA-256",
    salt,
    challenge: await sha256Hex(salt + number),
    maxnumber,
    expires: Math.floor(Date.now() / 1000) + 300,
    clientip: "203.0.113.7",
    signature: "sig"
  };
}

beforeEach(() => {
  // jsdom reports window.isSecureContext === false while still exposing a
  // working crypto.subtle — the opposite of a browser, where the two travel
  // together. Every test below except the secure-context ones is about what
  // happens once the check can actually run, so give them a secure context.
  vi.stubGlobal("isSecureContext", true);
});

afterEach(() => {
  vi.unstubAllGlobals();
  // Testing Library only registers auto-cleanup when vitest runs with globals
  // enabled, which this project does not. Without it each test inherits the
  // previous one's mounted tree and every query matches more than once.
  cleanup();
});

function stubFetch(body: unknown, ok = true) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok,
      status: ok ? 200 : 503,
      headers: new Headers({ "Content-Type": "application/json" }),
      json: async () => body,
      text: async () => JSON.stringify(body)
    })
  );
}

describe("PowWidget", () => {
  it("fetches a challenge, solves it, and hands up the token", async () => {
    stubFetch(await challengeFor(7));
    const onToken = vi.fn();

    render(<PowWidget onToken={onToken} />);

    await waitFor(() => expect(onToken).toHaveBeenCalledTimes(1));
    const solution = JSON.parse(atob(onToken.mock.calls[0][0]));
    expect(solution.number).toBe(7);
  });

  it("reports a completed check to the user", async () => {
    stubFetch(await challengeFor(3));
    render(<PowWidget onToken={vi.fn()} />);
    await waitFor(() => expect(screen.getByText(/verified/i)).toBeTruthy());
  });

  it("asks for HTTPS instead of throwing when the page is not a secure context", async () => {
    // crypto.subtle is [SecureContext]: over http://192.168.1.x:5866 — which
    // the shipped docker-compose serves — it is undefined, sha256Hex throws a
    // TypeError, no token is ever produced and nobody can sign in. Every layer
    // of testing hid this: jsdom and Node expose crypto.subtle unconditionally
    // and http://localhost *is* a secure context, so the condition has to be
    // stubbed rather than reproduced.
    vi.stubGlobal("isSecureContext", false);
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const onToken = vi.fn();

    render(<PowWidget onToken={onToken} />);

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/HTTPS/i);
    expect(alert.textContent).toMatch(/administrator/i);
    expect(onToken).not.toHaveBeenCalled();
    // Detected before anything is attempted: no point spending a challenge
    // the browser cannot solve.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("asks for HTTPS when crypto.subtle is missing even if isSecureContext lies", async () => {
    vi.stubGlobal("crypto", {});
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    render(<PowWidget onToken={vi.fn()} />);

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/HTTPS/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("surfaces a failure instead of silently handing up nothing", async () => {
    // The login button stays enabled, so a user who cannot get a token must
    // be told why rather than watching the form reject them with no reason.
    stubFetch({ error: "too many challenge requests" }, false);
    const onToken = vi.fn();

    render(<PowWidget onToken={onToken} />);

    await waitFor(() => expect(screen.getByRole("alert")).toBeTruthy());
    expect(onToken).not.toHaveBeenCalled();
  });
});
