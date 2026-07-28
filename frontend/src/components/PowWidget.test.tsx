import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
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
    signature: "sig"
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
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
