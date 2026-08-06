import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ChangePasswordForm } from "./ChangePasswordForm";

const postJSON = vi.fn();
const onSuccess = vi.fn();

vi.mock("../api/client", () => ({
  postJSON: (url: string, body: unknown) => postJSON(url, body)
}));

vi.mock("../api/auth", () => ({
  deriveNewCredential: async () => "new-secret",
  deriveCredential: async () => ({ authSecret: "old-secret" }),
  credentialFields: (c: { authSecret: string }, prefix: string) => ({ [`${prefix}AuthSecret`]: c.authSecret })
}));

vi.mock("../lib/authSecret", () => ({
  defaultIterations: () => 600000,
  newLoginSalt: () => "salt"
}));

vi.mock("../lib/pgpSession", () => ({
  rewrappedEnvelopeFor: async () => undefined,
  loadPGPSession: async () => undefined
}));

afterEach(cleanup);

beforeEach(() => {
  postJSON.mockReset();
  onSuccess.mockReset();
  postJSON.mockResolvedValue({ ok: true });
});

describe("ChangePasswordForm", () => {
  it("rejects a new password under the minimum length without calling the server", async () => {
    render(<ChangePasswordForm username="gwen" onSuccess={onSuccess} />);
    await userEvent.type(screen.getByLabelText("Current password"), "currentpassword");
    await userEvent.type(screen.getByLabelText("New password"), "short");
    await userEvent.click(screen.getByRole("button", { name: /update password/i }));

    expect(postJSON).not.toHaveBeenCalled();
    expect((await screen.findByRole("status")).textContent).toContain("at least 14 characters");
  });

  it("calls onSuccess after the credential commits, and does not navigate itself", async () => {
    render(<ChangePasswordForm username="gwen" onSuccess={onSuccess} />);
    await userEvent.type(screen.getByLabelText("Current password"), "currentpassword");
    await userEvent.type(screen.getByLabelText("New password"), "a-long-enough-password");
    await userEvent.click(screen.getByRole("button", { name: /update password/i }));

    await waitFor(() => expect(postJSON).toHaveBeenCalledWith("/api/auth/password", expect.anything()));
    expect(onSuccess).toHaveBeenCalledOnce();
  });

  it("uses the password carried in from sign-in when the current-password field is left blank", async () => {
    render(<ChangePasswordForm username="gwen" initialCurrentPassword="from-signin" onSuccess={onSuccess} />);
    await userEvent.type(screen.getByLabelText("New password"), "a-long-enough-password");
    await userEvent.click(screen.getByRole("button", { name: /update password/i }));

    await waitFor(() => expect(postJSON).toHaveBeenCalled());
  });
});
