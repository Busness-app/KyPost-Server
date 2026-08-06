import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { AuthContext } from "../../../auth";
import { Password } from "./Password";

// The form itself is covered by ChangePasswordForm.test.tsx. What matters here
// is the wiring: this section must hand the form the signed-in user and its own
// lede, and must not navigate anywhere on success — that is the difference
// between this entry point and the forced reset at /password.
vi.mock("../../../components/ChangePasswordForm", () => ({
  ChangePasswordForm: ({ username, lede }: { username: string; lede: string }) => (
    <div>
      <p>form for {username}</p>
      <p>{lede}</p>
    </div>
  )
}));

afterEach(cleanup);

function renderPassword(username: string | undefined = "gwen") {
  return render(
    <AuthContext.Provider value={{ authenticated: true, userId: "u1", username }}>
      <Password />
    </AuthContext.Provider>
  );
}

describe("Password", () => {
  it("renders the shared form for the signed-in user", () => {
    renderPassword();
    expect(screen.getByText("form for gwen")).toBeTruthy();
  });

  it("tells the user their PGP key is re-wrapped, which is what makes this safe", () => {
    renderPassword();
    expect(screen.getByText(/PGP key is re-encrypted under the new password/i)).toBeTruthy();
  });

  it("renders without a username rather than throwing, since the gate already proved the session", () => {
    renderPassword(undefined);
    expect(screen.getByText(/form for/)).toBeTruthy();
  });
});
