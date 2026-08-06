import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { AuthContext, type AuthState } from "../../auth";
import { AutomationPanel } from "./AutomationPanel";

// The sections are covered where they live. What matters here is that this
// panel is entirely per-user: an admin and a non-admin must see exactly the
// same thing, because everything on it belongs to the account viewing it.
vi.mock("../../settings/sections/PromptTuning", () => ({
  PromptTuning: () => <p>prompt tuning</p>
}));

vi.mock("../../settings/sections/Decisions", () => ({
  Decisions: () => <p>decisions</p>
}));

afterEach(cleanup);

function renderPanel(role: AuthState["role"], tab = "") {
  return render(
    <MemoryRouter initialEntries={[`/settings/automation${tab ? `?tab=${tab}` : ""}`]}>
      <AuthContext.Provider value={{ authenticated: true, userId: "u1", role }}>
        <AutomationPanel />
      </AuthContext.Provider>
    </MemoryRouter>
  );
}

function tabLabels() {
  return screen.getAllByRole("tab").map((tab) => tab.textContent);
}

describe("Email Labels panel", () => {
  it("gives a non-admin their prompt tuning", () => {
    renderPanel("user");
    expect(screen.getByText("prompt tuning")).toBeTruthy();
  });

  it("shows a non-admin and an admin the identical set of tabs", () => {
    renderPanel("user");
    const asUser = tabLabels();
    cleanup();
    renderPanel("admin");

    expect(asUser).toEqual(tabLabels());
  });

  it("carries nothing instance-wide — Label Rules belongs to Server", () => {
    // The allowlist saves through PUT /api/config, which is withAdmin. A tab
    // for it here would be a form a non-admin cannot submit.
    renderPanel("admin");
    expect(tabLabels()).toEqual(["Prompt Tuning", "Decisions"]);
  });

  it("opens the decisions tab from the URL", () => {
    renderPanel("user", "decisions");
    expect(screen.getByText("decisions")).toBeTruthy();
    expect(screen.queryByText("prompt tuning")).toBeNull();
  });
});
