import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { AuthContext, type AuthState } from "../../auth";
import { AutomationPanel } from "./AutomationPanel";

// The sections are covered where they live. What matters here is that this
// panel is entirely per-user: an admin and a non-admin must see exactly the
// same thing, because everything on it belongs to the account viewing it.
vi.mock("../../settings/sections/MyLabels", () => ({
  MyLabels: () => <p>my labels</p>
}));

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
  it("opens on the account's own label list", () => {
    renderPanel("user");
    expect(screen.getByText("my labels")).toBeTruthy();
  });

  it("gives a non-admin their prompt tuning", () => {
    renderPanel("user", "prompt-tuning");
    expect(screen.getByText("prompt tuning")).toBeTruthy();
  });

  it("shows a non-admin and an admin the identical set of tabs", () => {
    renderPanel("user");
    const asUser = tabLabels();
    cleanup();
    renderPanel("admin");

    expect(asUser).toEqual(tabLabels());
  });

  it("carries nothing instance-wide — the house list belongs to Server", () => {
    // Every tab here writes through a withAuth endpoint scoped to the calling
    // account. The house list that seeds a NEW account is a different thing and
    // saves through the admin-only PUT /api/config.
    renderPanel("admin");
    expect(tabLabels()).toEqual(["Your Labels", "Prompt Tuning", "Decisions"]);
  });

  it("opens the decisions tab from the URL", () => {
    renderPanel("user", "decisions");
    expect(screen.getByText("decisions")).toBeTruthy();
    expect(screen.queryByText("prompt tuning")).toBeNull();
  });
});
