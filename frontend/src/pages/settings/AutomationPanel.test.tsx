import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { AuthContext, type AuthState } from "../../auth";
import { AutomationPanel } from "./AutomationPanel";

// The sections themselves are covered where they live. What matters here is
// the gate: Automation moved under Config so non-admins can reach their own
// prompt tuning, which means the admin-only half must not travel with it.
vi.mock("../../admin/sections/PromptTuning", () => ({
  PromptTuning: () => <p>prompt tuning</p>
}));

vi.mock("../../admin/sections/LabelRules", () => ({
  LabelRules: () => <p>label rules</p>
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

describe("AutomationPanel", () => {
  it("gives a non-admin their prompt tuning", () => {
    renderPanel("user");
    expect(screen.getByText("prompt tuning")).toBeTruthy();
  });

  it("hides Label Rules from a non-admin", () => {
    renderPanel("user");
    expect(screen.queryByRole("tab", { name: "Label Rules" })).toBeNull();
  });

  it("does not render Label Rules for a non-admin even when the URL asks for it", () => {
    // Saving label rules is a PUT /api/config, which is withAdmin — the server
    // refuses regardless. This keeps the UI from presenting a form that cannot
    // succeed.
    renderPanel("user", "label-rules");
    expect(screen.queryByText("label rules")).toBeNull();
    expect(screen.getByText("prompt tuning")).toBeTruthy();
  });

  it("shows both tabs to an admin", () => {
    renderPanel("admin");
    expect(screen.getByRole("tab", { name: "Prompt Tuning" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "Label Rules" })).toBeTruthy();
  });
});
