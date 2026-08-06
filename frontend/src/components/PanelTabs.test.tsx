import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { PanelTabs, resolvePanelTab } from "./PanelTabs";

afterEach(cleanup);

const TABS = [
  { id: "one", label: "First", body: <p>first body</p> },
  { id: "two", label: "Second", body: <p>second body</p> }
];

function renderTabs(initial = "/settings/mail") {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <PanelTabs tabs={TABS} ariaLabel="Test sections" />
    </MemoryRouter>
  );
}

describe("resolvePanelTab", () => {
  it("opens a real tab", () => {
    expect(resolvePanelTab("two", TABS)).toBe("two");
  });

  it("falls back to the first tab for anything unrecognised, so a bad link still renders", () => {
    expect(resolvePanelTab(null, TABS)).toBe("one");
    expect(resolvePanelTab("", TABS)).toBe("one");
    expect(resolvePanelTab("nope", TABS)).toBe("one");
    expect(resolvePanelTab("../../etc/passwd", TABS)).toBe("one");
  });
});

describe("PanelTabs", () => {
  it("renders only the active tab's body", async () => {
    renderTabs();
    expect(screen.getByText("first body")).toBeTruthy();
    expect(screen.queryByText("second body")).toBeNull();

    await userEvent.click(screen.getByRole("tab", { name: "Second" }));

    expect(screen.getByText("second body")).toBeTruthy();
    expect(screen.queryByText("first body")).toBeNull();
  });

  it("opens the tab named in the URL, which is what the retired routes point at", () => {
    renderTabs("/settings/mail?tab=two");
    expect(screen.getByText("second body")).toBeTruthy();
  });

  it("marks exactly one tab selected, so assistive tech is never told two are", async () => {
    renderTabs();
    const selected = () => screen.getAllByRole("tab").filter((t) => t.getAttribute("aria-selected") === "true");
    expect(selected()).toHaveLength(1);

    await userEvent.click(screen.getByRole("tab", { name: "Second" }));
    expect(selected()).toHaveLength(1);
  });
});
