import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { LabelRules } from "./LabelRules";

const getJSON = vi.fn();
const putJSON = vi.fn();

vi.mock("../../api/client", () => ({
  getJSON: (url: string) => getJSON(url),
  putJSON: (url: string, body: unknown) => putJSON(url, body)
}));

afterEach(cleanup);

beforeEach(() => {
  getJSON.mockReset();
  putJSON.mockReset();
});

describe("LabelRules — load guard", () => {
  it("disables Save Configuration until the initial config read lands", async () => {
    let resolveConfig: (value: unknown) => void = () => {};
    getJSON.mockImplementation((url: string) => {
      if (url === "/api/config") {
        return new Promise((resolve) => {
          resolveConfig = resolve;
        });
      }
      // /api/labels
      return Promise.resolve({ configured: [], imap: [] });
    });

    render(<LabelRules />);

    const saveButton = screen.getByRole("button", { name: /save configuration/i }) as HTMLButtonElement;
    expect(saveButton.disabled).toBe(true);

    resolveConfig({ labels: { allowlist: ["Work"], keywordMappings: {} } });
    await waitFor(() => expect(saveButton.disabled).toBe(false));
  });

  it("keeps Save Configuration disabled after a failed load, so a click can never overwrite label rules with empties", async () => {
    getJSON.mockImplementation((url: string) => {
      if (url === "/api/config") {
        return Promise.reject(new Error("boom"));
      }
      return Promise.resolve({ configured: [], imap: [] });
    });

    render(<LabelRules />);

    await screen.findByText("Failed to load configuration data.");
    const saveButton = screen.getByRole("button", { name: /save configuration/i }) as HTMLButtonElement;
    expect(saveButton.disabled).toBe(true);

    // Even if something bypassed the disabled attribute, saveConfigPatch
    // must never fire — that would PUT allowlist: [] over real label rules.
    expect(putJSON).not.toHaveBeenCalled();
  });
});
