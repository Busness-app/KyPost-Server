import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { ApplicationRuntime } from "./ApplicationRuntime";

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

describe("ApplicationRuntime — load failure", () => {
  it("shows the failure message instead of leaving the tab permanently blank", async () => {
    getJSON.mockImplementation((url: string) => {
      if (url === "/api/config") {
        return Promise.reject(new Error("boom"));
      }
      return Promise.resolve({});
    });

    render(<ApplicationRuntime />);

    // Before the fix this returned null on a failed fetch, so the status
    // paragraph carrying this exact message was never in the tree to find.
    await screen.findByText("Failed to load configuration data.");
  });

  it("renders the card shell immediately, before the config fetch resolves", async () => {
    let resolveConfig: (value: unknown) => void = () => {};
    getJSON.mockImplementation((url: string) => {
      if (url === "/api/config") {
        return new Promise((resolve) => {
          resolveConfig = resolve;
        });
      }
      return Promise.resolve({});
    });

    render(<ApplicationRuntime />);

    expect(screen.getByText("Application")).toBeTruthy();

    resolveConfig({});
    await waitFor(() => expect(screen.getByLabelText(/timezone/i)).toBeTruthy());
  });
});
