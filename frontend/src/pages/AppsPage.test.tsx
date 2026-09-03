import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppsPage } from "./AppsPage";

afterEach(cleanup);

const platforms = [
  { name: "Test OS", blurb: "", channels: [{ label: "Live Store", href: "https://example.test/store" }, { label: "Soon Store" }] }
];

describe("AppsPage", () => {
  it("links live channels and renders unpublished ones as placeholders", () => {
    render(<AppsPage pwa={{ installed: false, canInstall: true, install: vi.fn() }} platforms={platforms} />);
    const link = screen.getByRole("link", { name: "Live Store" });
    expect(link.getAttribute("href")).toBe("https://example.test/store");
    expect(link.getAttribute("rel")).toBe("noopener noreferrer");
    expect(screen.queryByRole("link", { name: /Soon Store/ })).toBeNull();
    expect(screen.getByText("Soon Store").closest(".app-channel-soon")).not.toBeNull();
  });

  it("explains how to install when the browser never offers it", () => {
    render(<AppsPage pwa={{ installed: false, canInstall: false, install: vi.fn() }} platforms={platforms} />);
    expect(screen.queryByRole("button", { name: "Install web app" })).toBeNull();
    expect(screen.getByText(/Add to Home Screen/)).toBeTruthy();
  });

  it("shows Installed instead of the button once installed", () => {
    render(<AppsPage pwa={{ installed: true, canInstall: true, install: vi.fn() }} platforms={platforms} />);
    expect(screen.queryByRole("button", { name: "Install web app" })).toBeNull();
    expect(screen.getByText("Installed")).toBeTruthy();
  });
});
