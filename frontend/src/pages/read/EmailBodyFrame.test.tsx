import { describe, expect, it, beforeEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import { EmailBodyFrame, FRAME_SANDBOX } from "./EmailBodyFrame";

// The isolation boundary between a sender and a document holding the CSRF
// cookie and (for a client-protected account) an unlocked private key.
//
// jsdom does not enforce sandbox or CSP, so nothing here proves a script is
// blocked — only a browser can. What these pin is what is decidable from the
// markup: the sandbox token set, the absence of allow-scripts, that content goes
// in srcdoc rather than src, and that the frame carries colours instead of
// system keywords.

function frame(): HTMLIFrameElement {
  const el = document.querySelector("iframe");
  if (!el) throw new Error("no iframe rendered");
  return el as HTMLIFrameElement;
}

beforeEach(() => {
  cleanup();
  document.documentElement.style.removeProperty("--ink-strong");
  document.documentElement.style.removeProperty("--bg");
});

describe("EmailBodyFrame sandbox", () => {
  it("never grants allow-scripts", () => {
    // With allow-same-origin also present, allow-scripts voids the sandbox and
    // hands the frame the parent's origin — every reason for the iframe, undone.
    render(<EmailBodyFrame html="<p>hi</p>" />);
    expect(frame().getAttribute("sandbox")).not.toContain("allow-scripts");
    expect(FRAME_SANDBOX).not.toContain("allow-scripts");
  });

  it("grants exactly the tokens it documents and no others", () => {
    render(<EmailBodyFrame html="<p>hi</p>" />);
    const tokens = (frame().getAttribute("sandbox") ?? "").split(/\s+/).filter(Boolean).sort();
    expect(tokens).toEqual(
      ["allow-popups", "allow-popups-to-escape-sandbox", "allow-same-origin"].sort()
    );
  });

  it("does not grant allow-forms or allow-top-navigation", () => {
    // A sender-controlled form is a credential-phishing surface; a frame that
    // can navigate the top level can replace the whole app.
    render(<EmailBodyFrame html="<p>hi</p>" />);
    const sandbox = frame().getAttribute("sandbox") ?? "";
    expect(sandbox).not.toContain("allow-forms");
    expect(sandbox).not.toContain("allow-top-navigation");
    expect(sandbox).not.toContain("allow-modals");
  });

  it("carries content in srcdoc, never as a fetchable src", () => {
    render(<EmailBodyFrame html="<p>secret</p>" />);
    expect(frame().getAttribute("srcdoc")).toContain("<p>secret</p>");
    expect(frame().getAttribute("src")).toBeNull();
  });
});

describe("EmailBodyFrame document", () => {
  it("sets base target so links can open at all", () => {
    render(<EmailBodyFrame html='<a href="https://x.example">x</a>' />);
    expect(frame().getAttribute("srcdoc")).toContain('<base target="_blank">');
  });

  it("suppresses the referrer from inside the document", () => {
    // On the <iframe> element, referrerpolicy governs the fetch of src — and
    // there is no src, so it did nothing. A meta inside the document does
    // apply, and is what stops an unblocked tracking pixel reporting the app's
    // URL back to the sender.
    render(<EmailBodyFrame html='<img src="https://tracker.example/p.gif">' />);
    expect(frame().getAttribute("srcdoc")).toContain('<meta name="referrer" content="no-referrer">');
  });

  it("does not leave the app stylesheet reachable from inside", () => {
    render(<EmailBodyFrame html="<p>hi</p>" />);
    const srcdoc = frame().getAttribute("srcdoc") ?? "";
    expect(srcdoc).not.toContain("<link");
    expect(srcdoc).not.toContain("styles.css");
  });
});

describe("EmailBodyFrame colours", () => {
  it("uses the app's theme colours rather than system keywords", () => {
    // `color: CanvasText` with `color-scheme: normal` resolves to black over a
    // frame backed by the app's --bg. The default theme is #1a1a1e, so every
    // HTML email rendered black-on-near-black.
    document.documentElement.style.setProperty("--ink-strong", "#e8e8ea");
    document.documentElement.style.setProperty("--bg", "#1a1a1e");
    render(<EmailBodyFrame html="<p>hi</p>" />);
    const srcdoc = frame().getAttribute("srcdoc") ?? "";

    expect(srcdoc).toContain("#e8e8ea");
    expect(srcdoc).toContain("#1a1a1e");
    expect(srcdoc).not.toContain("CanvasText");
    expect(srcdoc).not.toContain("background:transparent");
  });

  it("falls back to readable colours when the theme variables are unset", () => {
    render(<EmailBodyFrame html="<p>hi</p>" />);
    const srcdoc = frame().getAttribute("srcdoc") ?? "";
    // Dark ink on light ground: legible either way, never invisible.
    expect(srcdoc).toContain("#111111");
    expect(srcdoc).toContain("#ffffff");
  });

  it("refuses a theme value that is not a colour", () => {
    // These are our own custom properties rather than sender input, but they are
    // interpolated into a <style> block, which is a sink either way.
    document.documentElement.style.setProperty("--ink-strong", "red;} body{display:none");
    render(<EmailBodyFrame html="<p>hi</p>" />);
    const srcdoc = frame().getAttribute("srcdoc") ?? "";
    expect(srcdoc).not.toContain("display:none");
    expect(srcdoc).toContain("#111111");
  });
});

describe("EmailBodyFrame sizing", () => {
  it("starts at a usable height rather than collapsed", () => {
    // Measuring the initial about:blank document set the height to 0 and made
    // every message flash on open.
    render(<EmailBodyFrame html="<p>hi</p>" />);
    const height = frame().style.height;
    expect(height).not.toBe("0px");
    expect(parseInt(height, 10)).toBeGreaterThan(0);
  });

  it("renders without a ResizeObserver present", () => {
    // jsdom has none by default, and the component must degrade rather than
    // throw.
    expect(() => render(<EmailBodyFrame html="<p>hi</p>" />)).not.toThrow();
  });

  it("caps the height a message can demand", async () => {
    // The measured height feeds back into the frame's own containing block, so
    // a percentage-sized element grows the frame which grows the element. The
    // sanitizer strips style/class/id, but DOMPurify allows the presentational
    // `height` attribute, so `<table height="150%">` is a render loop a sender
    // can post. Simulate a body that reports a runaway scrollHeight.
    let observerCallback: ResizeObserverCallback | undefined;
    class RO {
      constructor(cb: ResizeObserverCallback) {
        observerCallback = cb;
      }
      observe() {}
      unobserve() {}
      disconnect() {}
    }
    const original = (globalThis as { ResizeObserver?: unknown }).ResizeObserver;
    (globalThis as { ResizeObserver?: unknown }).ResizeObserver = RO;

    try {
      render(<EmailBodyFrame html="<p>runaway</p>" />);
      const el = frame();
      const body = el.contentDocument?.body;
      if (!body) return; // jsdom without a frame document: nothing to drive.

      Object.defineProperty(body, "scrollHeight", { value: 10_000_000, configurable: true });
      el.dispatchEvent(new Event("load"));
      observerCallback?.([], {} as ResizeObserver);

      const height = parseInt(el.style.height, 10);
      expect(height).toBeLessThanOrEqual(20000);
    } finally {
      (globalThis as { ResizeObserver?: unknown }).ResizeObserver = original;
    }
  });

  it("does not throw when the html prop changes", () => {
    // Switching messages reuses the same iframe element and re-runs the effect
    // while the previous document may still be loaded.
    const { rerender } = render(<EmailBodyFrame html="<p>first</p>" />);
    expect(() => rerender(<EmailBodyFrame html="<p>second</p>" />)).not.toThrow();
    expect(frame().getAttribute("srcdoc")).toContain("second");
  });
});

describe("EmailBodyFrame observer lifecycle", () => {
  it("disconnects every observer it creates", async () => {
    // onLoad runs twice on mount (about:blank is readyState "complete" when the
    // effect fires, then the srcdoc load event fires), so reassigning `observer`
    // without disconnecting strands one observer and one detached document per
    // message opened.
    const connected: Array<{ disconnected: boolean }> = [];
    class TrackingResizeObserver {
      private record = { disconnected: false };
      constructor(_cb: ResizeObserverCallback) {
        connected.push(this.record);
      }
      observe() {}
      unobserve() {}
      disconnect() {
        this.record.disconnected = true;
      }
    }
    const original = (globalThis as { ResizeObserver?: unknown }).ResizeObserver;
    (globalThis as { ResizeObserver?: unknown }).ResizeObserver = TrackingResizeObserver;

    try {
      const { rerender, unmount } = render(<EmailBodyFrame html="<p>one</p>" />);
      // Drive the double-onLoad path explicitly.
      frame().dispatchEvent(new Event("load"));
      frame().dispatchEvent(new Event("load"));
      rerender(<EmailBodyFrame html="<p>two</p>" />);
      frame().dispatchEvent(new Event("load"));
      unmount();

      // Non-vacuity: if the component stopped constructing observers entirely
      // this test would pass while checking nothing. The load path above
      // produces three.
      expect(connected.length, "no observers were constructed; this test is checking nothing").toBeGreaterThan(1);

      const leaked = connected.filter((o) => !o.disconnected);
      expect(leaked, `${leaked.length} of ${connected.length} observers were never disconnected`).toHaveLength(0);
    } finally {
      (globalThis as { ResizeObserver?: unknown }).ResizeObserver = original;
    }
  });
});
