import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearDraftSnapshot,
  hasContent,
  loadDraftSnapshot,
  restoreNotice,
  saveDraftSnapshot,
  type DraftInput
} from "./draftAutosave";

function draft(over: Partial<DraftInput> = {}): DraftInput {
  return { to: "", cc: "", bcc: "", subject: "", body: "", attachments: [], ...over };
}

const USER = "user-1";

beforeEach(() => {
  window.localStorage.clear();
});

describe("hasContent", () => {
  it("treats an empty Quill editor as empty", () => {
    // Quill leaves this behind on a blank editor. Counting it as content means
    // every opened compose window overwrites a real snapshot with nothing.
    expect(hasContent(draft({ body: "<p><br></p>" }))).toBe(false);
    expect(hasContent(draft({ body: "<p>&nbsp;</p>" }))).toBe(false);
  });

  it("sees real body text through markup", () => {
    expect(hasContent(draft({ body: "<p>hello</p>" }))).toBe(true);
  });

  it("sees any populated field", () => {
    expect(hasContent(draft({ to: "a@b.test" }))).toBe(true);
    expect(hasContent(draft({ subject: "hi" }))).toBe(true);
    expect(hasContent(draft({ attachments: [{ name: "a.pdf", mimeType: "application/pdf", dataBase64: "x", size: 1 }] }))).toBe(true);
  });
});

describe("save/load round trip", () => {
  it("restores every text field", () => {
    saveDraftSnapshot(USER, draft({ to: "a@b.test", cc: "c@d.test", bcc: "e@f.test", subject: "Hi", body: "<p>body</p>" }));
    const got = loadDraftSnapshot(USER);
    expect(got).toMatchObject({ to: "a@b.test", cc: "c@d.test", bcc: "e@f.test", subject: "Hi", body: "<p>body</p>" });
  });

  it("stores attachment names but never their bytes", () => {
    saveDraftSnapshot(
      USER,
      draft({ subject: "x", attachments: [{ name: "report.pdf", mimeType: "application/pdf", dataBase64: "QUJD", size: 3 }] })
    );
    const raw = window.localStorage.getItem(`kypost-compose-draft:${USER}`) ?? "";
    expect(raw).toContain("report.pdf");
    // The bytes are what blow the ~5MB quota; they must not be there.
    expect(raw).not.toContain("QUJD");
    expect(loadDraftSnapshot(USER)?.attachmentNames).toEqual(["report.pdf"]);
  });

  it("clears the stored snapshot when the draft becomes empty", () => {
    saveDraftSnapshot(USER, draft({ subject: "typed something" }));
    expect(loadDraftSnapshot(USER)).not.toBeNull();
    saveDraftSnapshot(USER, draft());
    expect(loadDraftSnapshot(USER)).toBeNull();
  });
});

describe("isolation and cleanup", () => {
  it("does not leak a draft between accounts on a shared browser", () => {
    saveDraftSnapshot(USER, draft({ subject: "private" }));
    expect(loadDraftSnapshot("user-2")).toBeNull();
  });

  it("clearDraftSnapshot removes it", () => {
    saveDraftSnapshot(USER, draft({ subject: "x" }));
    clearDraftSnapshot(USER);
    expect(loadDraftSnapshot(USER)).toBeNull();
  });

  it("ignores a missing user id rather than writing a shared key", () => {
    saveDraftSnapshot("", draft({ subject: "x" }));
    expect(window.localStorage.length).toBe(0);
    expect(loadDraftSnapshot("")).toBeNull();
  });
});

describe("robustness", () => {
  it("returns null for corrupt stored JSON instead of throwing", () => {
    window.localStorage.setItem(`kypost-compose-draft:${USER}`, "{not json");
    expect(loadDraftSnapshot(USER)).toBeNull();
  });

  it("discards a snapshot from a different version rather than guessing its shape", () => {
    window.localStorage.setItem(`kypost-compose-draft:${USER}`, JSON.stringify({ version: 99, subject: "old" }));
    expect(loadDraftSnapshot(USER)).toBeNull();
  });

  it("does not throw when storage is full", () => {
    // Swap the whole storage object rather than spying on a method. Neither
    // spy target works in both environments: jsdom hands out a proxied
    // Storage that an instance-level spy does not intercept, while the Node 26
    // polyfill in src/test/setup.ts does not inherit from Storage.prototype,
    // so a prototype spy misses it there. A spy that silently fails to
    // intercept turns this into an assertion that nothing throws when nothing
    // was asked to throw — green, and worthless.
    const original = Object.getOwnPropertyDescriptor(window, "localStorage");
    const setItem = vi.fn(() => {
      throw new DOMException("QuotaExceededError");
    });
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: { ...window.localStorage, setItem }
    });

    try {
      // A failed autosave must never surface as an exception mid-typing.
      expect(() => saveDraftSnapshot(USER, draft({ subject: "x" }))).not.toThrow();
      expect(setItem).toHaveBeenCalled();
    } finally {
      if (original) {
        Object.defineProperty(window, "localStorage", original);
      }
    }
  });
});

describe("expiry", () => {
  // The stored body is the plaintext of a message that may be about to be
  // PGP-encrypted. Logout clears it, but closing the tab or never logging out
  // does not — so it has to expire on its own.
  function storeWithAge(ageMs: number): void {
    window.localStorage.setItem(
      `kypost-compose-draft:${USER}`,
      JSON.stringify({
        version: 1,
        to: "",
        cc: "",
        bcc: "",
        subject: "secret",
        body: "<p>plaintext</p>",
        attachmentNames: [],
        savedAt: new Date(Date.now() - ageMs).toISOString()
      })
    );
  }

  it("still restores a snapshot from within the window", () => {
    storeWithAge(23 * 60 * 60 * 1000);
    expect(loadDraftSnapshot(USER)?.subject).toBe("secret");
  });

  it("discards a snapshot older than the window", () => {
    storeWithAge(25 * 60 * 60 * 1000);
    expect(loadDraftSnapshot(USER)).toBeNull();
  });

  it("removes the expired plaintext rather than merely refusing to return it", () => {
    storeWithAge(25 * 60 * 60 * 1000);
    loadDraftSnapshot(USER);
    expect(window.localStorage.getItem(`kypost-compose-draft:${USER}`)).toBeNull();
  });

  it("treats an unparseable savedAt as expired, not as fresh", () => {
    // Snapshots written before the expiry check existed have no usable
    // timestamp; those are the oldest plaintext on disk, not the newest.
    window.localStorage.setItem(
      `kypost-compose-draft:${USER}`,
      JSON.stringify({ version: 1, subject: "ancient", attachmentNames: [], savedAt: "" })
    );
    expect(loadDraftSnapshot(USER)).toBeNull();
  });
});

describe("restoreNotice", () => {
  it("names attachments that could not be restored", () => {
    const snap = loadDraftSnapshot(USER) ?? {
      version: 1, to: "", cc: "", bcc: "", subject: "", body: "",
      attachmentNames: ["a.pdf", "b.png"], savedAt: ""
    };
    expect(restoreNotice({ ...snap, attachmentNames: ["a.pdf", "b.png"] })).toContain("a.pdf, b.png");
  });

  it("stays short when there were none", () => {
    expect(restoreNotice({ version: 1, to: "", cc: "", bcc: "", subject: "", body: "", attachmentNames: [], savedAt: "" }))
      .toBe("Restored your unsent draft.");
  });
});
