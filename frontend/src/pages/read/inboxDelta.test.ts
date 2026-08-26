import { describe, expect, it } from "vitest";
import { applyInboxDelta, messageIDsIn, withoutMessages } from "./inboxDelta";
import type { InboxEmail } from "./types";

function email(messageId: string, over: Partial<InboxEmail> = {}): InboxEmail {
  return {
    messageId,
    sender: `${messageId}@example.com`,
    subject: `subject ${messageId}`,
    status: "read",
    atUtc: "2026-08-01T10:00:00Z",
    ...over
  };
}

describe("applyInboxDelta", () => {
  it("keeps messages the delta does not mention", () => {
    const next = applyInboxDelta({ Primary: [email("1"), email("2")] }, { tabs: ["Primary"], byTab: { Primary: [] } });
    expect(next.Primary.map((e) => e.messageId)).toEqual(["1", "2"]);
  });

  it("drops messages named in removed", () => {
    const next = applyInboxDelta(
      { Primary: [email("1"), email("2")] },
      { tabs: ["Primary"], byTab: { Primary: [] }, removed: ["2"] }
    );
    expect(next.Primary.map((e) => e.messageId)).toEqual(["1"]);
  });

  it("inserts new messages", () => {
    const next = applyInboxDelta(
      { Primary: [email("1")] },
      { tabs: ["Primary"], byTab: { Primary: [email("2", { changeType: "new", body: "fresh" })] } }
    );
    expect(next.Primary.map((e) => e.messageId).sort()).toEqual(["1", "2"]);
  });

  // The server sends an updated entry with an empty body on purpose. Taking it
  // literally would blank a body the client already had.
  it("keeps the cached body when an updated entry arrives without one", () => {
    const next = applyInboxDelta(
      { Primary: [email("1", { body: "cached", bodyMode: "html" })] },
      { tabs: ["Primary"], byTab: { Primary: [email("1", { status: "read", changeType: "updated" })] } }
    );
    expect(next.Primary[0].body).toBe("cached");
    expect(next.Primary[0].bodyMode).toBe("html");
  });

  it("takes the server's flags on an updated entry", () => {
    const next = applyInboxDelta(
      { Primary: [email("1", { status: "unread", body: "cached" })] },
      { tabs: ["Primary"], byTab: { Primary: [email("1", { status: "read", changeType: "updated" })] } }
    );
    expect(next.Primary[0].status).toBe("read");
  });

  // A keyword change moves a message between tabs. Patching in place would
  // leave a duplicate behind in the tab it came from.
  it("re-files a message that changed tab instead of duplicating it", () => {
    const next = applyInboxDelta(
      { Primary: [email("1", { body: "cached" })], Receipts: [] },
      {
        tabs: ["Primary", "Receipts"],
        byTab: { Receipts: [email("1", { label: "Receipts", changeType: "updated" })] }
      }
    );
    expect(next.Primary.map((e) => e.messageId)).toEqual([]);
    expect(next.Receipts.map((e) => e.messageId)).toEqual(["1"]);
    expect(next.Receipts[0].body).toBe("cached");
  });

  it("keeps a tab the response declares even when it is empty", () => {
    const next = applyInboxDelta({}, { tabs: ["Primary", "Receipts"], byTab: {} });
    expect(Object.keys(next).sort()).toEqual(["Primary", "Receipts"]);
  });
});

describe("withoutMessages", () => {
  it("drops the named messages from every tab", () => {
    const next = withoutMessages({ Primary: [email("1"), email("2")], Receipts: [email("3")] }, ["2", "3"]);
    expect(next.Primary.map((e) => e.messageId)).toEqual(["1"]);
    expect(next.Receipts).toEqual([]);
  });
});

describe("messageIDsIn", () => {
  it("flattens every tab", () => {
    expect(messageIDsIn({ Primary: [email("1")], Receipts: [email("2")] })).toEqual(new Set(["1", "2"]));
  });
});
