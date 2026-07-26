import { describe, expect, it } from "vitest";
import { firstAddressFromText, listAddressesFromText } from "./addressText";

// A display name is attacker-controlled and is NOT authenticated by DKIM, SPF,
// or DMARC — a message can be perfectly aligned and still carry a display name
// containing someone else's address. Reply/Reply All/Forward feed from these
// functions and carry the quoted original, so picking the wrong address out of
// a From header sends a thread to a party who never sent it.
//
// These six vectors are shared verbatim with the Android and Linux clients so
// all three agree on the rule: the real address is the LAST angle-addr, never
// the first email-shaped run of characters.
describe("firstAddressFromText", () => {
  it("reads an ordinary display name plus address", () => {
    expect(firstAddressFromText("Bob <bob@corp.com>")).toBe("bob@corp.com");
  });

  // The confidentiality bug. Scanning for the first email-shaped substring
  // found the address inside the *display name*, so a reply — quoted original
  // attached — went to the attacker while the header still showed Bob.
  it("ignores an address planted in the display name", () => {
    expect(firstAddressFromText('"evil@attacker.tld" <bob@corp.com>')).toBe("bob@corp.com");
  });

  // The mirror case: the real sender is the attacker, and the display name is
  // dressed up to look like Bob. The reply must go where the mail came from.
  it("uses the real address when the display name mimics an angle-addr", () => {
    expect(firstAddressFromText('"Bob <bob@corp.com>" <evil@attacker.tld>')).toBe("evil@attacker.tld");
  });

  it("passes through a bare address", () => {
    expect(firstAddressFromText("bob@corp.com")).toBe("bob@corp.com");
  });

  it("handles a comma inside a quoted display name", () => {
    expect(firstAddressFromText('"a, b" <bob@corp.com>')).toBe("bob@corp.com");
  });

  it("returns empty for a value with no address at all", () => {
    expect(firstAddressFromText("Unknown sender")).toBe("");
  });

  it("returns empty for empty input", () => {
    expect(firstAddressFromText("")).toBe("");
  });
});

describe("listAddressesFromText", () => {
  it("splits a recipient list on commas", () => {
    expect(listAddressesFromText("Bob <bob@corp.com>, carol@corp.com")).toEqual(["bob@corp.com", "carol@corp.com"]);
  });

  // Reply All previously leaked the display-name address into the recipient
  // list, silently adding the attacker to every reply.
  it("never picks up an address hidden in a display name", () => {
    expect(listAddressesFromText('"evil@attacker.tld" <bob@corp.com>')).toEqual(["bob@corp.com"]);
  });

  it("does not split on a comma inside a quoted display name", () => {
    expect(listAddressesFromText('"Smith, Bob" <bob@corp.com>, carol@corp.com')).toEqual([
      "bob@corp.com",
      "carol@corp.com"
    ]);
  });

  it("de-duplicates case-insensitively", () => {
    expect(listAddressesFromText("bob@corp.com, BOB@CORP.COM")).toEqual(["bob@corp.com"]);
  });

  it("drops entries with no address", () => {
    expect(listAddressesFromText("Unknown sender, bob@corp.com")).toEqual(["bob@corp.com"]);
  });

  it("returns nothing for empty input", () => {
    expect(listAddressesFromText("")).toEqual([]);
  });
});
