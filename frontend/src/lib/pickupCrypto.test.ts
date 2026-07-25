import { describe, expect, it } from "vitest";
import { openPickup, sealPickup, type PickupContents } from "./pickupCrypto";

const CONTENTS: PickupContents = {
  subject: "Quarterly numbers",
  body: "<p>The figures are attached.</p>",
  mode: "html",
  from: "alice@example.com"
};

describe("sealPickup / openPickup", () => {
  it("round-trips through the fragment key", async () => {
    const { sealed, fragmentKey } = await sealPickup(CONTENTS);
    await expect(openPickup(sealed, fragmentKey)).resolves.toEqual(CONTENTS);
  });

  // The whole point: what the server stores must not contain the message or
  // the subject. A subject stored in the clear would give away most of what
  // the encryption was for.
  it("leaves nothing readable in the stored envelope", async () => {
    const { sealed } = await sealPickup(CONTENTS);
    const serialized = JSON.stringify(sealed);
    expect(serialized).not.toContain("Quarterly");
    expect(serialized).not.toContain("figures");
    expect(serialized).not.toContain("alice@example.com");
  });

  it("does not put the key anywhere in the envelope", async () => {
    const { sealed, fragmentKey } = await sealPickup(CONTENTS);
    expect(JSON.stringify(sealed)).not.toContain(fragmentKey);
  });

  it("uses a fresh key and IV per message", async () => {
    const a = await sealPickup(CONTENTS);
    const b = await sealPickup(CONTENTS);
    expect(a.fragmentKey).not.toBe(b.fragmentKey);
    expect(a.sealed.iv).not.toBe(b.sealed.iv);
    expect(a.sealed.ciphertext).not.toBe(b.sealed.ciphertext);
  });

  it("refuses a key from a different message", async () => {
    const a = await sealPickup(CONTENTS);
    const b = await sealPickup(CONTENTS);
    await expect(openPickup(a.sealed, b.fragmentKey)).rejects.toBeTruthy();
  });

  // AES-GCM authenticates, so a ciphertext altered in storage or transit
  // fails to open rather than decrypting to something plausible.
  it("detects a tampered ciphertext", async () => {
    const { sealed, fragmentKey } = await sealPickup(CONTENTS);
    const bytes = atob(sealed.ciphertext).split("");
    bytes[0] = String.fromCharCode(bytes[0].charCodeAt(0) ^ 0xff);
    const tampered = { ...sealed, ciphertext: btoa(bytes.join("")) };
    await expect(openPickup(tampered, fragmentKey)).rejects.toBeTruthy();
  });

  it("rejects a truncated key rather than deriving something from it", async () => {
    const { sealed, fragmentKey } = await sealPickup(CONTENTS);
    await expect(openPickup(sealed, fragmentKey.slice(0, 10))).rejects.toThrow(/wrong length/);
  });

  it("survives a body with characters that would break naive encoding", async () => {
    const tricky: PickupContents = {
      subject: "Ünïcödé — 日本語 — 🔐",
      body: "line1\r\nline2\t<script>alert(1)</script>",
      mode: "plain",
      from: "b@example.com"
    };
    const { sealed, fragmentKey } = await sealPickup(tricky);
    await expect(openPickup(sealed, fragmentKey)).resolves.toEqual(tricky);
  });
});
