// @vitest-environment node
import { describe, it, expect } from "vitest";
import * as openpgp from "openpgp";

import { buildEncryptedSentCopy, decryptMessage } from "./pgpClient";
import { unlockWithArmoredKey, lock } from "./keyVault";

// run-4 finding H7: decryptMessage offered every contact public key as a
// verification key and set verified=true on the first signature that validated
// against *any* of them. That establishes only that someone in the reader's
// address book signed the message — not that the sender did. signerFingerprint
// was computed and never rendered, so nothing in the UI exposed the mismatch,
// and the green "signature verified" badge sat directly above the sender
// address. An attacker whose key the reader had auto-pinned (Autocrypt harvest
// and WKD auto-trust both do that without asking) could sign a message,
// address it From: someone-else, and have the client vouch for it.

type TestKey = { publicKey: string; privateKey: string };

async function generateTestKey(name: string, email: string): Promise<TestKey> {
  const { publicKey, privateKey } = await openpgp.generateKey({
    type: "ecc",
    curve: "curve25519Legacy",
    userIDs: [{ name, email }],
    format: "armored"
  });
  return { publicKey, privateKey };
}

/**
 * A key as the server hands it over: labelled with the addresses the ADDRESS
 * BOOK binds it to, which is the contact's own email list — not anything the
 * key says about itself. `bound(mallory, "mallory@evil.example")` is what the
 * Autocrypt harvest produces for a key pinned under Mallory's contact,
 * whatever User IDs that key happens to carry.
 */
function bound(key: TestKey, ...addresses: string[]) {
  return { addresses, publicKey: key.publicKey };
}

/** Encrypts to recipientPublicKey, signed by signerPrivateKey. */
async function encryptSignedFor(
  recipientPublicKey: string,
  signerPrivateKey: string,
  text: string
): Promise<string> {
  const encryptionKeys = await openpgp.readKey({ armoredKey: recipientPublicKey });
  const signingKeys = await openpgp.readPrivateKey({ armoredKey: signerPrivateKey });
  return (await openpgp.encrypt({
    message: await openpgp.createMessage({ text }),
    encryptionKeys,
    signingKeys,
    format: "armored"
  })) as string;
}

describe("signature verification is bound to the sender", () => {
  it("does not report verified when a different contact's key made the signature", async () => {
    const mallory = await generateTestKey("Mallory", "mallory@evil.example");
    const bob = await generateTestKey("Bob", "bob@example.com");
    const victim = await generateTestKey("Victim", "victim@example.com");

    // Signed by Mallory, encrypted to the victim, claiming to be from Bob.
    const ciphertext = await encryptSignedFor(victim.publicKey, mallory.privateKey, "hello");

    unlockWithArmoredKey(victim.privateKey);
    try {
      const result = await decryptMessage(
        ciphertext,
        [bound(mallory, "mallory@evil.example"), bound(bob, "bob@example.com")],
        "bob@example.com"
      );

      expect(result.signed).toBe(true);
      expect(result.verified).toBe(false);
      // The signer is still identified, so the UI can say who actually signed.
      expect(result.signerFingerprint).not.toBe("");
    } finally {
      lock();
    }
  }, 30000);

  it("reports verified when the sender's own key made the signature", async () => {
    const bob = await generateTestKey("Bob", "bob@example.com");
    const victim = await generateTestKey("Victim", "victim@example.com");

    const ciphertext = await encryptSignedFor(victim.publicKey, bob.privateKey, "hello");

    unlockWithArmoredKey(victim.privateKey);
    try {
      const result = await decryptMessage(
        ciphertext,
        [bound(bob, "bob@example.com")],
        "bob@example.com"
      );

      expect(result.signed).toBe(true);
      expect(result.verified).toBe(true);
    } finally {
      lock();
    }
  }, 30000);
});

// run-4 M5: the client-custody send path posted the composer's raw HTML to the
// server as the Sent copy, alongside deliveries the server could not read. On
// an account whose stated property is "Server can decrypt mail: No", that
// handed over the cleartext of every message and its real subject.
//
// The copy is now encrypted here, to the sender's own key, so the server relays
// bytes it cannot open — the same as it already does for the deliveries.
describe("the Sent copy is encrypted to the sender's own key (run-4 M5)", () => {
  it("produces a PGP/MIME message the sender can decrypt", async () => {
    const alice = await generateTestKey("Alice", "alice@example.com");
    unlockWithArmoredKey(alice.privateKey);
    try {
      const sentCopy = await buildEncryptedSentCopy(
        { from: "alice@example.com", to: ["bob@example.com"], subject: "Quarterly numbers" },
        "text/html; charset=UTF-8",
        "<p>the actual message</p>",
        false
      );

      // Neither the body nor the real subject may appear anywhere in it.
      expect(sentCopy).not.toContain("the actual message");
      expect(sentCopy).not.toContain("Quarterly numbers");
      expect(sentCopy).toContain("multipart/encrypted");
      expect(sentCopy).toContain("[Encrypted] Email Sent by KyPost");

      // And the sender must still be able to read their own outbox.
      const armored = sentCopy.slice(
        sentCopy.indexOf("-----BEGIN PGP MESSAGE-----"),
        sentCopy.indexOf("-----END PGP MESSAGE-----") + "-----END PGP MESSAGE-----".length
      );
      const decrypted = await decryptMessage(armored, [], "alice@example.com");
      expect(decrypted.body).toContain("the actual message");
    } finally {
      lock();
    }
  }, 30000);

  it("cannot be read by anyone but the sender", async () => {
    const alice = await generateTestKey("Alice", "alice@example.com");
    const mallory = await generateTestKey("Mallory", "mallory@evil.example");

    unlockWithArmoredKey(alice.privateKey);
    let sentCopy: string;
    try {
      sentCopy = await buildEncryptedSentCopy(
        { from: "alice@example.com", to: ["bob@example.com"], subject: "s" },
        "text/plain",
        "secret",
        false
      );
    } finally {
      lock();
    }

    const armored = sentCopy.slice(
      sentCopy.indexOf("-----BEGIN PGP MESSAGE-----"),
      sentCopy.indexOf("-----END PGP MESSAGE-----") + "-----END PGP MESSAGE-----".length
    );
    unlockWithArmoredKey(mallory.privateKey);
    try {
      await expect(decryptMessage(armored, [], "alice@example.com")).rejects.toThrow();
    } finally {
      lock();
    }
  }, 30000);
});

// run-7 F1, then run-8 F1: the H7 fix above was reimplemented twice against the
// key's own User IDs — first as a raw-substring test, then as a parsed-email
// comparison — and both are forgeable, because a User ID is self-asserted and
// one key may carry as many as its owner likes.
//
// The run-8 payload needs no crafted string at all: ONE key with the two
// ordinary User IDs `Mallory <mallory@evil.example>` and `Bob <bob@example.com>`.
// The Autocrypt harvest validates it against Mallory's From, matches on the
// first, and pins it under HER contact with no prompt. The second then satisfied
// any "does this key certify the sender" test and the badge went green under a
// spoofed From — with the real signer's fingerprint suppressed, since ReadPage
// shows it only when !verified.
//
// The anchor is now the address book: a key verifies for the addresses the
// CONTACT it is filed under carries, and nothing the key asserts can add to
// that. Removing the browser's own User-ID parse also ends the openpgp.js /
// go-crypto disagreement, which was independently forgery-capable in the
// direction the server rejected and the browser accepted.
describe("signature binding is anchored in the address book, not the key's User IDs", () => {
  it("refuses a key carrying the sender as a second, self-asserted User ID", async () => {
    // One key, two ordinary User IDs. Pinned under Mallory's contact, because
    // that is the From the Autocrypt header arrived with.
    const { publicKey, privateKey } = await openpgp.generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [
        { name: "Mallory", email: "mallory@evil.example" },
        { name: "Bob", email: "bob@example.com" }
      ],
      format: "armored"
    });
    const attacker: TestKey = { publicKey, privateKey };
    const bob = await generateTestKey("Bob", "bob@example.com");
    const victim = await generateTestKey("Victim", "victim@example.com");

    const ciphertext = await encryptSignedFor(victim.publicKey, attacker.privateKey, "hello");

    unlockWithArmoredKey(victim.privateKey);
    try {
      // Bob's genuine key is in the book too, exactly as it would be for a
      // reader who had verified him: the attacker's signature must still lose.
      const result = await decryptMessage(
        ciphertext,
        [bound(attacker, "mallory@evil.example"), bound(bob, "bob@example.com")],
        "bob@example.com"
      );

      expect(result.signed).toBe(true);
      expect(result.verified).toBe(false);
    } finally {
      lock();
    }
  }, 30000);

  it("still reports verified for an ordinary well-formed key", async () => {
    const bob = await generateTestKey("Bob", "bob@example.com");
    const victim = await generateTestKey("Victim", "victim@example.com");
    const ciphertext = await encryptSignedFor(victim.publicKey, bob.privateKey, "hello");

    unlockWithArmoredKey(victim.privateKey);
    try {
      const result = await decryptMessage(
        ciphertext,
        [bound(bob, "bob@example.com")],
        "bob@example.com"
      );
      expect(result.verified).toBe(true);
    } finally {
      lock();
    }
  }, 30000);

  it("verifies a contact's second address without the key carrying it", async () => {
    // The address book says this contact is both addresses. The key carries
    // only one as a User ID — which under the old anchor silently cost the
    // reader their signature indicator.
    const bob = await generateTestKey("Bob", "bob@example.com");
    const victim = await generateTestKey("Victim", "victim@example.com");
    const ciphertext = await encryptSignedFor(victim.publicKey, bob.privateKey, "hello");

    unlockWithArmoredKey(victim.privateKey);
    try {
      const result = await decryptMessage(
        ciphertext,
        [bound(bob, "bob@example.com", "bob@work.example")],
        "bob@work.example"
      );
      expect(result.verified).toBe(true);
    } finally {
      lock();
    }
  }, 30000);
});
