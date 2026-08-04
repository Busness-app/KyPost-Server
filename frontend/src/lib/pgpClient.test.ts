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
        [mallory.publicKey, bob.publicKey],
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
      const result = await decryptMessage(ciphertext, [bob.publicKey], "bob@example.com");

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

// run-7 finding F1: the H7 fix above was implemented as a raw-substring test,
// `uid.toLowerCase().includes("<" + sender + ">")`, over the UNPARSED User-ID
// string. A User ID is free-form and self-certified, and the Go backend parses it
// differently: go-crypto's parseUserId stops after the FIRST bracketed address,
// while a substring test is order-independent. So a single crafted UID
//
//     Mallory <mallory@evil.example> aka Bob <bob@example.com>
//
// parsed server-side as mallory@evil.example — the Autocrypt harvest pinned it
// under the ATTACKER's own contact with no prompt — while the browser found
// <bob@example.com> inside the raw string and rendered "signature verified" under
// a spoofed From, with the real signer's fingerprint suppressed (ReadPage only
// shows it when !verified).
//
// The fix compares the PARSED User-ID email. openpgp.js declines to parse a
// multi-address User ID at all (name/email/comment all come back ""), so a UID the
// two parsers could disagree about now certifies no address whatsoever.
describe("signature binding uses the parsed User ID, not a substring of it", () => {
  async function generateFreeformKey(rawName: string, email: string): Promise<TestKey> {
    const { publicKey, privateKey } = await openpgp.generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ name: rawName, email }],
      format: "armored"
    });
    return { publicKey, privateKey };
  }

  it("refuses a key whose User ID merely CONTAINS the sender address", async () => {
    // Parses server-side as mallory@evil.example; contains "<bob@example.com>".
    const attacker = await generateFreeformKey(
      "Mallory <mallory@evil.example> aka Bob",
      "bob@example.com"
    );
    const victim = await generateTestKey("Victim", "victim@example.com");

    const ciphertext = await encryptSignedFor(victim.publicKey, attacker.privateKey, "hello");

    unlockWithArmoredKey(victim.privateKey);
    try {
      const result = await decryptMessage(ciphertext, [attacker.publicKey], "bob@example.com");

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
      const result = await decryptMessage(ciphertext, [bob.publicKey], "bob@example.com");
      expect(result.verified).toBe(true);
    } finally {
      lock();
    }
  }, 30000);
});
