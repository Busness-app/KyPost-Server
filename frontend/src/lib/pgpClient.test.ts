// @vitest-environment node
import { describe, it, expect } from "vitest";
import * as openpgp from "openpgp";

import { decryptMessage } from "./pgpClient";
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
