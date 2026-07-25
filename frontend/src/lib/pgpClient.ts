// pgpClient: the OpenPGP operations that must happen in the browser once the
// private key is client-protected, because the server has no copy it can
// open.
//
// openpgp is imported dynamically everywhere here for the same reason
// ContactsPage already does it: it is a large bundle and no page needs it
// until the user actually touches PGP.

import { requireUnlockedKey } from "./keyVault";

type OpenPGP = typeof import("openpgp");

async function openpgp(): Promise<OpenPGP> {
  return import("openpgp");
}

export type GeneratedIdentity = {
  armoredPrivateKey: string;
  armoredPublicKey: string;
  fingerprint: string;
};

/**
 * Generates a new keypair in the browser. The private key never leaves it
 * unwrapped.
 *
 * curve25519Legacy, not openpgp.js v6's modern `type: "curve25519"`. The
 * "legacy" name is misleading: it is the RFC 4880-compatible EdDSA/Curve25519
 * key that GnuPG, Thunderbird, and this server's own gopenpgp generator all
 * produce and accept. The modern option emits an RFC 9580 v6 key that much
 * of the ecosystem still rejects, which for a mail client means recipients
 * silently unable to read anything you send them.
 */
export async function generateIdentity(name: string, email: string): Promise<GeneratedIdentity> {
  const pgp = await openpgp();
  const { privateKey, publicKey } = await pgp.generateKey({
    type: "ecc",
    curve: "curve25519Legacy",
    userIDs: [{ name, email }],
    format: "armored"
  });
  const parsed = await pgp.readKey({ armoredKey: publicKey });
  return {
    armoredPrivateKey: privateKey,
    armoredPublicKey: publicKey,
    fingerprint: parsed.getFingerprint().toUpperCase()
  };
}

/**
 * Reads an armored private key the user is importing, unlocking it with
 * passphrase if it carries one.
 *
 * The returned private key is always decrypted: it is about to be wrapped
 * under the account password instead, so carrying its original passphrase
 * forward would mean two secrets to lose rather than one.
 */
export async function importIdentity(
  armoredPrivateKey: string,
  passphrase: string
): Promise<GeneratedIdentity> {
  const pgp = await openpgp();
  let key = await pgp.readPrivateKey({ armoredKey: armoredPrivateKey.trim() });
  if (!key.isDecrypted()) {
    if (!passphrase) {
      throw new Error("This key is passphrase-protected. Enter its passphrase to import it.");
    }
    key = await pgp.decryptKey({ privateKey: key, passphrase });
  }
  return {
    armoredPrivateKey: key.armor(),
    armoredPublicKey: key.toPublic().armor(),
    fingerprint: key.getFingerprint().toUpperCase()
  };
}

export type DecryptedMessage = {
  body: string;
  signed: boolean;
  verified: boolean;
  signerFingerprint: string;
};

/**
 * Decrypts a PGP/MIME payload the server handed through untouched, using the
 * unlocked key. Throws VaultLockedError if the vault is locked.
 *
 * signerPublicKeys are every known contact key: the sender is not known in
 * advance, so all are offered and whichever actually produced the signature
 * is the one that verifies.
 */
export async function decryptMessage(
  payload: string,
  signerPublicKeys: string[]
): Promise<DecryptedMessage> {
  const pgp = await openpgp();
  const privateKey = await pgp.readPrivateKey({ armoredKey: requireUnlockedKey() });

  const armored = extractArmoredMessage(payload);
  const message = await pgp.readMessage({ armoredMessage: armored });

  const verificationKeys = await readPublicKeys(pgp, signerPublicKeys);
  const result = await pgp.decrypt({
    message,
    decryptionKeys: privateKey,
    verificationKeys: verificationKeys.length > 0 ? verificationKeys : undefined,
    expectSigned: false
  });

  let signed = false;
  let verified = false;
  let signerFingerprint = "";
  const signatures = result.signatures ?? [];
  if (signatures.length > 0) {
    signed = true;
    for (const signature of signatures) {
      try {
        // `verified` rejects rather than returning false on a bad signature.
        await signature.verified;
        verified = true;
        const keyID = signature.keyID.toHex().toUpperCase();
        const match = verificationKeys.find((k) =>
          k.getKeys().some((sub) => sub.getKeyID().toHex().toUpperCase() === keyID)
        );
        signerFingerprint = match ? match.getFingerprint().toUpperCase() : keyID;
        break;
      } catch {
        // Try the next signature; an unverifiable one is not fatal.
      }
    }
  }

  return {
    body: typeof result.data === "string" ? result.data : String(result.data),
    signed,
    verified,
    signerFingerprint
  };
}

/** One encrypted delivery: a full PGP/MIME message plus its recipients. */
export type EncryptedDelivery = {
  recipients: string[];
  ciphertext: string;
};

/**
 * Encrypts (and optionally signs) mimeBody once per delivery group.
 *
 * BCC recipients get their own delivery each, so they never appear in one
 * another's encryption key list — the same split the server-side path makes,
 * and the reason this takes groups rather than one flat recipient list.
 */
export async function buildEncryptedDeliveries(
  mimeBody: string,
  groups: { recipients: string[]; publicKeys: string[] }[],
  sign: boolean
): Promise<EncryptedDelivery[]> {
  const pgp = await openpgp();
  const signingKeys = sign ? [await pgp.readPrivateKey({ armoredKey: requireUnlockedKey() })] : undefined;

  const deliveries: EncryptedDelivery[] = [];
  for (const group of groups) {
    if (group.recipients.length === 0 || group.publicKeys.length === 0) {
      continue;
    }
    const encryptionKeys = await readPublicKeys(pgp, group.publicKeys);
    const armored = await pgp.encrypt({
      message: await pgp.createMessage({ text: mimeBody }),
      encryptionKeys,
      signingKeys,
      format: "armored"
    });
    deliveries.push({
      recipients: group.recipients,
      ciphertext: wrapAsPGPMime(String(armored))
    });
  }
  return deliveries;
}

async function readPublicKeys(pgp: OpenPGP, armoredKeys: string[]) {
  const keys = [];
  for (const armored of armoredKeys) {
    const trimmed = armored?.trim();
    if (!trimmed) {
      continue;
    }
    try {
      keys.push(await pgp.readKey({ armoredKey: trimmed }));
    } catch {
      // One unparseable contact key must not cost every other recipient
      // their encryption, or every other signer their verification.
    }
  }
  return keys;
}

// RFC 3156 boundary. Fixed rather than random: it is only required to not
// occur in the body, and an ASCII-armored PGP block cannot contain it.
const PGP_MIME_BOUNDARY = "kypost-pgp-boundary";

/**
 * Wraps an armored PGP message as an RFC 3156 multipart/encrypted body,
 * which is what a receiving mail client expects.
 *
 * Only the body is produced here; the server prepends nothing and the
 * headers travel inside the ciphertext, matching how the server-side
 * EncryptMIME path builds its output.
 */
function wrapAsPGPMime(armoredMessage: string): string {
  return [
    `Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="${PGP_MIME_BOUNDARY}"`,
    "MIME-Version: 1.0",
    "",
    "This is an OpenPGP/MIME encrypted message (RFC 3156).",
    `--${PGP_MIME_BOUNDARY}`,
    "Content-Type: application/pgp-encrypted",
    "Content-Description: PGP/MIME version identification",
    "",
    "Version: 1",
    "",
    `--${PGP_MIME_BOUNDARY}`,
    'Content-Type: application/octet-stream; name="encrypted.asc"',
    "Content-Description: OpenPGP encrypted message",
    'Content-Disposition: inline; filename="encrypted.asc"',
    "",
    armoredMessage.trim(),
    "",
    `--${PGP_MIME_BOUNDARY}--`,
    ""
  ].join("\r\n");
}

/**
 * Pulls the armored PGP block out of whatever the server passed through —
 * either a bare armored message or a full multipart/encrypted body.
 */
export function extractArmoredMessage(payload: string): string {
  const begin = payload.indexOf("-----BEGIN PGP MESSAGE-----");
  const endMarker = "-----END PGP MESSAGE-----";
  const end = payload.indexOf(endMarker);
  if (begin === -1 || end === -1) {
    return payload.trim();
  }
  return payload.slice(begin, end + endMarker.length);
}
