// pgpClient: the OpenPGP operations that must happen in the browser once the
// private key is client-protected, because the server has no copy it can
// open.
//
// openpgp is imported dynamically everywhere here for the same reason
// ContactsPage already does it: it is a large bundle and no page needs it
// until the user actually touches PGP.

import { requireUnlockedKey } from "./keyVault";
import { parseMimeContent, type BodyMode } from "./mimeContent";

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
export async function generateIdentity(
  name: string,
  email: string,
  additionalEmails: string[] = []
): Promise<GeneratedIdentity> {
  const pgp = await openpgp();
  // Every address the account has proven it owns becomes a User ID. Both WKD
  // serving and Autocrypt advertising refuse a key that does not carry the
  // address in question, so a key with only the primary address silently
  // fails to publish for verified aliases. Mirrors pgpmail.GenerateIdentity.
  const seen = new Set([email.trim().toLowerCase()]);
  const userIDs = [{ name, email: email.trim() }];
  for (const extra of additionalEmails) {
    const addr = extra.trim();
    if (!addr || seen.has(addr.toLowerCase())) {
      continue;
    }
    seen.add(addr.toLowerCase());
    userIDs.push({ name, email: addr });
  }
  const { privateKey, publicKey } = await pgp.generateKey({
    type: "ecc",
    curve: "curve25519Legacy",
    userIDs,
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
  /**
   * Which MIME part `body` came from, read off the decrypted entity's own
   * Content-Type — the client-side counterpart to the server's `bodyMode`.
   *
   * Undefined only for an inline-PGP message, which decrypts to bare text with
   * no MIME headers to read. Route it through displayBody (pages/read/body.ts)
   * so that one case gets the fallback and nothing else does.
   */
  bodyMode?: BodyMode;
  signed: boolean;
  verified: boolean;
  signerFingerprint: string;
};

/**
 * Decrypts a PGP/MIME payload the server handed through untouched, using the
 * unlocked key. Throws VaultLockedError if the vault is locked.
 *
 * signerPublicKeys are every known contact key: which one signed is not known
 * in advance, so all are offered and whichever actually produced the signature
 * is identified. senderAddress is what the verdict is then bound to — see the
 * comment at the verification loop. `verified` means "the sender signed this",
 * not "somebody did".
 */
export async function decryptMessage(
  payload: string,
  signerPublicKeys: string[],
  senderAddress: string
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
    const wanted = senderAddress.trim().toLowerCase();
    for (const signature of signatures) {
      try {
        // `verified` rejects rather than returning false on a bad signature.
        await signature.verified;
        const keyID = signature.keyID.toHex().toUpperCase();
        const match = verificationKeys.find((k) =>
          k.getKeys().some((sub) => sub.getKeyID().toHex().toUpperCase() === keyID)
        );
        signerFingerprint = match ? match.getFingerprint().toUpperCase() : keyID;
        // A cryptographically valid signature from SOME key in the address
        // book proves only that someone signed this. The badge claims the
        // SENDER signed it, so the key that actually produced the signature
        // must carry the sender's address as a User ID. Without this, an
        // attacker whose key the reader had auto-pinned — Autocrypt harvest
        // and WKD auto-trust both pin without asking — could sign a message,
        // put anyone in the From header, and be vouched for by the UI.
        verified = Boolean(
          match &&
            wanted &&
            match
              .getUserIDs()
              .some((uid) => uid.toLowerCase().includes(`<${wanted}>`))
        );
        break;
      } catch {
        // Try the next signature; an unverifiable one is not fatal.
      }
    }
  }

  // The decrypted payload is a MIME entity, not display text: headers,
  // boundaries and an encoded body. Parsing it here keeps the reader from
  // showing "Content-Type: text/html" and a boundary marker as part of the
  // message, and recovers the render mode from the part's own Content-Type so
  // nothing downstream has to sniff the bytes. An inline-PGP message has no MIME
  // headers; parseMimeContent returns null and the raw text is the body.
  const raw = typeof result.data === "string" ? result.data : String(result.data);
  const parsed = parseMimeContent(raw);

  return {
    body: parsed ? parsed.body : raw,
    bodyMode: parsed?.mode,
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
 * The outer, unencrypted envelope of a PGP/MIME message.
 *
 * These headers are the message as far as a receiving MTA is concerned:
 * /api/mail/send-pgp relays the bytes verbatim and synthesizes nothing. An
 * earlier version of this module emitted only Content-Type and MIME-Version,
 * producing messages with no From, To, Subject, or Date — malformed, and
 * rejected or rendered blank by receiving clients. The server now refuses
 * such a delivery (validatePGPMimeDelivery) rather than relaying it.
 *
 * bcc is deliberately absent: BCC recipients get their own delivery and must
 * not appear in anyone's headers, exactly as the server-side path does it.
 */
export type MessageEnvelope = {
  from: string;
  to: string[];
  cc?: string[];
  subject: string;
  date?: Date;
};

/**
 * Encrypts (and optionally signs) a message body once per delivery group.
 *
 * BCC recipients get their own delivery each, so they never appear in one
 * another's encryption key list — the same split the server-side path makes,
 * and the reason this takes groups rather than one flat recipient list.
 *
 * The real Subject is moved inside the encrypted part as a protected header
 * and replaced on the outside with a placeholder, mirroring
 * pgpmail.EncryptMIME. Encrypting the body while leaving the subject in
 * cleartext would give away most of what encryption was for.
 */
export async function buildEncryptedDeliveries(
  envelope: MessageEnvelope,
  contentType: string,
  body: string,
  groups: { recipients: string[]; publicKeys: string[] }[],
  sign: boolean
): Promise<EncryptedDelivery[]> {
  const pgp = await openpgp();
  const signingKeys = sign ? [await pgp.readPrivateKey({ armoredKey: requireUnlockedKey() })] : undefined;
  const protectedContent = buildProtectedContent(contentType, body, envelope.subject);

  const deliveries: EncryptedDelivery[] = [];
  for (const group of groups) {
    if (group.recipients.length === 0 || group.publicKeys.length === 0) {
      continue;
    }
    const encryptionKeys = await readPublicKeys(pgp, group.publicKeys);
    const armored = await pgp.encrypt({
      message: await pgp.createMessage({ text: protectedContent }),
      encryptionKeys,
      signingKeys,
      format: "armored"
    });
    deliveries.push({
      recipients: group.recipients,
      ciphertext: wrapAsPGPMime(envelope, String(armored))
    });
  }
  return deliveries;
}

/**
 * Builds the Sent-folder copy: the same protected content the recipients get,
 * encrypted to the SENDER'S OWN key and wrapped as PGP/MIME.
 *
 * This used to be the composer's raw HTML, posted to the server in the clear.
 * On a client-custody account that quietly gave away everything the deliveries
 * were protecting — the body and the real subject of every message — to a
 * server whose stated property is that it cannot read your mail.
 *
 * The encryption key is derived from the UNLOCKED PRIVATE KEY in this browser,
 * not fetched from the server. That matters: if the server supplied "your"
 * public key, a compromised or hostile one could hand back an attacker's key
 * and every Sent copy would be encrypted to them, with nothing on screen
 * looking any different.
 *
 * Signing is optional and mirrors the send: a copy of a signed message is
 * signed. It changes nothing about who can read it.
 */
export async function buildEncryptedSentCopy(
  envelope: MessageEnvelope,
  contentType: string,
  body: string,
  sign: boolean
): Promise<string> {
  const pgp = await openpgp();
  const ownKey = await pgp.readPrivateKey({ armoredKey: requireUnlockedKey() });
  const signingKeys = sign ? [ownKey] : undefined;
  const armored = await pgp.encrypt({
    message: await pgp.createMessage({ text: buildProtectedContent(contentType, body, envelope.subject) }),
    encryptionKeys: ownKey.toPublic(),
    signingKeys,
    format: "armored"
  });
  return wrapAsPGPMime(envelope, String(armored));
}

// Matches pgpmail.OuterPlaceholderSubject so both send paths look identical
// on the wire.
export const OUTER_PLACEHOLDER_SUBJECT = "[Encrypted] Email Sent by KyPost";

/**
 * Wraps the real content in an RFC 5322 protected-headers part carrying the
 * true Subject, mirroring pgpmail.protectContent. The receiving side lifts it
 * back out (pgpmail.ExtractProtectedSubject).
 */
function buildProtectedContent(contentType: string, body: string, subject: string): string {
  const clean = sanitizeHeaderValue(subject);
  const boundary = `kypost-protected-${randomToken()}`;
  const lines = [`Content-Type: multipart/mixed; boundary="${boundary}"; protected-headers="v1"`, ""];
  if (clean) {
    lines.unshift(`Subject: ${clean}`);
    lines.push(
      `--${boundary}`,
      'Content-Type: text/rfc822-headers; protected-headers="v1"',
      "Content-Disposition: inline",
      "",
      `Subject: ${clean}`,
      ""
    );
  }
  lines.push(`--${boundary}`, `Content-Type: ${contentType}`, "", body, "", `--${boundary}--`, "");
  return lines.join("\r\n");
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

/** Flattens CR/LF so a header value cannot inject extra headers. */
function sanitizeHeaderValue(value: string): string {
  return value.replace(/[\r\n]+/g, " ").trim();
}

function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Wraps an armored PGP message as a complete RFC 5322 message with an RFC
 * 3156 multipart/encrypted body.
 *
 * This emits the full envelope — From, To, Cc, Subject, Date, MIME-Version —
 * not just the Content-Type. /api/mail/send-pgp relays these bytes verbatim,
 * so anything omitted here is simply absent from the delivered mail.
 */
function wrapAsPGPMime(envelope: MessageEnvelope, armoredMessage: string): string {
  const boundary = `${PGP_MIME_BOUNDARY}-${randomToken()}`;
  const headers = [
    `From: ${sanitizeHeaderValue(envelope.from)}`,
    `To: ${envelope.to.map(sanitizeHeaderValue).filter(Boolean).join(", ")}`
  ];
  const cc = (envelope.cc ?? []).map(sanitizeHeaderValue).filter(Boolean);
  if (cc.length > 0) {
    headers.push(`Cc: ${cc.join(", ")}`);
  }
  // The real subject is inside the ciphertext as a protected header; this is
  // the placeholder the server-side path uses too.
  headers.push(`Subject: ${OUTER_PLACEHOLDER_SUBJECT}`);
  headers.push(`Date: ${(envelope.date ?? new Date()).toUTCString()}`);
  headers.push("MIME-Version: 1.0");
  headers.push(`Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="${boundary}"`);

  return [
    ...headers,
    "",
    "This is an OpenPGP/MIME encrypted message (RFC 3156).",
    `--${boundary}`,
    "Content-Type: application/pgp-encrypted",
    "Content-Description: PGP/MIME version identification",
    "",
    "Version: 1",
    "",
    `--${boundary}`,
    'Content-Type: application/octet-stream; name="encrypted.asc"',
    "Content-Description: OpenPGP encrypted message",
    'Content-Disposition: inline; filename="encrypted.asc"',
    "",
    armoredMessage.trim(),
    "",
    `--${boundary}--`,
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
