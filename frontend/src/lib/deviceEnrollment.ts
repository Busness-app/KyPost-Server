// Device enrollment: deriving and verifying the short authentication string,
// and sealing the private key to a paired device.
//
// THE SECURITY OF THIS WHOLE FEATURE IS ONE COMPARISON.
//
// The server stores and serves the device's public key, so the server is the
// party that can substitute its own — and then open anything sealed to it. The
// device derives the code from the key in its own keystore, which the server
// cannot influence; the browser derives it from the key the server handed over.
// If they differ, the server substituted. The browser must refuse to seal.
//
// The check gates the seal and never merely reports on it. Verifying on the
// device instead would be too late: by the time the phone finds it cannot open
// the envelope, the browser has already sealed to the attacker's key.
//
// Do NOT model this on backend/internal/mfa/number_match.go. That verifies on
// the server because only the server knows the right answer, which is correct
// there and exactly inverted here — in enrollment the server is the adversary,
// so a server-side check would be decoration.
//
// Every constant and layout below is normative and shared with the Android and
// Qt clients. See the NORMATIVE sections of
// docs/superpowers/specs/2026-08-04-device-enrollment-design.md. Changing any of
// it is a wire-format break and must move the version tag with it.

/** Seconds per code bucket. Matches GET /api/pgp/qr/token's TTL deliberately. */
export const CODE_BUCKET_SECONDS = 120;

/** Crockford base32 — excludes the character pairs people transcribe wrongly. */
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const CODE_LENGTH = 10;
const CODE_BITS = CODE_LENGTH * 5; // 50

const ENVELOPE_VERSION = "kypost-device-envelope/v1";
const RAW_KEY_BYTES = 65; // 0x04 || X(32) || Y(32)

export type DeviceEnvelope = {
  v: 1;
  alg: "ECDH-P256+HKDF-SHA256+A256GCM";
  epk: string;
  iv: string;
  ct: string;
};

// The ArrayBuffer type argument is load-bearing, not decoration: TypeScript 7
// defaults a bare Uint8Array to ArrayBufferLike, which WebCrypto's BufferSource
// rejects because it admits SharedArrayBuffer. Dropping it fails the build.
function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/**
 * Decodes and shape-checks the device's published public key.
 *
 * The server stores this opaquely and never validates it, so the browser is the
 * first party to look at it. Rejecting the wrong shape here keeps a malformed
 * value from reaching the hash as bytes that happen to differ from what the
 * device hashed.
 */
function decodeRawKey(publicKeyB64: string): Uint8Array<ArrayBuffer> {
  let raw: Uint8Array<ArrayBuffer>;
  try {
    raw = base64ToBytes(publicKeyB64);
  } catch {
    throw new Error("device public key is not valid base64");
  }
  if (raw.length !== RAW_KEY_BYTES) {
    throw new Error(`device public key must be ${RAW_KEY_BYTES} bytes, got ${raw.length}`);
  }
  if (raw[0] !== 0x04) {
    throw new Error("device public key is not an uncompressed SEC1 point");
  }
  return raw;
}

/** The 120-second bucket containing a unix timestamp. */
export function bucketFor(unixSeconds: number): number {
  return Math.floor(unixSeconds / CODE_BUCKET_SECONDS);
}

function uint16BE(n: number): Uint8Array {
  return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}

/**
 * uint64 big-endian. Built through BigInt because a bucket is comfortably
 * inside Number's safe range today but the field is eight bytes on the wire,
 * and doing it with bit shifts would silently truncate above 2^31.
 */
function uint64BE(n: number): Uint8Array {
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Derives the ten-character code for a key, device and bucket.
 *
 * Hashes the RAW 65 bytes rather than the base64 text: hashing the transport
 * encoding would make padding or alphabet drift between implementations a
 * silent mismatch that presents to the user as a hostile server.
 *
 * deviceId is length-prefixed defensively rather than out of present necessity:
 * it sits between a fixed 65-byte key and a fixed 8-byte bucket, so today its
 * boundaries are already unambiguous. The prefix is what keeps that true if a
 * second variable-width field is ever added, which is the point at which the
 * ambiguity would otherwise appear silently and only across implementations.
 */
export async function deriveEnrollmentCode(
  publicKeyB64: string,
  deviceId: string,
  bucket: number,
): Promise<string> {
  const raw = decodeRawKey(publicKeyB64);
  const id = new TextEncoder().encode(deviceId);

  const preimage = new Uint8Array(raw.length + 2 + id.length + 8);
  let off = 0;
  preimage.set(raw, off);
  off += raw.length;
  preimage.set(uint16BE(id.length), off);
  off += 2;
  preimage.set(id, off);
  off += id.length;
  preimage.set(uint64BE(bucket), off);

  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", preimage));

  // First 50 bits, most-significant first, five bits per character.
  let out = "";
  for (let i = 0; i < CODE_BITS; i += 5) {
    let v = 0;
    for (let b = 0; b < 5; b += 1) {
      const bit = i + b;
      const byte = digest[bit >>> 3];
      v = (v << 1) | ((byte >>> (7 - (bit & 7))) & 1);
    }
    out += CROCKFORD[v];
  }
  return out;
}

/**
 * Applies Crockford's decode rules so a user's transcription compares equal:
 * uppercase, strip separators, I/L are 1 and O is 0.
 */
export function normalizeEnrollmentCode(input: string): string {
  return input
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0");
}

/** The display grouping. Never compare this form. */
export function formatEnrollmentCode(code: string): string {
  return `${code.slice(0, 5)}-${code.slice(5, 10)}`;
}

/**
 * Constant-time-ish comparison of two already-normalised codes.
 *
 * Fifty bits typed by a human is not a timing-attack target in any practical
 * sense, but an early-return compare on a security decision is the kind of
 * thing that gets copied into somewhere it does matter.
 */
function codesEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Whether the typed code matches what the device would have displayed.
 *
 * Accepts the current bucket and the immediately preceding one — the phone may
 * have rendered just before a boundary the browser has already crossed — and
 * never a future one, because accepting a window that has not started lets an
 * attacker precompute into it.
 *
 * Returns false rather than throwing on malformed input: a mismatch and a typo
 * are the same answer to the caller, which is "do not seal".
 */
export async function verifyEnrollmentCode(
  publicKeyB64: string,
  deviceId: string,
  typed: string,
  nowUnixSeconds: number = Math.floor(Date.now() / 1000),
): Promise<boolean> {
  const candidate = normalizeEnrollmentCode(typed);
  if (candidate.length !== CODE_LENGTH) return false;
  for (const ch of candidate) {
    if (!CROCKFORD.includes(ch)) return false;
  }

  const current = bucketFor(nowUnixSeconds);
  for (const bucket of [current, current - 1]) {
    let expected: string;
    try {
      expected = await deriveEnrollmentCode(publicKeyB64, deviceId, bucket);
    } catch {
      return false;
    }
    if (codesEqual(expected, candidate)) return true;
  }
  return false;
}

/**
 * Imports the device's public key for ECDH.
 *
 * WebCrypto validates that the point is actually on P-256 here, which
 * decodeRawKey deliberately does not attempt — shape checking is cheap and
 * catches encoding drift, curve membership needs the real implementation.
 */
export async function importDevicePublicKey(publicKeyB64: string): Promise<CryptoKey> {
  const raw = decodeRawKey(publicKeyB64);
  return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, false, []);
}

/**
 * Seals the armored private key to a device.
 *
 * CALLERS MUST HAVE VERIFIED THE CODE FIRST. This function cannot check that
 * for itself — it is handed a key and told to seal — which is exactly why the
 * comparison belongs at the call site and gates reaching here at all.
 *
 * The AAD binds the device id and the identity fingerprint, so an envelope
 * minted for one device cannot be replayed at another, and one that outlives an
 * identity rotation fails authentication instead of decrypting into a key the
 * account no longer advertises.
 */
export async function sealEnvelopeForDevice(
  publicKeyB64: string,
  deviceId: string,
  pgpFingerprint: string,
  armoredPrivateKey: string,
): Promise<DeviceEnvelope> {
  const devicePub = await importDevicePublicKey(publicKeyB64);
  const ephemeral = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ])) as CryptoKeyPair;

  const shared = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "ECDH", public: devicePub }, ephemeral.privateKey, 256),
  );

  const hkdfKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: decodeRawKey(publicKeyB64),
      info: new TextEncoder().encode(ENVELOPE_VERSION),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(
    `${ENVELOPE_VERSION}|${deviceId}|${pgpFingerprint.toUpperCase().replace(/\s/g, "")}`,
  );
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad },
      aesKey,
      new TextEncoder().encode(armoredPrivateKey),
    ),
  );

  const epk = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  return {
    v: 1,
    alg: "ECDH-P256+HKDF-SHA256+A256GCM",
    epk: bytesToBase64(epk),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(ct),
  };
}
