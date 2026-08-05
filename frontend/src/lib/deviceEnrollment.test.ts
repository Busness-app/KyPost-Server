import { describe, expect, it } from "vitest";

import {
  CODE_BUCKET_SECONDS,
  bucketFor,
  deriveEnrollmentCode,
  formatEnrollmentCode,
  importDevicePublicKey,
  normalizeEnrollmentCode,
  verifyEnrollmentCode,
} from "./deviceEnrollment";

// The authoritative test vector. Android and Qt assert the same expected code;
// see the NORMATIVE sections of the device-enrollment design doc. Do not
// hand-copy this value into another repository — read it from here.
const RAW_KEY = new Uint8Array([0x04, ...Array(32).fill(0x01), ...Array(32).fill(0x02)]);
const VECTOR_KEY_B64 = btoa(String.fromCharCode(...RAW_KEY));
const VECTOR_DEVICE_ID = "test-device";
const VECTOR_UNIX_SECONDS = 1_680_000_000;
const VECTOR_BUCKET = 14_000_000;

describe("bucketFor", () => {
  it("floors to a 120-second bucket", () => {
    expect(CODE_BUCKET_SECONDS).toBe(120);
    expect(bucketFor(VECTOR_UNIX_SECONDS)).toBe(VECTOR_BUCKET);
    expect(bucketFor(VECTOR_UNIX_SECONDS + 119)).toBe(VECTOR_BUCKET);
    expect(bucketFor(VECTOR_UNIX_SECONDS + 120)).toBe(VECTOR_BUCKET + 1);
  });
});

describe("deriveEnrollmentCode", () => {
  it("produces ten Crockford characters", async () => {
    const code = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    expect(code).toMatch(/^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{10}$/);
  });

  it("is stable — this is the cross-implementation vector", async () => {
    const code = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    // Locked in on first green run. A change here is a wire-format break and
    // must move the version tag in the design doc with it.
    expect(code).toMatchInlineSnapshot(`"5R9K6FWA18"`);
  });

  // The whole feature exists to detect a substituted key, so the code must
  // actually depend on the key rather than incidentally on the id and clock.
  it("changes when the key changes", async () => {
    const other = new Uint8Array(RAW_KEY);
    other[1] = 0x09;
    const otherB64 = btoa(String.fromCharCode(...other));
    const a = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    const b = await deriveEnrollmentCode(otherB64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    expect(b).not.toBe(a);
  });

  it("changes when the device id changes", async () => {
    const a = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    const b = await deriveEnrollmentCode(VECTOR_KEY_B64, "other-device", VECTOR_BUCKET);
    expect(b).not.toBe(a);
  });

  it("changes when the bucket advances", async () => {
    const a = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    const b = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET + 1);
    expect(b).not.toBe(a);
  });

  // Different-length ids must not collide. Note this passes even without the
  // length prefix, because the id sits between two fixed-width fields today —
  // the prefix is defensive for a future variable-width field, and the vector
  // snapshot above is what actually pins its presence.
  it("does not collide across a device-id boundary shift", async () => {
    const a = await deriveEnrollmentCode(VECTOR_KEY_B64, "ab", VECTOR_BUCKET);
    const b = await deriveEnrollmentCode(VECTOR_KEY_B64, "a", VECTOR_BUCKET);
    expect(b).not.toBe(a);
  });

  it("rejects a key that is not a 65-byte uncompressed point", async () => {
    await expect(deriveEnrollmentCode(btoa("short"), VECTOR_DEVICE_ID, VECTOR_BUCKET)).rejects.toThrow();
  });

  it("rejects a point without the 0x04 uncompressed marker", async () => {
    const bad = new Uint8Array(RAW_KEY);
    bad[0] = 0x03;
    await expect(
      deriveEnrollmentCode(btoa(String.fromCharCode(...bad)), VECTOR_DEVICE_ID, VECTOR_BUCKET),
    ).rejects.toThrow();
  });
});

describe("normalizeEnrollmentCode", () => {
  it("applies Crockford decode rules", () => {
    expect(normalizeEnrollmentCode("abcde-fghjk")).toBe("ABCDEFGHJK");
    // I and L are 1; O is 0. These are the transcription pairs Crockford exists to fix.
    expect(normalizeEnrollmentCode("IL0OO-12345")).toBe("1100012345");
    expect(normalizeEnrollmentCode("  ABCDE FGHJK \t")).toBe("ABCDEFGHJK");
  });
});

describe("formatEnrollmentCode", () => {
  it("groups as XXXXX-XXXXX", () => {
    expect(formatEnrollmentCode("ABCDEFGHJK")).toBe("ABCDE-FGHJK");
  });
});

describe("verifyEnrollmentCode", () => {
  const at = VECTOR_UNIX_SECONDS;

  it("accepts the current bucket", async () => {
    const typed = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, bucketFor(at));
    await expect(verifyEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, typed, at)).resolves.toBe(true);
  });

  // The phone may have rendered its code just before a boundary the browser
  // has already crossed.
  it("accepts the immediately preceding bucket", async () => {
    const typed = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, bucketFor(at) - 1);
    await expect(verifyEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, typed, at)).resolves.toBe(true);
  });

  // Accepting a future bucket would let an attacker precompute against a
  // window that has not started.
  it("refuses a future bucket", async () => {
    const typed = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, bucketFor(at) + 1);
    await expect(verifyEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, typed, at)).resolves.toBe(false);
  });

  it("refuses a bucket two back", async () => {
    const typed = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, bucketFor(at) - 2);
    await expect(verifyEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, typed, at)).resolves.toBe(false);
  });

  // THE decisive test. A server that substitutes its own public key must not
  // be able to produce a matching code for what the device displayed.
  it("refuses a code derived from a different key — the substitution attack", async () => {
    const attacker = new Uint8Array(RAW_KEY);
    attacker[40] = 0xfe;
    const attackerB64 = btoa(String.fromCharCode(...attacker));
    // The user types what their phone showed, derived from the REAL key.
    const typed = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, bucketFor(at));
    // The browser was handed the attacker's key by a hostile server.
    await expect(verifyEnrollmentCode(attackerB64, VECTOR_DEVICE_ID, typed, at)).resolves.toBe(false);
  });

  it("accepts the display form and mixed case", async () => {
    const typed = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, bucketFor(at));
    const messy = formatEnrollmentCode(typed).toLowerCase();
    await expect(verifyEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, messy, at)).resolves.toBe(true);
  });

  it("refuses empty or malformed input rather than throwing", async () => {
    await expect(verifyEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, "", at)).resolves.toBe(false);
    await expect(verifyEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, "nope", at)).resolves.toBe(false);
  });
});

describe("importDevicePublicKey", () => {
  it("imports a real P-256 point for ECDH", async () => {
    const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
      "deriveBits",
    ])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    expect(raw.length).toBe(65);
    expect(raw[0]).toBe(0x04);
    const b64 = btoa(String.fromCharCode(...raw));
    await expect(importDevicePublicKey(b64)).resolves.toBeDefined();
  });

  it("rejects a well-formed-looking point that is not on the curve", async () => {
    // Right length and marker, but the coordinates are not a curve point.
    await expect(importDevicePublicKey(VECTOR_KEY_B64)).rejects.toThrow();
  });
});
