import { describe, expect, it } from "vitest";

import {
  CODE_BUCKET_SECONDS,
  bucketFor,
  buildEnvelopeAad,
  deriveEnrollmentCode,
  explainEnrollmentFailure,
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
  it("produces fourteen Crockford characters", async () => {
    const code = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    expect(code).toMatch(/^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{14}$/);
  });

  // The width is load-bearing, not cosmetic. With no commitment in the preimage
  // the attacker's search is offline, so the output width is the only thing
  // setting its cost: at 50 bits a collision is ~2^50 SHA-256 compressions, about
  // 14 GPU-hours and a few dollars per 120-second window. A silent regression to
  // a shorter code would not fail the vector test alone, because the shorter code
  // is a PREFIX of the longer one.
  it("is 70 bits wide", async () => {
    const code = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    expect(code).toHaveLength(14);
  });

  it("is stable — this is the cross-implementation vector", async () => {
    const code = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    // Locked in on first green run. A change here is a wire-format break and
    // must move the version tag in the design doc with it.
    //
    // Widened from "5R9K6FWA18" (50 bits) on 2026-08-05 -- see CODE_LENGTH. The
    // old value is a prefix of this one, which is exactly why a client left at 10
    // characters fails silently as "the codes never match" rather than loudly.
    expect(code).toMatchInlineSnapshot(`"5R9K6FWA18A8YP"`);
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

describe("buildEnvelopeAad", () => {
  // The SAME assertion exists in kypost-android's DeviceEnvelopeTest
  // (aad_isTheExactContractBytes). Two implementations of the same prose is how
  // the fingerprint-format bug got in -- the spec said "uppercase hex, no spaces"
  // and only one side did it. Assert the bytes on both sides instead.
  it("is the exact contract bytes, length-prefixed", () => {
    const aad = buildEnvelopeAad("dev-1", "ABCD1234");
    const enc = new TextEncoder();
    const expected = new Uint8Array([
      ...enc.encode("kypost-device-envelope/v2"),
      0, 5, ...enc.encode("dev-1"),
      0, 8, ...enc.encode("ABCD1234"),
    ]);
    expect(Array.from(aad)).toEqual(Array.from(expected));
  });

  // A pipe in one field must not be able to shift the boundary into the next.
  it("is unambiguous across a field boundary", () => {
    const a = buildEnvelopeAad("dev", "BADC0FFEE0123456789ABCDEF");
    const b = buildEnvelopeAad("devBADC0FFEE", "0123456789ABCDEF");
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  // Both clients' natural fingerprint producers emit space-grouped hex.
  it("normalises a space-grouped fingerprint", () => {
    const grouped = buildEnvelopeAad("dev-1", "164D 5B83 4E7F E927");
    const flat = buildEnvelopeAad("dev-1", "164D5B834E7FE927");
    expect(Array.from(grouped)).toEqual(Array.from(flat));
  });
});

describe("formatEnrollmentCode", () => {
  it("groups as XXXX-XXX-XXXX-XXX", () => {
    expect(formatEnrollmentCode("ABCDEFGHJKMNPQ")).toBe("ABCD-EFG-HJKM-NPQ");
  });

  // The grouping must not drop characters. `.replace("-", "")` removed only the FIRST hyphen --
  // fine when there was one, wrong now there are three -- so this strips every separator the same
  // way normalizeEnrollmentCode does.
  it("never drops characters", async () => {
    const code = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET);
    expect(formatEnrollmentCode(code).split("-").join("")).toBe(code);
  });

  // The phone and the browser must show the same grouping of the same value.
  it("matches the Android client on the normative vector", () => {
    expect(formatEnrollmentCode("5R9K6FWA18A8YP")).toBe("5R9K-6FW-A18A-8YP");
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

describe("explainEnrollmentFailure", () => {
  it("reads a code from an older bucket as expired", async () => {
    const stale = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET - 6);
    const why = await explainEnrollmentFailure(
      VECTOR_KEY_B64,
      VECTOR_DEVICE_ID,
      stale,
      VECTOR_UNIX_SECONDS
    );
    expect(why).toBe("expired");
  });

  it("reads a code derived from a different key as a mismatch", async () => {
    const other = new Uint8Array(RAW_KEY);
    other[1] = 0x09;
    const otherB64 = btoa(String.fromCharCode(...other));
    const substituted = await deriveEnrollmentCode(otherB64, VECTOR_DEVICE_ID, VECTOR_BUCKET);

    const why = await explainEnrollmentFailure(
      VECTOR_KEY_B64,
      VECTOR_DEVICE_ID,
      substituted,
      VECTOR_UNIX_SECONDS
    );
    expect(why).toBe("mismatch");
  });

  it("reads a short entry as malformed rather than alarming", async () => {
    const why = await explainEnrollmentFailure(
      VECTOR_KEY_B64,
      VECTOR_DEVICE_ID,
      "5R9K6",
      VECTOR_UNIX_SECONDS
    );
    expect(why).toBe("malformed");
  });

  it("reads a code far past the diagnostic window as a mismatch", async () => {
    const ancient = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET - 400);
    const why = await explainEnrollmentFailure(
      VECTOR_KEY_B64,
      VECTOR_DEVICE_ID,
      ancient,
      VECTOR_UNIX_SECONDS
    );
    expect(why).toBe("mismatch");
  });

  // Pins the exact boundary of DIAGNOSTIC_BUCKETS (15), the one number this
  // function owns. current-6 and current-400 above bracket it loosely; this
  // is the edge itself, one bucket on either side.
  it("reads current-15 as expired and current-16 as a mismatch", async () => {
    const atEdge = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET - 15);
    expect(
      await explainEnrollmentFailure(VECTOR_KEY_B64, VECTOR_DEVICE_ID, atEdge, VECTOR_UNIX_SECONDS)
    ).toBe("expired");

    const pastEdge = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET - 16);
    expect(
      await explainEnrollmentFailure(VECTOR_KEY_B64, VECTOR_DEVICE_ID, pastEdge, VECTOR_UNIX_SECONDS)
    ).toBe("mismatch");
  });

  // The load-bearing property. The diagnostic exists to CHOOSE COPY, and this
  // pins that widening it never widens the gate: a code it calls "expired" is
  // still one verifyEnrollmentCode refuses.
  it("does not make the gate accept anything it refused", async () => {
    const stale = await deriveEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, VECTOR_BUCKET - 6);

    expect(
      await explainEnrollmentFailure(VECTOR_KEY_B64, VECTOR_DEVICE_ID, stale, VECTOR_UNIX_SECONDS)
    ).toBe("expired");
    expect(
      await verifyEnrollmentCode(VECTOR_KEY_B64, VECTOR_DEVICE_ID, stale, VECTOR_UNIX_SECONDS)
    ).toBe(false);
  });
});
