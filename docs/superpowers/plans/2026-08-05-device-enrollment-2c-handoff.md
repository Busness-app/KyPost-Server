> **SUPERSEDED — 2026-08-05.** The maintained copy of this handoff lives in `kypost-android` at
> `docs/superpowers/plans/2026-08-05-device-enrollment-2c-handoff.md`. That copy carries the
> Hostile Location gate, which this one never had, and both wire-format breaks below. Read it
> instead; this file is kept only so links to it do not rot.
>
> **The wire format on this page is out of date.** The code is now 14 Crockford characters (70
> bits), not 10, and the envelope is `v2` with a length-prefixed AAD. Both changes came out of
> security audit run-5.

# 2C (Android) — device enrollment, the device half

**Repo:** `kypost-android` (not this checkout). **Server + browser:** PR #80 on `kypost-server`.
**Spec (normative):** `docs/superpowers/specs/2026-08-04-device-enrollment-design.md`.

## The security does not live here — and that is the point

2b is where the substituted-key attack is caught: the browser compares a code it derives from
the key **the server handed it** against a code the user reads off this device, and refuses to
seal on mismatch. This device's job is narrower and stricter:

- **Derive the code from the key in your own keystore.** Never from anything the server sent
  back, never from a cached copy of what you published. The moment this device derives from a
  server-supplied value, the comparison compares the server against itself and the whole
  feature is decoration.
- **Never let the private half leave the secure element.** `PURPOSE_AGREE_KEY`, non-extractable.
  If it can be exported, an attacker with the sealed envelope has the key.
- **Report your real state.** `encryptionEnrolled` is *your* answer to "can I still open my
  local envelope", and the browser renders it as "this device can read your encrypted mail".
  A marker that drifts optimistic is worse than none.

You are the ground truth the browser checks the server against. Be honest, be local.

## Do this first, before any UI

Assert the normative vector. One test, no dependencies, an hour of work:

```
deviceId  = "test-device"
bucket    = 14000000                    (unixSeconds 1680000000)
rawKey    = 0x04 ‖ X(0x01 × 32) ‖ Y(0x02 × 32)      // valid encoding, NOT on the curve
expected  = "5R9K6FWA18"                             // displayed 5R9K6-FWA18
```

**This vector has only ever been verified in the browser.** If Android disagrees, the failure
mode is that codes never match — and the browser reports that as *"the key this server gave the
browser is not the key on that device"*. An encoding bug presents to the user as an active
attack. Find out now, not during a ceremony.

The key is deliberately off-curve: derivation hashes bytes and must not require a curve
operation, so this stays reproducible before ECDH is wired up.

`frontend/src/lib/deviceEnrollment.test.ts` holds the same vector as an inline snapshot and is
**authoritative if it and the spec ever disagree** — it runs on every frontend build; the doc
does not.

## Wire format — settled, do not renegotiate

**Public key.** Base64 (standard alphabet, padded) of the uncompressed SEC1 point:
`0x04 ‖ X ‖ Y`, X and Y left-padded to exactly 32 bytes. 65 bytes raw, 88 encoded.
Android: `ECPublicKey.getW()` gives you X and Y to pad.

**Code derivation.** Hash the **raw 65 bytes**, never the base64 text.

```
bucket   = floor(unixSeconds / 120)      // integer division, UTC, no leap smear
preimage = rawKey(65) ‖ uint16BE(byteLength(deviceIdUtf8)) ‖ deviceIdUtf8 ‖ uint64BE(bucket)
H        = SHA-256(preimage)
code     = first 50 bits of H, MSB first, ten Crockford base32 chars
           alphabet 0123456789ABCDEFGHJKMNPQRSTVWXYZ, char i = bits [5i, 5i+5)
display  = XXXXX-XXXXX
```

**`deviceId` is now charset-bounded (added 2026-08-05, after 2b).** New ids must be **1–128
characters of `A-Z a-z 0-9 . _ : -`** and the server rejects anything else at registration. Every
permitted character is byte-identical under UTF-8, NFC and NFD. **Do not normalise `deviceId`
before hashing** — with this charset there is nothing to normalise, which is the point. This bound
exists because an NFC/NFD disagreement between two clients would surface to the user as a
substituted key.

**Envelope** (browser → server → you), all fields base64:

```json
{ "v": 1,
  "alg": "ECDH-P256+HKDF-SHA256+A256GCM",
  "epk": "<raw ephemeral public key, 65 bytes, same encoding as above>",
  "iv":  "<12 bytes>",
  "ct":  "<AES-256-GCM ciphertext, 16-byte tag appended>" }
```

- **Shared secret:** ECDH(your private, `epk`) → 32 bytes.
- **KDF:** HKDF-SHA256, `ikm` = shared secret, **`salt` = your own raw 65-byte public key**,
  `info` = UTF-8 `"kypost-device-envelope/v1"`, length 32.
- **AAD** = UTF-8 of `kypost-device-envelope/v1|<deviceId>|<pgpFingerprint>`, fingerprint
  **uppercase hex, no spaces**.
- **Plaintext** = the armored PGP private key, UTF-8.

The AAD binding is a shipping condition, not an optimisation — it is what the Android side
required before withdrawing its objection to this design. Binding `deviceId` stops an envelope
minted for one device being replayed at another; binding the fingerprint stops one surviving an
identity rotation and decrypting into a key the account no longer advertises. **If AAD
verification fails, treat it as hostile, not as a retry.**

## Server contract — implemented and verified

| Step | Route | Auth | Notes |
|---|---|---|---|
| Publish your public key | `POST /api/pgp/device/enrollment-key` | device headers | `{"publicKey":"<base64>"}`, ≤4 KiB. No step-up: a public key is not a capability. |
| Read your own envelope | `GET /api/pgp/device/envelope` | device headers | **No slot parameter exists.** The slot is built server-side from your verified credential. |
| Report your state | `POST /api/notifications/native/register` | pairing token | `encryptionEnrolled` is tri-state: omit it if you have no opinion. |

Device headers are `X-Kypost-Device-Id` and `X-Kypost-Device-Secret`.

`GET /api/pgp/device/envelope` returns `{"slot":"device:<id>","envelope":"<opaque string>"}`, or
**404** `{"error":"no envelope sealed for this device"}`. 404 covers both "never sealed" and
"expired" — they are indistinguishable by design, and both mean *re-run the ceremony*.

**The server's copy expires after 7 days** (`DeviceEnvelopeTTL`). It is transport, not storage:
fetch it, re-seal locally, and stop depending on it. Nothing deletes it for you — expiry is
lazy and needs no caller, because you have no session and inventing a device-authenticated
delete would hand a device the power to destroy a sealing.

**Only a session may mint or destroy a sealing.** You may publish a public key and read what was
sealed for you. `PUT`/`DELETE /api/pgp/identity/envelope/{slot}` are session-only and step-up
gated, and no device credential routes around that.

### Two changes since 2b that will bite you

1. **Re-registration now requires your current device secret.** Rebinding an existing `deviceId`
   at `POST /api/notifications/native/register` returns **409** unless you send
   `X-Kypost-Device-Secret` with the request. If your FCM-token-refresh flow re-registers — and
   the `encryptionEnrolled` contract implies it does — **it must send that header**. A stolen
   session could otherwise take over your device row, keeping your `MFAApprover` status and
   redirecting your push.
2. **Device credentials are refused while the account owes a password change.** After an admin
   password reset, `deviceAuthFromRequest` rejects you until the user completes the change.
   Surface that as "sign in on the web to finish your password change", not as a pairing error.

## The ceremony, end to end

1. Generate an EC P-256 keypair, `PURPOSE_AGREE_KEY`, StrongBox where the hardware allows,
   private half **non-extractable**. `minSdk = 31` makes this available everywhere you support;
   `PURPOSE_AGREE_KEY` landed in API 31.
2. Publish the public half under your existing pairing credential.
3. User starts enrollment. Display the code for the current bucket, refreshing on the boundary.
4. User types it into the browser. The browser verifies and, on match, seals and `PUT`s.
5. Fetch `GET /api/pgp/device/envelope`. Open by ECDH **inside the secure element**.
6. Re-seal locally under a secure-element AES-GCM key carrying
   `setUserAuthenticationRequired`. From here the server's copy is dead weight.
7. Report `encryptionEnrolled` on registration and every token refresh, based on whether you can
   **actually still open your local envelope** — not on whether you once could.

**Primary entry point is a prompt at pairing**, not a settings screen. Both screens are already
in front of the same person, and the attacker's grinding window collapses from days to seconds.
The device list on the Security page is the secondary path, for a device that declined or was
paired before this shipped.

## Failure handling

- **Declined at pairing** — nothing happens. Push and mail work exactly as before. Offer it
  again later; declining must not be a dead end.
- **Code expired** — mint a fresh one. The browser distinguishes expiry from mismatch and says
  so; do not make your copy contradict it.
- **Mismatch** — the browser refuses and explains. You have nothing to do; do not offer a retry
  that implies the user mistyped when the browser has just told them the server may be hostile.
- **Clock skew** — a device more than ~2 minutes **ahead** of the browser fails every attempt.
  The browser's copy names this. Keep your clock honest; do not widen your window to compensate.
- **AAD verification fails** — hostile or stale. Do not retry, do not fall back. Re-enroll.
- **Envelope 404** — expired or never sealed. Re-run the ceremony.
- **Identity rotated** — every sealing is invalidated by design. Report
  `encryptionEnrolled: false` and offer re-enrollment. Surface it as expected, not as an error.
- **Ordering** — enrollment must FOLLOW identity creation. Reversed, the envelope is silently
  discarded and the server cannot detect it, because both calls are individually valid and it
  cannot read either envelope. This is a client obligation. Test it.

## Tests that matter, in order

1. **The vector reproduces** — `5R9K6FWA18`. Before anything else.
2. **The code is derived from the keystore key**, not from anything the server returned. Mutate
   the source to a server-supplied value and prove the test fails.
3. **The private key cannot be exported.** Assert the key is non-extractable, and that a request
   for the raw private material throws.
4. **AAD mismatch refuses**, for both a wrong `deviceId` and a wrong fingerprint.
5. **The local re-seal requires user authentication** — `setUserAuthenticationRequired` holds.
6. **`encryptionEnrolled` follows reality down as well as up** — after the local key is
   destroyed (app reinstall, biometric change), it reports false.
7. **Re-registration sends the device secret** and survives a token refresh without a 409.
8. **Enrollment before identity creation** is rejected or retried, not silently lost.

Treat "there is a test for it" as unproven until you have broken the implementation and watched
the test go red. Two of 2b's security tests originally passed against implementations with the
property removed — one of them against the design's own headline attack — and were only caught
because someone mutated the code and re-ran them. See `1c74842` and `00feae6` in this repo.

## What 2c cannot fix, and should not pretend to

- **A live hostile server defeats the code.** It ships the browser's JavaScript and can serve a
  bundle that skips the comparison. This control defends against a server that retains too much,
  a stolen backup, or a compromised database. The browser UI says so in its own copy; do not
  write Android copy that claims more.
- **Once you re-seal locally, the server cannot revoke you.** Deleting the slot removes the
  transport copy only. Real revocation is identity rotation. Signal has the same property.
- **This concedes attacks by someone holding an unlocked device.** That is the trade the parent
  spec makes; `setUserAuthenticationRequired` is what narrows it.

## Open question for 2d (Qt)

Whether the Qt clients can hold a non-extractable key is still unproven. If they cannot, they
stay on the passphrase tier — and that must not block 2c. Do not design Android around a shared
abstraction with a client that may never exist.
