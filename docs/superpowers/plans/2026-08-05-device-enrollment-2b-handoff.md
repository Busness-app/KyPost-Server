# Device Enrollment 2b (Browser) — Handoff

**Written:** 2026-08-05. Server side (2a) is complete and merged into
`fix/security-audit-run-9`. This document hands off the **browser** half.

**Spec:** `docs/superpowers/specs/2026-08-04-device-enrollment-design.md`.
**Sibling:** the Android handoff lives in the kypost-android repo at
`docs/superpowers/plans/2026-08-05-device-enrollment-2c-handoff.md`. Read its
"Unresolved spec gaps" section — the gaps are shared, and two of them must be settled
jointly or the two clients will disagree silently.

---

## Read this first: 2b is where the security lives

Every other part of this feature is plumbing. The browser is the only component that
can detect the attack the ceremony exists to stop, and it detects it in exactly one
place:

> **On mismatch it refuses to seal.**

The threat is precise. The server stores and serves the device's public key, so the
server is the party that can substitute its own — and then open everything the browser
seals to it. The typed code is the only thing that catches that substitution. If the
browser seals first and verifies afterwards, or treats a mismatch as a warning the user
can click through, the entire feature is decoration and the server has the account's
private key.

Two consequences that are easy to get wrong:

- **The comparison must gate the seal, not report on it.** Verifying on the device
  instead would be too late — by the time the phone finds it cannot open the envelope,
  the browser has already sealed to the attacker's key and uploaded it.
- **The device displays, the browser verifies.** Do not copy
  `backend/internal/mfa/number_match.go`. That solves a similar-looking problem and
  states its own rule plainly: the number match is verified on the *server* because only
  the server knows the right answer. That is correct there and **exactly inverted here** —
  in enrollment the server is the adversary, so a server-side check would be the
  decoration. Reuse the interaction lesson (make the human do something a reflex cannot
  fake), never the verification location.
- **Typed, not chosen from a list.** A pick-one-of-three control has a one-in-three blind
  success rate. Acceptable for a single sign-in; not for a control whose prize is every
  message the account will ever receive, against an attacker who can induce re-enrollment
  by telling the user to re-pair their phone.

---

## What 2b has to build

1. **Device list with an enrolled indicator**, on the Security page.
2. **The code entry field** — user types what the phone displays.
3. **Local derivation and comparison** from the public key the server handed over.
4. **ECDH seal** of the private key to the device's public key, on match only.
5. **`PUT` to `device:<deviceId>`.**
6. **Revocation copy** that tells the truth (see "Revocation" below).

---

## Server contract (implemented and verified)

### Reading device enrollment state — already available, no server work needed

`GET /api/notifications/native/devices` already returns the enrollment fields. They were
added to `state.NativeDevice`, which that handler serialises through `Redacted()` (which
clears `SecretHash` only). New fields on the wire:

- `enrollmentPublicKey` (string, `omitempty`) — absent means the device has never
  published, so it cannot be enrolled until it does.
- `enrollmentKeyAt` (string, `omitempty`) — RFC3339 UTC, server-stamped at publish.
- `encryptionEnrolled` (bool, **always present**) — the device's own report of whether it
  can still open its local envelope.

**The frontend type is stale.** `NativeDevice` in `src/pages/NotificationsPage.tsx:46`
lists nine fields and none of these three. Extend it there, or lift the type somewhere
shared — it is currently declared inside a page component.

### Sealing — the existing Change 1 route, unchanged

`PUT /api/pgp/identity/envelope/device:<deviceId>`

- **`withAuth` (session only) and step-up gated.** This is deliberate and must not be
  relaxed: a device may publish a public key and read what was sealed for it, but **only
  a session may mint a sealing.** That asymmetry is what makes the planned
  passphrase-only tier enforceable.
- Refuses the `password` slot (400). That field has exactly one writer,
  `POST /api/pgp/identity/rewrap`.
- Slots are capped (`maxWrappedEnvelopeSlots`); expired entries do not consume headroom.
- **The server never interprets the envelope.** It is an opaque string bounded by length.
  Everything about its structure is a browser↔device contract — see the gaps.

`DELETE /api/pgp/identity/envelope/device:<deviceId>` — same auth, step-up gated,
idempotent when the slot is absent.

### The transport copy expires after 7 days

`users.DeviceEnvelopeTTL`. Stamped automatically on `device:` slots; the recovery and
password slots never expire. An expired entry disappears from `WrappedEnvelopes()` and
reads as a 404 to the device, indistinguishable from "never sealed" by design.

This bounds the easy-revocation window — see below.

---

## Frontend anchors (verified to exist)

| What | Where |
|---|---|
| Unwrapped private key access | `src/lib/keyVault.ts` — `requireUnlockedKey()`, `isUnlocked()`, `VaultLockedError` |
| PGP session state | `src/lib/pgpSession.ts` — `isClientProtected()`, `needsUnlock()`, `unlockPGPSession()` |
| PGP API client (add the envelope calls here) | `src/api/pgp.ts` — **no envelope functions exist yet** |
| Step-up / reauth | `src/api/auth.ts::reauthenticate(password, code)`, `src/components/ReauthGate.tsx` |
| Security page, existing device list | `src/pages/SecurityPage.tsx` — `ApproverDevice` (line 41), `toggleApprover` (721) |
| Native device list + stale type | `src/pages/NotificationsPage.tsx` — type at 46, fetch at 433 |

**There is no envelope-slot client in the frontend at all.** `grep -rn "envelope" src/`
returns only `keyVault.ts` comments and a `body.ts` MIME reference. Change 1 shipped
three routes with no browser consumer, so 2b writes that client from scratch — there is
no existing call to copy the shape from.

**Two device lists already exist and they are different.** `SecurityPage` renders
`approverDevices` from the MFA status payload (`mfa_handlers.go:72`), a
purpose-built projection for push-2FA eligibility. `NotificationsPage` fetches the full
device list. The enrolled indicator belongs on the Security page per the spec, so decide
deliberately whether to widen the MFA status payload or fetch the device list there —
do not quietly add a third shape.

---

## Revocation — the copy is part of the security, not polish

`DELETE`ing `device:<id>` removes **the server's copy**. It does not reach the copy the
device re-sealed under its own keystore key, because the server has no reach into that.

- **Before the device re-seals** — deleting the slot genuinely revokes. That window is
  seconds at pairing, and at most the 7-day TTL for a deferred enrollment.
- **After the device re-seals** — the server cannot revoke it. Un-enrolling a lost phone
  means **rotating the identity key**, which invalidates every sealing and forces
  re-enrollment everywhere.

This is inherent to any design where a device holds a durable local sealing — Signal has
the same property, where unlinking stops future delivery but does not reach what the
device already holds. **The UI must not imply otherwise.** "Remove device" should say it
stops future sealings and does not erase what that device already has.

---

## Unresolved gaps — settle these BEFORE writing code

Gaps 1–3 are shared with 2c and are described in full in the Android handoff. Summarised
here because 2b cannot proceed without them either:

1. **The public key's wire encoding is unspecified.** Raw uncompressed point? DER
   `SubjectPublicKeyInfo`? Base64 of which? The server stores it opaquely with only a
   4 KiB cap. The code derivation hashes this value, so 2b and 2c hashing different
   encodings of the same key produces a mismatch on **every honest enrollment** — and the
   user is told the codes do not match, which reads as "your server is hostile."

2. **The code derivation is under-specified.** The spec gives
   `truncate(SHA-256(devicePublicKey ‖ deviceId ‖ timeBucket), 50 bits)` → ten Crockford
   base32 characters as `XXXXX-XXXXX`, two minutes' validity. Undefined: what `‖` is in
   bytes; how `timeBucket` is encoded and at what width and endianness; *which* 50 bits
   and how they pack into base32. Also unstated: whether the browser accepts the adjacent
   time bucket when the two ends straddle a boundary — that doubles the attacker's window
   and must be a decision, not an accident.

   This one is a trap because it *looks* specified and passes review as such.

3. **GCM AAD binding is absent from every document.** The device id and the PGP key
   fingerprint must be bound into the envelope's AAD so a substituted or replayed
   envelope fails authentication rather than decrypting into the wrong account's key.
   This is a **shipping condition** carried over from the Android side's rejection of an
   unbound design, not an optimisation.

4. **Identity rotation does not clear device enrollment state — server bug, found
   2026-08-05, not yet fixed.** `SetPGPIdentity`, `SetPGPIdentityClientProtected` and
   `ClearPGPIdentity` all clear `PGPWrappedEnvelopes`, because every non-password slot
   seals the old key. None of them touch `native_devices`, and they structurally cannot —
   `users.Store` has no coupling to `state.Store`.

   So after rotating the identity, every device still reports `encryptionEnrolled: true`
   with a populated `enrollmentPublicKey`, while its envelope has been destroyed. **This
   lands in the revocation flow specifically:** rotation is the documented way to
   un-enroll a lost phone, and afterwards the Security page still lists that phone as
   enrolled.

   There is a subtlety 2b's copy has to survive: the device genuinely *can* still open its
   local copy of the superseded key, so `true` is not a lie about capability — it is a lie
   about *which identity*. The indicator needs to distinguish "enrolled for your current
   key" from "holds a copy of a retired key". **Do not build the indicator until this is
   fixed**, or it will be built against state the server does not maintain.

Gaps 1 and 2 belong in the server design doc as normative wire format **with test
vectors**, since three implementations (browser, Android, Qt) must agree bit-for-bit.
Gap 3 belongs in a joint 2b/2c section. Gap 4 is server work.

---

## Test expectations

The frontend gate runs locally in `frontend/` — vitest, tsc, and the vite build all work
here. There is no environment excuse for skipping it.

The assertions that matter most, in order:

1. **A substituted public key produces a mismatch and the browser does not seal.** This
   is the one test the feature exists for. Assert that no `PUT` was issued, not merely
   that a warning rendered.
2. A mismatch is not click-through-able.
3. An expired code is refused, and the boundary behaviour matches whatever gap 2 decides.
4. Sealing is refused when the vault is locked (`VaultLockedError`) rather than sealing
   something wrong.
5. The derivation matches published test vectors — the same vectors 2c tests against.

Existing patterns to follow: `src/lib/keyVault.test.ts`, `src/lib/pgpClient.test.ts`.

---

## Status of the server work

Complete: `cd28b8f`, `bfd2c10`, `54b7daf`, `3b038fe` on `fix/security-audit-run-9`.
Build/vet/gofmt clean, full non-race suite exit 0 across 30 packages, `-race` at CI flags
green on `internal/api`, `internal/state`, `internal/users`. 17 new tests with four
mutation checks.

**Branch is not pushed and has no PR.** Two gates are outstanding on it: the frontend
gate (run-9 touched `src/App.tsx` and `src/app/compose.ts`) and the hostile review that
`CONTRIBUTING.md` requires of every PR.
