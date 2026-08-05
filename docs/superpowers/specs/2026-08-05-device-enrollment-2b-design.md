# Device enrollment 2b: the browser half

**Status: design.** Implements the 2b half of
`2026-08-04-device-enrollment-design.md`, whose NORMATIVE sections are unchanged and
authoritative here. This spec adds only what that one left to the implementation: where
the UI lives, what gates the seal, and how a refusal is told apart from a typo.

2a has shipped. `frontend/src/lib/deviceEnrollment.ts` has shipped with 20 tests and the
`5R9K6FWA18` vector. What remains is the API client, the UI, and the ceremony that joins
them.

## Everything else is plumbing

The browser is the only component that can detect a substituted device public key, and it
detects it in exactly one place: **on mismatch it refuses to seal.** Seal-then-verify, or
a mismatch the user can click through, and the server has the private key.

Every decision below is downstream of that sentence. Where a choice made the gate harder
to get wrong, it was taken even when it cost more code.

## Module boundaries

Three new files. `SecurityPage.tsx` grows by about ten lines, which is the point — it is
already 1539 lines.

**`src/api/devices.ts`** — the `NativeDevice` type and `listNativeDevices()`. The type
carries `enrollmentPublicKey`, `enrollmentKeyAt` and `encryptionEnrolled`, which the copy
at `NotificationsPage.tsx:46` is stale by. That page deletes its local copy and imports
this one.

A shared *fetch helper*, deliberately not a shared *render component*. The two lists
answer different questions — which device can approve a sign-in, versus which device can
read the mail — and coupling them would tie an MFA checkbox to an enrollment indicator
that have no reason to change together.

**`src/api/pgp.ts`** — `putDeviceEnvelope(deviceId, envelope, password)` and
`deleteDeviceEnvelope(deviceId, password)`, both step-up gated through the existing
`stepUp()`. Change 1 shipped these routes with no browser consumer at all.

The slot is `` `device:${encodeURIComponent(deviceId)}` ``, following the precedent at
`SecurityPage.tsx:726`. The `device:` prefix stays literal; only the id is escaped.

**No `GET` client.** The browser never reads a slot back. The device reads its own, over
the narrow `withMailAuth` route 2a added. Adding a browser `GET` because the route exists
would be building the one call that has no caller.

**`src/components/DeviceEnrollmentCard.tsx`** — the device list, the enrollment indicator,
the ceremony dialog, and the refusal path.

## The gate

```
const key = device.enrollmentPublicKey;        // captured ONCE, at dialog open
const armored = requireUnlockedKey();          // a locked vault refuses here, first
if (!(await verifyEnrollmentCode(key, device.deviceId, typed))) return refuse();
const env = await sealEnvelopeForDevice(key, device.deviceId, fingerprint, armored);
await putDeviceEnvelope(device.deviceId, env, password);
```

Three orderings in that block are load-bearing.

**`key` is captured once and never re-read.** Verifying against a freshly fetched key and
then sealing against a second fetch would let a server answer honestly once and hostilely
once: the comparison passes on bytes that are never sealed to. The dialog snapshots the
device record when it opens and both calls take that same value. This is the failure the
whole design exists to prevent, arriving through the back door of a refetch.

**The unlock check comes first**, so a locked vault refuses before anything derives.
Otherwise a locked vault reports itself as a code mismatch — the most alarming message in
the product, shown for the most mundane cause.

**The `PUT` is last and reachable only through the gate.** `sealEnvelopeForDevice` cannot
verify the code itself; it is handed a key and told to seal. That is exactly why the
comparison has to gate reaching it rather than run beside it.

## Two credentials, not one

Enrollment needs the *unlocked vault* — `requireUnlockedKey()`, for the key to seal — and
separately an *account password*, as the step-up the `PUT` requires.

These are not the same string and must not be collected as one. `SecurityPage` already
carries a stale-envelope recovery path where the password that opens the envelope is an
older one than the account's. A single prompt doing both jobs breaks precisely there, and
breaks silently.

A locked vault therefore refuses rather than prompting mid-ceremony. Unlocking is the
existing `PgpUnlockDialog`, before enrollment starts.

## Expiry told apart from mismatch

The parent spec requires the browser report expiry distinctly from mismatch — "they mean
different things and only one of them is alarming" — without saying how. It cannot be done
with the gate alone: `verifyEnrollmentCode` returns `false` for a stale code and a
substituted key alike, by construction.

**`explainEnrollmentFailure`**, alongside the gate in `deviceEnrollment.ts`, resolves it. It
walks the **15 buckets preceding the current one** — 30 minutes, long enough to cover a
user who walked away mid-ceremony and short enough to stay cheap — and answers `"expired"`
or `"mismatch"`. It runs *only after the gate has already refused*. Its answer selects
error copy. Nothing downstream of it seals.

The split matters more than the function does. `verifyEnrollmentCode` stays exactly as
shipped and tested — current and previous bucket, never a future one — so the diagnostic
cannot widen what gets sealed no matter what it concludes. A single function that both
decided and explained would be one edit away from accepting what it was only meant to
describe.

Clock skew gets its own copy. A phone whose clock runs more than about two minutes ahead
fails every attempt, and the reading a user reaches unaided is "my server is compromised."

## What each failure says

- **Locked vault** — unlock first; offers the unlock dialog.
- **Not ten characters** — a malformed entry, not a mismatch. Does not consume an attempt.
- **Mismatch** — refuses, names the actual risk: the key this server handed over is not the
  key on that phone. Near this copy, the limit `keyVault.ts` already documents for the whole
  product — this defends against a server that retains too much, a stolen backup, or a
  compromised database, not against one actively serving malicious JavaScript.
- **Expired** — the device mints a fresh one. Unalarming, and says so.
- **Three attempts** — the ceremony aborts and restarts from the device. Three because
  typing ten characters invites a real typo while blind guessing is hopeless; this is the
  opposite of the MFA case, where one attempt is right because guessing is cheap.
- **`PUT` failed** — the sealing was not stored, and nothing was disclosed by trying.

**There is no "seal anyway" control at any point.** The refusal is not click-through-able
because there is nothing to click, which is a stronger property than a warning the user is
asked to respect.

## Ordering, and what removal does not do

Enrollment is offered only when protection is `client`, a fingerprint exists, and the
device has published a key. That last condition self-gates the card to invisible until 2c
ships — no flag, and no button that leads somewhere no device can follow.

Creating or replacing an identity clears every non-password slot, so enrollment must follow
identity creation; reversed, the envelope is silently discarded and the server cannot detect
it. The card refreshes on identity change and must not cache past it.

**Remove-device copy states what removal actually does:** it stops future sealings and does
not erase what that device already re-sealed locally. Real revocation is rotating the
identity, and the copy points at the replace-identity control already on the page. No new
destructive control — the honest sentence plus a pointer to a button that exists.

## Tests

In `DeviceEnrollmentCard.test.tsx`, in the order they matter:

- A substituted key produces a mismatch and **`putDeviceEnvelope` is never called** —
  asserting the absence of the request, not the presence of a warning.
- No path from a refusal to a seal.
- `sealEnvelopeForDevice` receives the exact key bytes that were verified.
- A locked vault refuses before anything derives.
- An expired code is refused *and* reported as expiry rather than substitution.
- Three attempts abort the ceremony.
- Enrollment is not offered for a device with no published key.

The derivation vector `5R9K6FWA18` is already covered by `deviceEnrollment.test.ts`, which
stays authoritative over every document including this one.

## Deferred: one device, three lists

After this change the same phone appears in three places — pairing and removal on the
Notifications page, the approver checkbox at `SecurityPage.tsx:1013`, and the new
enrollment indicator. That is a real defect and it is deliberately not fixed here.

The consolidation that pays is a **Devices page** carrying all per-device state, which
leaves Notifications as genuinely just delivery preferences and shrinks Security rather
than growing it. Folding Notifications into Security instead was considered and rejected:
delivery mode, content preview and IMAP keywords are not security settings, and merging
them produces one ~2,400-line page answering two unrelated questions.

It waits for two reasons. It renames user-facing copy in `README.md`, `SECURITY.md:197`,
`.env.example:284`, `frontend/AGENTS.md`, `docs/Desktop_Pairing.md:186` and a Go error
string at `push_mfa_handlers.go:117`. And its most important row state — enrolled, not
enrolled, cannot enrol — would be designed against a feature no device can complete until
2c ships.

`src/api/devices.ts` is the seam that page consumes. Nothing in 2b has to be undone for it.

## Non-goals

- **Changing the wire format.** Every NORMATIVE section of the parent spec is fixed.
- **A browser reader for envelope slots.** The device reads its own; the browser writes.
- **Rotate-and-re-enrol as a guided flow.** Rotation already invalidates every sealing;
  wrapping it in a wizard is a new feature wearing revocation's clothes.
- **2c and 2d.** Nothing here is user-visible until Android lands.
