# Device enrollment: giving a paired device its own sealing of the PGP key

**Status: design.** This is Change 2 of
`2026-08-04-multi-wrapped-key-custody-design.md`. Change 1's server side has shipped
(PR #70): an identity can now carry several wrapped envelopes, and a `device:<id>`
slot is already a valid, writable slot with nothing yet minting one. This spec says
how one gets minted.

## What this is for

A client-protected private key is sealed under the account password. A phone pairs by
QR and never learns that password, so it cannot open the envelope — which is why
client-custody accounts are unusable outside the browser today, and why the legacy
`server` custody mode cannot be retired.

Device enrollment gives each paired device its own sealing of the same key, opened by
the device's secure element rather than by a passphrase. The device never learns the
account password, and revocation is per-device.

## Scope

This spans four subsystems and is deliberately decomposed. **This spec covers 2a and
2b**, which together define the wire format and the ceremony; 2c and 2d implement it.

- **2a — Server.** Enrollment public key on `NativeDevice`, the publish endpoint,
  shared code derivation. *This spec.*
- **2b — Browser.** Device list, the verification UI, ECDH seal, upload to the
  `device:` slot. *This spec.*
- **2c — Android.** Keystore/StrongBox keypair, publish, code display, local re-seal.
  Written against this spec.
- **2d — Qt clients.** Deferred. `2026-08-04-multi-wrapped-key-custody-design.md`
  already flags the platform keystore story as unproven; if those clients cannot hold
  a non-extractable key they stay on the passphrase tier, and that must not block 2a-2c.

Nothing is user-visible until 2a+2b+2c all land. That is the minimum viable unit.

## The ceremony

**Primary entry point: a prompt at pairing.** Once pairing succeeds, the device offers
"Enroll this device for encrypted mail?". This is the right moment and not merely a
convenient one: the pairing QR came from the browser, so both screens are already in
front of the same person, and — see "Why the code can be short" — the attacker's
grinding window is measured in seconds rather than months.

**Secondary entry point: the device list** on the Security page, for a device that
declined, a device paired before this shipped, or a re-enrollment after the identity
changed.

The steps:

1. The device generates an EC P-256 keypair with `PURPOSE_AGREE_KEY`, StrongBox-backed
   where the hardware allows, private half non-extractable. `minSdk = 31` on Android
   makes this available everywhere it supports; `PURPOSE_AGREE_KEY` landed in API 31.
2. The device publishes the **public** half under its existing pairing credential.
3. The user starts enrollment. The device displays a code derived from its own public
   key and the current time bucket, valid for two minutes.
4. The user types that code into the browser.
5. The browser fetches the device public key from the server, derives the same code
   from **what it was handed**, and compares against what the user typed. **On mismatch
   it refuses to seal.**
6. On match, the browser does ECDH against an ephemeral keypair, seals the private key,
   and `PUT`s it to `device:<deviceId>`.
7. The device fetches the sealed envelope, opens it by ECDH inside its secure element,
   and re-seals it locally under a secure-element AES-GCM key carrying
   `setUserAuthenticationRequired`.

Step 7 needs an endpoint that does not exist yet — see "A gap in Change 1" below.

## The verification, and why it points this way

The threat is precise: the server is the party that stores and serves the device public
key, so the server is the party that can substitute its own — and then open everything
the browser seals. The code is the only thing that catches that. Everything below
follows from getting its direction right.

**The device displays; the browser verifies.** The device derives the code from the key
in its own keystore, which is ground truth the server cannot influence. The browser
derives it from the key the server handed it. If those differ, the server substituted.

**The check must gate the browser, because that is where the secret moves.** Verifying
on the device instead would be too late: by the time the device notices it cannot open
the envelope, the browser has already sealed the private key to the attacker's public
key and uploaded it. Step 5 above is the gate for that reason and no other.

**Do not copy the MFA number match wholesale.** `backend/internal/mfa/number_match.go`
solves a similar-looking problem — is the human in front of the right screen — and
`push_mfa_handlers.go:460` states its rule plainly: "The number match is verified HERE,
not on the device… only the server knows which one was right, so a client-side
comparison would be decoration." That is correct there and **exactly inverted here**.
In enrollment the server is the adversary, so server-side verification would be the
decoration. Reuse the interaction pattern's lesson — make the human do something a
reflex cannot fake — not its verification location.

**Typed, not chosen from a list.** The MFA control offers 2 digits plus 2 decoys with a
single attempt: a one-in-three blind rate, acceptable there because failure is terminal
and the prize is one sign-in. Here the prize is every message the account will ever
receive, and an attacker can induce re-enrollment by telling the user to re-pair their
phone. One-in-three with retries is not a control. Typing cannot be satisfied by a
reflex.

## The code

**Ten characters, Crockford base32, grouped `XXXXX-XXXXX`**, derived as
`truncate(SHA-256(devicePublicKey ‖ deviceId ‖ timeBucket), 50 bits)`. Crockford
because it excludes the character pairs people transcribe wrongly.

**Valid for two minutes**, matching `GET /api/pgp/qr/token`'s existing TTL. Reuse that
number rather than inventing a second one; if it moves, both should move together.

### Why the time bucket is the load-bearing part

The device publishes its public key at pairing, so the server learns it immediately,
while enrollment might not happen for months. Without a time component that is unbounded
offline grinding: the attacker generates keypairs until one produces a matching code.
The time bucket forces the collision to be found *inside the window*.

### Why the code can be short

Ten characters is fifty bits. An attacker with a GPU farm at ~10¹² hashes/sec gets
about 2^47 attempts in 120 seconds — short of 2^50 with margin, and that is against the
deferred-enrollment case. Enrolling at pairing collapses the window further.

Note the honest asymmetry in this bound: the attacker must generate *real keypairs*,
because they need the private half to open what the browser seals. That is far more
expensive than a bare hash, so the figure above is conservative.

### Two things deliberately not used

**Proof-of-work.** The construction works — require the device to find a nonce where
`H(K ‖ T ‖ nonce)` has *k* leading zeros and derive the code from that hash, and the
attacker pays 2^(N+k) while the honest device pays 2^k once. But a phone can afford
about k=20 before the wait is felt, which buys two characters. Two characters do not
justify a proof-of-work that must agree bit-for-bit across three independent client
implementations, plus a new failure mode when a slow device times out mid-ceremony.

**Commitment-based SAS (ZRTP-style).** This is the technique that makes grinding
impossible rather than merely expensive, and it is how ZRTP gets away with a
four-digit string. It is the documented upgrade path if a six-character code ever
matters. It is not taken now for two reasons. ZRTP is a media-path protocol whose SAS
is coupled to a Diffie-Hellman exchange inside the RTP stream; its implementations are
VoIP stacks with no browser equivalent, since WebRTC chose DTLS-SRTP instead. Adopting
it would mean reimplementing the commitment core in TypeScript and Kotlin — a bespoke
protocol with a citation, not a vetted library. And a commitment protocol's ordering
requirements are the kind that, when wrong, produce something that passes every test
and is silently grindable. Across three client implementations that risk exceeds the
four characters it saves. If it is ever wanted, SPAKE2 as Magic Wormhole uses it is
the better-libraried starting point, and it deserves its own spec.

## Wire format (2a)

**Storage.** `NativeDevice` (`backend/internal/state/store.go:67`) gains an enrollment
public key and the time it was published. That record already carries the device
identity and is per-user isolated, and `MFAApprover` on the same struct is the
precedent for adding a field that older rows decode as absent.

**Publishing** is authenticated by the pairing credential — a device may publish its
own public key. This is safe because a public key is not a capability: it lets the
browser seal *to* the device, and confers nothing by itself.

**Sealing uses the existing endpoints.** `PUT /api/pgp/identity/envelope/device:<id>`
already exists from Change 1, is `withAuth` (session only, never `withMailAuth`), and
requires a step-up credential. That asymmetry is exactly right and worth naming: **a
device may publish a public key, but only a session may mint a sealing.** It is also
what makes the planned passphrase-only tier enforceable — the server refuses to store a
device envelope for such an account, and no device credential can route around it.

**Revocation is weaker than "delete the slot", and this corrects a claim the parent
spec makes.** Deleting `device:<id>` removes the server's copy. It does not reach the
copy the device re-sealed under its own Keystore key, because the server has no reach
into that. So:

- **Before the device re-seals** — deleting the slot revokes it. That window is seconds
  at pairing, and at most the seven-day TTL for a deferred enrollment.
- **After the device re-seals** — the server cannot revoke it. Un-enrolling a lost phone
  means **rotating the identity key**, which invalidates every sealing and forces
  re-enrollment on every device.

This is inherent to any design where a device holds a durable local sealing, not a flaw
in the TTL — Signal has the same property, where unlinking a device stops future
delivery but does not reach what it already holds. It is a real cost of device
enrollment and the UI must not imply otherwise: "remove device" should say that it stops
future sealings and does not erase what that device already has.

The TTL helps here rather than hurting: it bounds how long the easy revocation window
stays open, and makes the hard case explicit instead of letting "revocation is
per-device" read as stronger than it is.

### A gap in Change 1

Change 1 registered all three envelope-slot routes as `withAuth`, on the reasoning that
a paired device must not be able to mint a sealing. That is right for `PUT` and
`DELETE` and wrong for `GET`, which the ceremony's step 7 needs: **the device cannot
currently read the envelope that was just sealed for it.** The blanket rule was correct
for the threat it was written against and too broad for this one.

2a must add a narrow device-authenticated read: a `withMailAuth` route that serves
**only** the calling device's own `device:<callerDeviceId>` slot, with the slot name
taken from the authenticated device record and never from the request. It must not
accept a slot parameter at all — a device asking for another device's envelope, or for
`password`, is the whole reason the general `GET` stays session-only.

Serving that one envelope to that one device is safe: it is sealed to a key whose
private half is non-extractable from that device's secure element, so no other caller
gains anything by obtaining it. The distinction to hold onto is the one Change 1
established and this narrows rather than reverses — **a device may publish a public key
and read what was sealed for it; only a session may mint or destroy a sealing.**

### The transport copy expires; the enrollment record does not

After step 7 the device holds a locally re-sealed copy and the server still holds the
ECDH-sealed one. The server's copy **expires seven days after it is written**, reusing
the pickup-link retention window rather than inventing a third number.

A TTL rather than a delete, because expiry needs no caller. The ceremony's last step
happens on the device, which has no session — and inventing a device-authenticated
delete to tidy up would hand a device the power to destroy a sealing, exactly the
capability the `withAuth` rule exists to withhold, spent on housekeeping. Nobody gains
anything; the server simply stops serving it.

Expiry is lazy: `WrappedEnvelopes()` already synthesises its result, so it filters
expired transport copies there, and the slot-count cap excludes them. Seven days is
generous — at-pairing enrollment completes in seconds, and the window only matters when
the phone is offline during a deferred enrollment. A device that misses it re-runs
enrollment; nothing is lost but the ceremony.

**This is why the enrollment record cannot live in the slot.** If `device:<id>` were
both the transport payload and the record of enrollment, expiry would make an enrolled
device read as un-enrolled. So `NativeDevice` carries the durable marker — enrolled, and
when — while the slot carries only the payload in flight. One is state, the other is
cargo.

### Keeping the marker honest

The server's marker records that the browser sealed for this device. The device's own
ability to decrypt is a different fact, and the two can diverge: reinstalling the app
destroys the Keystore key, as does a biometric-enrollment change on some
configurations. A marker that drifts optimistic is worse than none — it tells the user
a device is protected when it cannot read anything.

The device therefore reports its own enrollment state on the native registration call
it already makes at pairing and on every FCM token refresh, based on whether it can
still open its local envelope. One boolean on an existing call, no new endpoint, and
the marker becomes self-healing rather than write-once.

### Where the marker is shown

- **The browser's device list** (Security page): each paired device shows whether it is
  enrolled for encrypted mail, so a user can see at a glance which devices can read
  their mail and which cannot.
- **The device's own pairing screen**: an "encryption enrolled" indicator, so the state
  is visible where the user pairs and manages the device rather than only in webmail.
  The device renders this from its **local** ground truth — whether it can actually open
  its envelope — not from the server's marker, because the local answer is the true one
  and the whole point of the reporting above is to make the server agree with it.

## Failure and abandonment

- **Declined at pairing.** Nothing happens. Push and mail work exactly as today; the
  device list offers enrollment later. Declining must not be a dead end.
- **Code expires.** The device mints a fresh one. The browser reports expiry distinctly
  from mismatch — they mean different things and only one of them is alarming.
- **Mismatch.** The browser refuses to seal and says why in terms of the actual risk,
  not "try again". Up to three entries are allowed within the one two-minute window,
  because typing ten characters invites a genuine typo while blind guessing is
  hopeless — this is the opposite of the MFA case, where a single attempt is right
  precisely because guessing is cheap. After three, the ceremony aborts and must be
  restarted from the device.
- **Abandoned after publishing.** Harmless. A published public key with no envelope
  seals nothing and grants nothing.
- **Identity replaced after enrollment.** Change 1's invariant clears every non-password
  slot, so the device stops being able to decrypt and must re-enrol. That is correct and
  must be surfaced as such, not as an error.
- **Ordering.** Creating an identity clears every non-password slot, so enrollment must
  follow identity creation. Reversed, the device envelope is silently discarded. The
  server cannot detect this — both calls are individually valid and it cannot read
  either envelope — so it is a client obligation, and 2b and 2c must both test it.

## What this costs, honestly

- **It concedes attacks by someone holding an unlocked device.** That is the trade the
  parent spec already made and describes; enrollment is where it becomes real.
- **A live hostile server defeats the code.** The server ships the browser JavaScript
  and can serve a bundle that skips the comparison. `frontend/src/lib/keyVault.ts`
  already documents this boundary for the whole product. This control defends against a
  server that retains too much, a stolen backup, or a compromised database — not against
  one actively serving malicious code. Say so in the UI copy's vicinity rather than
  letting "we verify the fingerprint" be read as stronger than it is.
- **Ten characters is real friction at a moment the user wants to be finished.** It is
  once per device, which is the right place to spend it, but the copy has to earn it by
  saying what the check is for.
- **The Qt keystore story is still unproven** and this spec does not resolve it.

## Non-goals

- **Changing what the server can see.** It holds opaque envelopes and public keys before
  and after.
- **Decrypting or sending mail on the device.** Those are separate changes; enrollment
  only gives the device a key it can open.
- **Enrolling a device that is not already paired.** Enrollment builds on pairing and
  does not replace it.
- **Recovery codes.** Change 1's other half, independent of this.
