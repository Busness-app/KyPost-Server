# Multi-wrapped key custody: making client protection the only mode

**Status: proposal.** This asks for a deliberate change to a rule `docs/E2E_PGP.md`
states as settled, and most of the work is server- and browser-side. It should be
accepted or rejected as a whole before any client work starts.

## What this proposes

Three changes, ordered by how much each unblocks:

1. **Multi-wrapped envelopes.** The private key envelope is sealed under several
   independent key-encryption keys rather than one, so losing any single one is
   survivable.
2. **Device enrollment.** A device joins the account once, through a
   fingerprint-verified handshake, and afterwards decrypts without a passphrase.
3. **Passphrase-only as an explicit tier.** Today's posture, preserved exactly,
   for users who want it — as a server-enforced account flag, not a client
   preference.

Together they make `client` protection usable everywhere, which is what has to be
true before `server` protection can be retired.

## Why this exists

`client` protection is already the default for new keys, and `server` protection is
already legacy — `migrationAvailable` exists to move accounts off it. So this is not
a proposal to start a migration. It is a proposal to unblock one that has stalled,
and to say plainly why it stalled.

It stalled because client protection is only usable in a browser. `E2E_PGP.md`'s
cold-start rule means every client reloads from nothing on every launch and prompts
for the account password before it can read anything. A browser tab absorbs that: it
lives for days. A phone process does not — Android kills it constantly, so the same
rule means typing the account password many times a day, on the device the document
itself calls "the least-trusted." The rational response is to stay on `server`
protection, or to read encrypted mail only in webmail.

The result is a mode that is the default on paper and a minority in practice, and a
legacy mode that cannot be retired because it is the only one that works everywhere.

## The rule being changed

From "Cold start":

> A client cannot keep the unwrapped private key across restarts — the web vault
> holds it in page memory only, and the mobile apps are told not to put it in the
> Keystore/Keychain, since anything recoverable without the password defeats the
> model.

And from "What this costs, honestly":

> **Admin password reset destroys the key.** The wrapping key comes from the
> password; an admin cannot rewrap a key they cannot open. Users must keep an
> exported backup. This is inherent to the model, not an implementation gap.

The first is proposed as the **opt-in tier** rather than the universal rule. The
second is proposed as **wrong** — it is inherent to wrapping the envelope once, not
to the model.

What does **not** change: the server never holds the key or anything that opens it,
the envelope stays opaque to it, decrypted mail is never cached server-side, and the
signature verdict always comes from the client's own decrypt.

## The argument

**The rule and mass adoption are mutually exclusive.** "Reconstitutable only from a
secret in the user's head" means the user supplies that secret whenever the process
dies. On a phone that is constant. No amount of UX work closes this; human memory is
the friction. One of the two goals has to yield, and this proposes it be the rule.

**The rule compares against the wrong baseline.** It weighs a device-held key against
a passphrase-held key, where the device key is worse. But a user who finds passphrase
mode unusable does not switch to passphrase mode with better discipline — they stay on
`server` protection, where the operator reads everything, always, with no attacker
action required and no user mistake needed. Against *that*, a key sealed in a secure
element and gated on device unlock is not a downgrade. It is the difference between
"one server compromise exposes every user's mail" and "an attacker must physically
hold this specific unlocked device." The rule optimises posture for the users who
already have the strongest posture, and its cost lands on everyone else.

**Every E2E system with real adoption made this call.** Signal, WhatsApp and iMessage
all keep keys on-device under the OS keystore. Signal's PIN is for *recovery*, not
per-session unlock. None of them asks for a passphrase to read a message. The systems
that did demand passphrase-per-session — PGP email, for thirty years — have close to
zero consumer adoption. That track record is the strongest available evidence about
which constraint actually binds.

**What device enrollment concedes, stated precisely.** An attacker who physically
holds the device *and* can satisfy its lock: a shoulder-surfed PIN, a compelled
fingerprint, a coerced unlock at a border, or malware already running as the app on
an unlocked device. That is the entire list. It concedes nothing to the server
operator, a server backup thief, a network attacker, or an offline filesystem image —
against all four, a secure-element-sealed envelope is as strong as a passphrase one,
because the sealing key is non-extractable. The conceded threats are real and they
matter enormously to a specific minority. That minority is what tier 3 is for.

## Change 1: multi-wrapped envelopes

Store a **set** of wrapped envelopes for one identity instead of a single blob. Each
entry is the same self-describing format used today, sealed under a different
key-encryption key:

- one derived from the account password (what exists today),
- one derived from a high-entropy **recovery code** shown once at key creation,
- one per **enrolled device** (Change 2).

Any one of them opens the key. The server stores them all and can open none of them.

This alone kills the biggest adoption blocker in the document. "Forgetting your
password destroys all your mail" cannot be the behaviour of a default mode, and the
stakes are higher than that line suggests — `E2E_PGP.md` notes the Sent copy is
encrypted to yourself, so a lost key takes the outbox with the inbox. A password
reset that costs the user their entire mail history is not a security property, it
is an outage the user cannot distinguish from data loss.

**The elegant part: enrolled devices are recovery paths.** With two devices enrolled,
a forgotten password costs nothing — either device re-wraps under the new one. The
offline recovery code stops being the primary mechanism and becomes the
single-device fallback, which is the right place for a secret people are bad at
storing.

**Ordering is load-bearing, and no server-side check can enforce it.** Creating an
identity clears every non-password slot — deliberately, because those envelopes seal
the key being replaced (see `SetPGPIdentityClientProtected`). So a client must
`POST /api/pgp/identity/client` **before** it `PUT`s the recovery slot. Reversed, the
recovery envelope is silently discarded and the user is told they hold a recovery
code that opens nothing — precisely the failure this design's "recovery codes get
lost" cost describes, arriving through a code path rather than through the user. The
server cannot detect the mistake: both calls are individually valid, and it cannot
read either envelope to notice one is orphaned. This is a contract the browser plan
has to honour and test.

The server side of this change shipped on `feat/multi-wrapped-key-custody`. The write
endpoints require a step-up credential (account password or auth secret), matching
every neighbouring key-material write — the plan file for that work predates this and
documents the `PUT` body without it.

Server-side this is a schema change on `User` (a list replacing
`PGPPrivateKeyWrapped`, with the old field readable as a one-entry list so existing
accounts need no migration pass) and a rewrap endpoint that replaces one entry
without disturbing the others. The server still interprets none of it.

## Change 2: device enrollment

The phone generates an EC P-256 keypair with `PURPOSE_AGREE_KEY`, StrongBox-backed
where the hardware allows, private half non-extractable. It publishes the public half
under its existing pairing credential. The browser — which already holds the
unwrapped key — does ECDH against an ephemeral keypair, seals the private key into a
device envelope, and uploads it as a new entry. The phone re-seals it locally under a
secure-element AES-GCM key carrying `setUserAuthenticationRequired`, and the server
drops the transport copy.

`minSdk = 31` on Android makes this buildable everywhere; `PURPOSE_AGREE_KEY` landed
in API 31. The Qt clients need an equivalent against their platform keystores, which
is the part of this proposal with the least certain footing and should be scoped
before the protocol is frozen.

**The handshake requires a user-verified fingerprint, and this is not polish.** In
this mode the server is the adversary. If the browser trusts the server's copy of
"this device's public key," a malicious server substitutes its own, receives the
sealed envelope, and opens the key the whole mode exists to withhold — silently, with
every client behaving correctly. Both ends display a fingerprint derived from the
device public key and the user compares them before the browser seals anything. This
is the same out-of-band check `kypost-android/Client_PGP_Update.md` already specifies
for QR key exchange, so the pattern and the UI vocabulary already exist. It is also
the check most likely to be dropped as friction by a later change; it is the one part
of this handshake that is load-bearing on its own. Bind the device id and
the PGP key fingerprint into the envelope's AAD as well, so a substituted or replayed
envelope fails authentication rather than decrypting into the wrong account's key.

Revocation is per-device — with a caveat this originally overstated, corrected while
designing the enrollment ceremony (`2026-08-04-device-enrollment-design.md`). Deleting
the entry removes the *server's* copy. It does not reach the copy a device has already
re-sealed under its own secure-element key, because the server has no reach into that.
So deletion revokes a device that has not yet completed enrollment; un-enrolling one
that has means rotating the identity key. That is inherent to any design where a device
holds a durable local sealing, and the UI must say what "remove device" actually does.

## Change 3: passphrase-only as an explicit tier

Today's posture, unchanged, for users who want it: no device envelopes, full reload
every cold start, key reconstitutable only from something the user knows.

**It must be a server-enforced account flag, not a client setting.** If passphrase-only
is a client preference, a client that ignores it — buggy, outdated, or hostile —
enrolls a device anyway, and the user's chosen posture is quietly not in force. The
server must refuse to store a device envelope for an account in this tier. That is the
one place the server can enforce a property it cannot otherwise verify, and it should.

On Android this should fold into **Hostile Location Protection** rather than
introducing a second axis. That toggle already means "I accept losing convenience for
posture," its audience is precisely the users these threats matter to, and it already
carries the offline-access cost. Same users, same trade, existing switch.

## What retiring `server` protection then requires

In order, because each depends on the last:

1. Multi-wrapped envelopes (server + browser). No client work. Worth shipping on its
   own merits whatever happens to the rest.
2. Device enrollment protocol (server + browser), then per-client enrollment.
3. Client-side decryption in every client. Android has BouncyCastle on the classpath
   already; see `kypost-android`'s
   `docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md`.
4. Client-side send in every client. Retiring `server` protection removes the
   server-side sign/encrypt path that `kypost-android/Client_Encrypted_Send.md` is
   built on — its "**Impossible here.** Save a draft and hand off to webmail" row
   stops being true the moment a device holds the key, and its webmail handoff
   quietly becomes the wrong answer while still reading as the deliberate one.
5. The sealed pickup-link path in every client, since the plaintext-storing fallback
   goes away with `server` protection.
6. Flip the default, migrate remaining legacy accounts, remove the mode.

Nothing before step 6 is irreversible.

## What this costs, honestly

- **Device enrollment concedes physical-device attacks.** Enumerated above. This is
  the real price and it should be described to users in those terms rather than
  softened.
- **Recovery codes get lost.** Multi-device enrollment is the mitigation, but a
  single-device user who loses both password and code is in exactly today's position.
  This improves the common case; it does not eliminate the failure.
- **Key lifecycle gets substantially more complex.** One blob becomes a set with
  independent rotation, revocation and rewrap paths. That is more surface for the
  kind of bug where an envelope is silently not re-sealed and a user discovers it
  months later.
- **Every client must implement more, not less.** Decrypt, send, sealed pickup links,
  enrollment. Retiring `server` protection removes the server's ability to paper over
  a client that has not caught up.
- **Keyword tabs stay degraded.** `poller.go:1411` already tags encrypted mail with a
  fallback label and never decrypts, in both modes — so this changes nothing there.
  Worth stating because it looks like a cost of this proposal and is not.
- **The Qt keystore story is unproven.** Android's is clear. If the Qt clients cannot
  hold a non-extractable device key, they fall back to the passphrase tier and the
  retirement in step 6 blocks on them.

## Non-goals

- **Changing what the server can see.** It holds opaque envelopes and ciphertext
  before and after.
- **Server-side search over encrypted bodies.** Out of scope and unaffected.
- **Weakening the passphrase tier.** It must remain exactly as strong as today, which
  is why the server enforces it rather than trusting clients.
- **Key generation, import or migration moving off the browser.** Unchanged.
