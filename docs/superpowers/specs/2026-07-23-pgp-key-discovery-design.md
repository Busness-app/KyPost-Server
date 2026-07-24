# PGP Key Discovery Ladder (WKD + Keyserver) — Spec A

## Context

Today, when a user sends an encrypted email to a recipient whose PGP key we
don't already have on file, the send path (`pgpRecipientPlan`,
`backend/internal/api/server.go:783`) drops that recipient into
`withoutKeyEmails` and falls back to a server-hosted, cleartext-emailed
**pickup link** (`backend/internal/pgpmail/pickup.go`,
`backend/internal/api/pickup_handlers.go`). That fallback is access-control,
not end-to-end encryption: the server holds the key and anyone with the link
can read the message.

The highest-leverage way to shrink how often that weak path runs is to
**discover the recipient's real public key automatically** and send true E2E
mail instead. The app already has a manual, user-confirmed keyserver lookup
(`handlePGPKeyserverLookup`, `backend/internal/api/pgp_keyserver.go:25`) but
never uses it at send time. This spec adds a **send-time discovery ladder**
with tiered auto-trust, pins discovered keys to the contact, and adds an
opt-in "encrypt whenever we have a key" switch.

Autocrypt (harvesting keys from inbound mail) is **out of scope** here and
captured as a separate stub at the end (Spec B).

## Goals

- At encrypted-send time, resolve each recipient through an ordered ladder and
  prefer real E2E encryption over the pickup fallback.
- Trust each discovery source according to its real strength (WKD auto-trust,
  keyserver confirm-first).
- Persist discovered keys + provenance on the contact so trust is durable and
  syncs to other clients.
- Never silently switch to a changed key (TOFU pinning).
- Add an opt-in setting to auto-enable encryption when every recipient already
  has a known key.

## Design

### 1. Send-time discovery ladder

When a send has **encryption enabled**, each recipient resolves through this
ordered ladder, stopping at the first hit:

1. **Contact key** — `findContactPGPKey` (`server.go:765`) as today. If present,
   pinned, and usable, use it silently.
2. **WKD** — fetch from the recipient's own domain. Domain-authoritative →
   **auto-trust, encrypt silently**, pin to contact (`source=wkd`).
3. **Keyserver** (keys.openpgp.org, reuse `handlePGPKeyserverLookup` logic) →
   **discover-then-prompt**: surface the fingerprint, user confirms once, then
   pin (`source=keyserver`, `verified=true`).
4. **No key** → existing `withoutKeyEmails` pickup fallback, unchanged.

Discovery lookups run **only when encryption is enabled for that compose** — a
WKD/keyserver query tells the queried domain/keyserver you're about to mail the
address, so we never do it speculatively.

### 2. WKD client

New `backend/internal/api/pgp_wkd.go` (sits next to `pgp_keyserver.go`):

- Try **advanced** method first, then **direct**:
  - advanced: `https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hu>?l=<localpart>`
  - direct:   `https://<domain>/.well-known/openpgpkey/hu/<hu>?l=<localpart>`
- `<hu>` = Z-Base-32( SHA-1( lowercase(localpart) ) ).
- WKD returns a **binary** (unarmored) key — parse with gopenpgp
  `crypto.NewKey` (the keyserver path uses `NewKeyFromArmored`; WKD is binary).
- **Reuse `newSSRFSafeHTTPClient`** (already used at `pgp_keyserver.go:40`) so
  discovery can't be pointed at internal hosts. Short timeout, `LimitReader`
  the body as the keyserver path does.
- Validate the returned key is not revoked/expired and actually carries the
  queried address as a user ID before trusting it.

### 3. Contact trust metadata (provenance + TOFU pin)

The contact model has one opaque `PGPKey` string
(`backend/internal/contacts/contacts.go:45`). Add optional fields that ride
CardDAV/mobile sync exactly like `MergedUIDs`/`MergedInto` do (unknown-field
tolerant, `contacts.go:56-61`):

- `pgpKeySource`      — `manual` | `qr` | `wkd` | `keyserver`
- `pgpKeyFingerprint` — the **TOFU pin** (first-seen fingerprint)
- `pgpKeyVerified`    — bool (user eyeballed the fingerprint, or it came via QR)

When a key is discovered for an address that has **no contact yet**, and
harvested-key storage is enabled (§7), auto-create a minimal contact (email +
key + provenance) so the pin is durable. Auto-created key contacts are the
subject of the removal + recreation-suppression flow in **Spec D** — removing
one records a suppression so discovery does not silently recreate it.

### 4. TOFU key-change safety

The pin is what makes auto-trust safe. If a later WKD/keyserver lookup returns
a fingerprint that **differs** from the pinned one:

- Do **not** silently switch and do **not** auto-encrypt to the new key.
- Drop that recipient to a "key changed — re-confirm" state; the new key is
  only adopted after explicit user confirmation.

This stops a compromised domain or a poisoned keyserver upload from quietly
redirecting ciphertext to an attacker's key.

### 5. Compose UX (extend existing check)

`handlePGPRecipientsCheck` (`pgp_keyserver.go:82`) already classifies
recipients for compose. Extend its response so each address reports a resolved
tier, and the compose UI (web `frontend/src/`, plus clients) renders it with no
silent downgrades:

- `verified key` (🔒) — pinned/verified contact key
- `found via WKD` (🔒) — auto-trusted, will encrypt
- `keyserver — confirm fingerprint` (⚠️) — needs one-time confirm
- `key changed — re-confirm` (⚠️) — TOFU mismatch
- `no key — will send pickup link`

The UI collects any one-time confirmations before send.

### 6. "Encrypt when we have a key" switch

New **per-user setting, default OFF** (surface in web
`frontend/src/pages/SecurityPage.tsx`, persisted server-side):

- When ON, composing auto-enables encryption **iff every recipient already has
  a usable known/pinned key** (contact key, or a previously-pinned
  WKD/keyserver key). This uses **only local knowledge** — no new network
  lookups, so no "about to email you" leak, consistent with §1.
- It does **not** trigger speculative WKD discovery on every send. Discovery
  still only runs once encryption is enabled for that compose.
- If any recipient lacks a known key, encryption is not force-enabled; the user
  chooses as today (and the normal ladder/pickup flow applies once they do).

> Deliberate boundary: a more aggressive "always try WKD on every send" mode is
> possible but rejected here for the privacy leak it implies. Revisit only if
> requested.

### 7. "Save discovered keys" switch (harvested-key storage toggle)

New **per-user setting, default ON** (surface in `SecurityPage.tsx`): controls
whether keys obtained by automatic discovery are **persisted**.

- **ON** — discovered WKD/keyserver keys are pinned to the contact and, for
  addresses with no contact, a minimal contact is auto-created (§3).
- **OFF** — discovery still runs and the key is used to encrypt **this** send,
  but nothing is written: no contact is created and no key/provenance is pinned.
  Every future send re-discovers. This is the "don't grow my address book /
  don't retain third-party keys" mode.

This same toggle governs Autocrypt harvesting in **Spec B** (harvested keys are
only stored when it is ON). Manual key entry and QR exchange are unaffected —
they are explicit user actions, not harvesting.

## Critical files (server)

- `backend/internal/api/pgp_wkd.go` — **new** WKD client (§2).
- `backend/internal/api/pgp_keyserver.go` — extend `handlePGPRecipientsCheck`
  response with tiers (§5); reuse lookup for the ladder.
- `backend/internal/api/server.go` — `pgpRecipientPlan`/`findContactPGPKey`:
  wire the ladder, pinning, and TOFU-mismatch handling (§1, §3, §4).
- `backend/internal/contacts/contacts.go` — new provenance fields (§3).
- Per-user settings store + `frontend/src/pages/SecurityPage.tsx` — the switch
  (§6) and compose-side tier rendering (§5).

## Verification

- **Unit**: WKD hu-encoding (known Z-Base-32/SHA-1 vectors), advanced→direct
  fallback, binary key parse, SSRF client rejects internal hosts, revoked/
  expired/wrong-UID keys rejected. Follow the existing table-test style in
  `pgp_keyserver_test.go` and point `keyserverBaseURL`/a WKD base var at an
  `httptest.Server` (same pattern as `keyserverBaseURL`, `pgp_keyserver.go:18`).
- **Ladder**: recipient with contact key (silent), with WKD key (auto-pin +
  encrypt), with only keyserver key (prompt), with none (pickup fallback).
- **TOFU**: pinned fingerprint + changed WKD result → re-confirm, no silent
  switch, no auto-encrypt.
- **Switch**: setting ON + all recipients known → encryption auto-enabled;
  one unknown recipient → not force-enabled; verify no WKD lookup fires until
  encryption is on.
- **Storage toggle**: setting OFF → discovery still encrypts the send but no
  contact is created and no key is pinned; setting ON → key pinned / minimal
  contact created.
- **E2E**: run backend, send encrypted to an address with a real WKD-published
  key, confirm ciphertext delivery (not a pickup link).

---

# Spec B (deferred) — Autocrypt key harvesting

Its own spec, to be written later. Sketch:

- Parse `Autocrypt:` headers from **inbound** mail on the processor/receive
  path (`backend/internal/processor/`, `backend/internal/adapters/imap/`).
- TOFU-store the harvested key + a per-sender message count; auto-trust for
  encryption only after N corresponded messages (weaker than WKD).
- Add `source=autocrypt` to the provenance enum from Spec A §3.
- Insert Autocrypt as a ladder tier **below** keyserver (opportunistic, TOFU).
- Persist per-sender counts somewhere on the receive side (new small store).

### Mobile / desktop client changes required (for the shared provenance + status work)

These land with Spec A's synced provenance fields and are extended by B's
`autocrypt` source. Both contact-syncing clients keep a local DB that already
carries `pgpKey`, so they need schema + mapping + UI updates:

**kypost-android** (Room; schema currently v7):
- `ContactEntity.kt` — add `pgpKeySource`, `pgpKeyFingerprint`,
  `pgpKeyVerified` columns; bump `AppDatabase.kt` to schema **v8** with a Room
  migration + new `app/schemas/.../8.json`, mirroring the v6→v7 migration and
  `MigrationTest.kt`.
- `ContactMappers.kt` / `ContactSyncModels.kt` — (de)serialize the new JSON
  fields from CardDAV/mobile sync (tolerate absent = legacy).
- `ContactDetailActivity.kt` + `activity_contact_detail.xml` — show key
  provenance ("via WKD", "keyserver — unverified", "verified", and later
  "via Autocrypt") and the TOFU/verified badge.
- `strings.xml` — new labels for the tiers/badges.
- Optional: a settings toggle mirroring the §6 "encrypt when we have a key"
  switch, if per-user settings are exposed to the client.

**kypost-Linux** (Qt/QML; SQLite migrations):
- `core/db/migrations/005_*.sql` — add the three provenance columns (follow
  `003_extended_contact_fields.sql` / `004_contact_self_and_merged.sql`).
- `core/models/Contact.h`, `core/db/ContactDao.cpp` — model fields + DAO
  read/write.
- `app/contacts/ContactFieldMapping.h`, `core/domain/ContactSyncRepository.cpp`,
  `core/vcard/VCardContact.cpp` — map the new fields through sync/vCard.
- `app/qml/pages/ContactDetail.qml` — render provenance + verified badge.
- `app/qml/pages/Settings.qml` — optional §6 toggle.

**kypost-for-Mac** — same pattern (local contact store + detail UI); mirror the
Qt client's field/mapping/UI additions.

> Note: PGP encryption is performed **server-side** on send, so clients do not
> encrypt; their job is to (a) sync/display the new provenance + verified
> state, (b) render compose-time recipient tiers if they have a compose screen,
> and (c) optionally expose the §6 switch. No client-side crypto is added.

---

# Spec C (deferred) — Outbound key publishing (be discoverable ourselves)

Its own spec, to be written later. Specs A/B make us *consume* WKD and
Autocrypt; C makes us *publish* so other providers can find our users' keys and
send us E2E mail in the first place. Nothing in the codebase does this today
(no Autocrypt anywhere; no `.well-known/openpgpkey` route). Sketch:

- **Host WKD** for domains this server is authoritative for: serve
  `GET /.well-known/openpgpkey/hu/<hu>?l=<localpart>` (direct method; advanced
  if using the `openpgpkey.` subdomain) returning each local user's **binary**
  public key, plus the `policy` file. Reuse the same hu (Z-Base-32/SHA-1)
  encoding built for Spec A §2 so lookup and publish share one implementation.
  Gate on a config flag + only for users who have a published key.
- **Add `Autocrypt:` headers to outbound mail** built on the send path
  (`backend/internal/mailmsg`, `backend/internal/pgpmail`), advertising the
  sender's key so correspondents' Autocrypt-aware clients harvest it (feeds
  other people's Spec B).
- Consider `Autocrypt-Gossip` on encrypted multi-recipient mail (optional).
- Docs: DNS/subdomain setup for the advanced WKD method.

---

# Spec D (deferred) — Multiple address books + discovered-keys book

Its own spec, to be written later. Motivated by Spec A auto-creating contacts
for discovered keys: those should be segregated and independently removable
without polluting the user's real address book. Today there is a single
per-user contacts store (`backend/internal/contacts/store.go`, surfaced over
CardDAV in `backend/internal/api/dav_server.go`). Sketch:

- **Multiple address books per user** — introduce named collections so the
  single store becomes one of several (CardDAV already models multiple
  addressbook collections, so this aligns with the protocol).
- **A system "Discovered Keys" address book** — auto-created key contacts from
  Spec A §3 land here, not in the user's primary book. Read-mostly, clearly
  labeled as machine-populated.
- **Remove key + suppress recreation** — removing a discovered-key contact (or
  just its key) records a **suppression entry** (per-user, keyed by email +
  optionally fingerprint) that Spec A's discovery ladder checks *before*
  auto-creating or re-pinning, so a removed key is not silently rediscovered.
  Suppression is itself user-clearable ("allow discovery again").
- **Interaction with the §7 storage toggle** — §7 OFF disables storage
  globally; Spec D suppression is the per-address override for when §7 is ON.
- Client impact: address-book selection UI + the discovered-keys book view;
  extends the same clients listed under Spec B.
