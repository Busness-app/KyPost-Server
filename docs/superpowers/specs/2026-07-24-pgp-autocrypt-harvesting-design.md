# PGP Autocrypt Harvesting (Spec B) — Design

## Context

Spec A added a **send-time** key-discovery ladder (pinned contact key → WKD →
keyserver → pickup fallback) and pins discovered keys to contacts with
provenance (`PGPKeySource`, `PGPKeyFingerprint`, `PGPKeyVerified`). D1 added a
per-user discovery-suppression list and a `DiscoveryCreated` contact marker.

Both of those *query* for keys at send time. This spec adds the complementary
**receive-side** source: harvest a correspondent's PGP public key from the
`Autocrypt:` header of inbound mail, so the send-time ladder already has a real
E2E key for people who never published to WKD or a keyserver — shrinking how
often the weak, server-hosted pickup-link fallback runs.

Autocrypt is deliberately *opportunistic* E2E: the key just arrived in mail
"from whoever emailed you". To keep that from being a trust hole, B harvests
**only from DKIM-authenticated inbound mail** (option C from brainstorming),
and treats a harvested key as the **weakest rung** — it never overrides a key
the user typed/scanned or one discovered via domain-authoritative WKD.

## Goals

- Automatically pin correspondents' Autocrypt keys to contacts, from
  DKIM-authenticated inbound mail only.
- Reuse existing infrastructure end to end: the poller's per-message loop,
  cryptographic DKIM verification, Spec A key validation + provenance fields,
  and D1's suppression + `DiscoveryCreated` + the `StoreDiscoveredKeys` toggle.
- Never disturb mail processing: harvesting is best-effort and fully isolated.
- **No send-path changes.** A harvested key is an ordinary pinned contact key,
  which the existing Spec A resolver already uses at step 1.

## Non-goals (scope boundaries)

- **No send-time Autocrypt "lookup".** Autocrypt keys exist only in received
  mail; there is nothing to query at send time, so the `keyResolver` is
  unchanged.
- **No confirm-first / pending-key holding area.** Because we harvest only from
  DKIM-authenticated mail (never silently trusting an unauthenticated header),
  there is no need for a new send-ladder tier, a pending-keys store, or a
  confirmation UI. Mail whose Autocrypt header is not DKIM-backed is simply
  ignored.
- **No per-sender message counting / trust accrual.** DKIM authentication is
  the trust gate; a message counter adds a persistent store for no security
  gain here.
- **No client code.** See "Deferred".

## Design

### 1. Architecture — receive-side only

Harvesting is a new best-effort step in the poller
(`backend/internal/processor/`) that runs inside `tickUser`'s per-message loop.
It writes into the same per-user `contacts` store the api process reads (the
two processes stay coherent through `contacts.Store`'s `refreshFromDiskLocked`,
exactly like `state.Store`/`rules.Store`/`sendas.Store`). A harvested key
becomes a normal pinned contact key with `PGPKeySource = "autocrypt"`, so the
Spec A resolver's step 1 (usable pinned key → encrypt silently) consumes it
with no resolver change.

### 2. New Autocrypt header parser

New package `backend/internal/pgpautocrypt` with a pure, table-tested parser:

- `ParseAutocryptHeader(value string) (addr string, keydata []byte, err error)`
  - Parses `Autocrypt: addr=<a>; [prefer-encrypt=<x>;] keydata=<base64>`.
  - `keydata` is **base64** (not armored); decode to the binary key bytes.
  - `prefer-encrypt` is parsed-and-ignored (we only want a usable key).
  - Unknown non-critical attributes are ignored (per the Autocrypt spec);
    an unknown **critical** attribute (one whose name does not start with `_`)
    makes the header invalid.
- The **"more than one `Autocrypt` header ⇒ treat as none"** rule lives at the
  call site (the harvester sees the full header set); the parser handles one
  header value.

The parser does not parse the OpenPGP key itself — it returns the raw
`keydata` bytes, which the harvester turns into a `crypto.Key` via
`crypto.NewKey` (the same binary-key path WKD uses) and validates with Spec A's
`validateDiscoveredKey`.

### 3. Harvest step (poller)

New file `backend/internal/processor/autocrypt_harvest.go`.

`Poller.userContactsStore(userID) (*contacts.Store, error)` — cached
per-user contacts store, mirroring `userRulesStore`/`userSendAsStore`.

`(p *Poller) harvestAutocrypt(ctx, uc, msg)` — called in `tickUser`'s message
loop **immediately after the `store.Seen(msg.ID)` skip**, so it runs once per
newly-seen inbound message, and **only when the user's `StoreDiscoveredKeys`
setting is true** (loaded via `pgpdiscovery.Load(userStateDir)`). It is
best-effort: every error is logged and swallowed; it never returns into
`handleMessage`, never touches `MarkProcessed`, the checkpoint, the
rate-limit budget, or notifications. It is idempotent, so re-running it for a
message reconsidered on a later tick is harmless.

Per-message steps:

1. **Cheap pre-check.** Fetch only the `Autocrypt` and `From` header fields via
   the IMAP `BODY[HEADER.FIELDS (AUTOCRYPT FROM)]` mechanism that
   `auth_results.go` already uses. If there is no `Autocrypt` header, stop —
   this keeps the expensive raw fetch off the ~99% of mail without one.
2. **Single-header rule.** If more than one `Autocrypt` header is present,
   stop (treat as none).
3. **Parse.** `ParseAutocryptHeader` → `addr`, `keydata`. On error, stop.
4. **Address match.** `addr` (normalized: lowercased, trimmed) must equal the
   `From` address; otherwise stop.
5. **DKIM gate.** `FetchRawMessage(ctx, uid)` →
   `imapadapter.VerifyDKIMForDomain(raw, domainOf(addr))`. If it does not
   verify, stop (option A: unauthenticated Autocrypt is skipped).
6. **Key parse + validate.** `crypto.NewKey(keydata)` then Spec A's
   `validateDiscoveredKey(key, addr)` (reject revoked/expired; require `addr`
   as a UID). On failure, stop.
7. **Suppression gate.** If `addr` is in `pgpdiscovery.SuppressedSet`, stop.
8. **Persist by precedence** (§4).

### 4. Precedence (fill-a-gap only)

The harvest-pin helper loads the matching contact (by email, case-insensitive)
and applies:

- **No contact, or contact with no usable key** → pin the harvested key:
  `PGPKey` (armored), `PGPKeyFingerprint`, `PGPKeySource = "autocrypt"`,
  `PGPKeyVerified = false`. If no contact existed, create a minimal one
  (`FormattedName`/`Emails` = the address) with `DiscoveryCreated = true`.
- **Existing `manual` / `qr` / `wkd` / `keyserver` key** → leave untouched,
  always. Autocrypt never overrides a user-owned or domain-authoritative key.
- **Existing `autocrypt` key, same fingerprint** → no-op (may refresh the
  stored armored copy; provenance unchanged).
- **Existing `autocrypt` key, different fingerprint** → **newest wins**: update
  to the new key. Safe because the new key arrived DKIM-authenticated from the
  sender's own domain (legitimate key rotation), and it never touches a
  stronger source.

"Usable" is judged with `pgpmail.CheckKeyStatus(...).Usable()`, matching the
resolver. Writes go through `contacts.Store.Upsert`.

### 5. Provenance constant

`backend/internal/contacts/contacts.go` gains
`PGPSourceAutocrypt = "autocrypt"` alongside the existing
`PGPSourceManual`/`PGPSourceQR`/`PGPSourceWKD`/`PGPSourceKeyserver`.

## Isolation & error handling

Harvesting mirrors the poller's existing best-effort side steps (cache-warm,
too-large rejection): a header-fetch error, unparseable `keydata`, DKIM
failure, validation failure, or contacts-store write error is logged and
swallowed. It never affects the classification pipeline, `MarkProcessed`, the
checkpoint, the rate limiter, or push notifications. One malformed Autocrypt
header cannot disturb mail processing.

## Testing

- **Parser (`pgpautocrypt`):** valid header; missing `keydata`; malformed
  base64; unknown critical (non-`_`) attribute → invalid; unknown `_`-prefixed
  attribute → ignored; `prefer-encrypt` parsed-and-ignored.
- **Single-header rule:** two `Autocrypt` headers → treated as none (call-site
  test in the harvester).
- **Harvest (fake IMAP client + generated identities):**
  - DKIM-pass, Autocrypt present, no existing key → pinned `autocrypt`,
    new contact marked `DiscoveryCreated`.
  - DKIM-fail → nothing pinned.
  - `addr` ≠ `From` → skipped.
  - Suppressed address → nothing pinned.
  - `StoreDiscoveredKeys` off → nothing pinned (no IMAP fetch beyond the loop).
  - Existing `wkd`/`manual` key → left untouched.
  - Existing `autocrypt` key, different (DKIM-authenticated) fingerprint →
    updated (newest wins); same fingerprint → no-op.
  - Revoked/expired harvested key → rejected.
  - Reuse DKIM test vectors from `dkim_verify_test.go` and identity generation
    from `pgp_resolver_test.go`.
- **No send-path tests** — the resolver is unchanged; existing Spec A resolver
  tests already cover "usable pinned key → step 1".

## Critical files

- `backend/internal/pgpautocrypt/autocrypt.go` — **new** header parser.
- `backend/internal/processor/autocrypt_harvest.go` — **new** harvest step +
  `userContactsStore` + precedence-pin helper.
- `backend/internal/processor/poller.go` — call `harvestAutocrypt` in
  `tickUser`'s message loop.
- `backend/internal/adapters/imap/` — header-fields pre-check method for the
  `Autocrypt`/`From` fields (reuse the `auth_results.go` `BODY[HEADER.FIELDS]`
  plumbing; add a method if one isn't already exposed).
- `backend/internal/contacts/contacts.go` — `PGPSourceAutocrypt` constant.

## Deferred (revisit only if it shows value)

- **Client provenance label** ("via Autocrypt") — bundled into Spec A's
  already-deferred mobile/desktop provenance work; `pgpKeySource="autocrypt"`
  rides existing CardDAV/mobile sync as an opaque string today, and clients
  that render provenance simply won't label it until then.
- **`prefer-encrypt` hint** — parsed-and-ignored; a future "encrypt by
  default with this contact" behavior could consume it.
- **Autocrypt-Gossip** (keys of other recipients embedded in encrypted message
  bodies) — not harvested; overlaps Spec C (outbound publishing) and needs
  decrypted-body access.
- **Autocrypt Setup Message**, key-rotation notifications, per-sender
  "last seen" counters — out of scope.
