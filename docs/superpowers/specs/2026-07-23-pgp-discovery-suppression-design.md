# PGP Discovery Suppression (Spec D1) — Design

## Context

Spec A added a send-time PGP key-discovery ladder that can **auto-create a
minimal contact** and pin a discovered key (WKD/keyserver) for a recipient the
user never saved. Two gaps followed:

1. If a user deletes an auto-created key contact, the next encrypted send
   silently **re-creates it** — the discovery ladder has no memory of the
   removal.
2. There is no clean way to tell a discovery-created contact apart from a real
   one, so the user can neither see nor filter them: the only marker,
   `PGPKeySource ∈ {wkd, keyserver}`, describes the *key's* origin and can also
   appear on a contact the user made themselves.

D1 is the first, independent slice of the original "Spec D" stub. It adds a
per-user **discovery suppression** list (opt out an address from discovery) and
a **`discoveryCreated` contact marker**. The larger pieces of the old stub —
**D2** (a dedicated "Discovered Keys" address book) and **D3** (general
user-created multiple address books over CardDAV) — remain **deferred**; see
"Deferred" at the end. Revisit them only if they show value.

## Goals

- Removing a discovery-created contact (or explicitly rejecting a discovered
  key) prevents the discovery ladder from silently bringing it back.
- Suppression is per-address, user-visible, and user-clearable ("allow
  discovery again").
- Discovery-created contacts carry a clean, filterable marker that drives a
  user-visible "added automatically" badge.

## Design

### 1. `discoveryCreated` contact marker

Add one optional field to `contacts.Contact`
(`backend/internal/contacts/contacts.go`), riding CardDAV/mobile sync like the
existing `MergedUIDs`/provenance fields:

- `DiscoveryCreated bool` — json `discoveryCreated,omitempty`.

Set to `true` **only** by the resolver's `pin()` in the branch that creates a
brand-new minimal contact (no pre-existing contact for the address). It is
**never** set when pinning a discovered key onto a contact the user already
had. This is the precise "discovery made this whole contact" signal — distinct
from `PGPKeySource`, which only describes the key.

Uses:
- **Filter:** "contacts discovery created" = `DiscoveryCreated == true` (also
  the exact predicate a future D2 book would segregate on).
- **UI badge:** clients render "Added automatically by PGP key discovery
  (<source>)" from `DiscoveryCreated` + `PGPKeySource`. No free-text `Notes`
  pollution (structured-flag-only; generic third-party CardDAV clients simply
  won't show the badge, which is acceptable).
- **Delete trigger precision:** implicit suppression (below) keys on this flag.

### 2. Suppression store

A per-user list of addresses opted out of discovery, persisted as
`pgp-discovery-suppressions.json` under the user's state dir — same pattern as
Spec A's `pgpdiscovery.Settings`. New file `suppress.go` in the existing
`backend/internal/pgpdiscovery` package.

- Entry: `{ email string (lowercased), suppressedAt string (RFC3339),
  reason string ("deleted" | "explicit") }`.
- API: `LoadSuppressions(dir) ([]Suppression, error)` (absent file → empty),
  `AddSuppression(dir, email, reason) error` (idempotent on email; lowercases;
  updates timestamp/reason on re-add), `RemoveSuppression(dir, email) (bool,
  error)`, and a helper `SuppressedSet(dir) (map[string]bool, error)` for the
  resolver. Atomic writes, mode `0o600`, mirroring `settings.go`.

### 3. Resolver integration (the effect)

`keyResolver` (`backend/internal/api/pgp_resolver.go`) gains a
`suppressed map[string]bool` field, populated at construction in the send
handler (`handleMailSend`) via `pgpdiscovery.SuppressedSet(...)`, alongside the
existing settings load.

In `resolve(ctx, email)`, **after** the step-1 usable-pinned-contact-key
short-circuit and **before** any WKD/keyserver lookup:

```
if kr.discover && kr.suppressed[strings.ToLower(strings.TrimSpace(email))] {
    return resolvedKey{Tier: tierNone}
}
```

Effect: a suppressed address does no network lookup, no pin, no auto-create —
it falls through to `withoutKeyEmails` and the existing pickup path. Suppression
blocks *discovery only*; a key the user holds themselves (manual/QR, used at
step 1) is unaffected. This is orthogonal to Spec A's global
`StoreDiscoveredKeys` toggle (which only controls persistence).

### 4. Triggers (hybrid)

- **Implicit on delete.** When a web delete removes a contact with
  `DiscoveryCreated == true`, record a suppression (`reason: "deleted"`) for
  each of the contact's email addresses. Covers `handleContactByID` (DELETE)
  and `handleContactsBulkDelete` in `backend/internal/api/contacts_handlers.go`.
- **Explicit action.** New endpoint that, for a given contact, clears its PGP
  key fields (`PGPKey`, `PGPKeySource`, `PGPKeyFingerprint`, `PGPKeyVerified`)
  while keeping the contact, and records a suppression (`reason: "explicit"`)
  for its emails — the "keep the person, reject the discovered key" case.

### 5. Management API

All under `s.withAuth`, per-user via `authFromContext` + `s.userStateDir`:

- `GET /api/pgp/discovery/suppressions` → `{"suppressions":[{email,suppressedAt,reason}]}`.
- `DELETE /api/pgp/discovery/suppressions/{email}` → "allow discovery again"
  (removes one; 404 if absent). `{email}` is path-escaped.
- `POST /api/pgp/discovery/suppress-contact` `{ "contactUID": "..." }` → the
  explicit action from §4 (clear key fields + suppress the contact's emails);
  returns the updated contact.

### 6. Frontend (web, minimal)

- **SecurityPage** (`frontend/src/pages/SecurityPage.tsx`): a "Discovery
  opt-outs" list under the existing discovery-settings area, showing each
  suppressed address + reason, with an "Allow discovery again" button
  (`DELETE`). Follows the existing settings-list pattern.
- **Contact view:** render an "Added automatically by key discovery (<source>)"
  badge when `discoveryCreated`, and surface the explicit "Remove key & stop
  rediscovering" action on a contact whose key source is `wkd`/`keyserver`.
- `frontend/src/api/pgp.ts`: typed clients for the three endpoints + a
  `discoveryCreated?` field on the contact type.

## Testing

- **Store:** suppression round-trip (add/list/remove, idempotent re-add, absent
  file → empty), `SuppressedSet` shape.
- **Resolver:** suppressed address → `tierNone` with **no** WKD/keyserver
  lookup fired (assert via a WKD httptest server that must not be hit); a
  manual pinned key at step 1 is still returned for a suppressed address.
- **`discoveryCreated`:** resolver sets it when auto-creating a new contact,
  and does NOT set it when pinning onto an existing contact.
- **Triggers:** deleting a `DiscoveryCreated` contact records suppression for
  its emails; deleting a normal contact does not; the explicit endpoint clears
  the key fields and records an "explicit" suppression.
- **API:** list/clear round-trip; unsuppress of an absent email → 404.

## Critical files

- `backend/internal/contacts/contacts.go` — `DiscoveryCreated` field.
- `backend/internal/pgpdiscovery/suppress.go` — **new** suppression store.
- `backend/internal/api/pgp_resolver.go` — `suppressed` field + skip-on-suppress
  in `resolve`; set `DiscoveryCreated` in `pin()`'s create branch.
- `backend/internal/api/server.go` — build `suppressed` set in `handleMailSend`;
  register routes.
- `backend/internal/api/pgp_discovery_handlers.go` — list/clear + explicit
  suppress-contact handlers.
- `backend/internal/api/contacts_handlers.go` — implicit suppression on delete.
- `frontend/src/pages/SecurityPage.tsx`, `frontend/src/api/pgp.ts`, contact
  view component — opt-out list, badge, explicit action.

## Deferred (revisit only if it shows value)

- **D2 — dedicated "Discovered Keys" address book:** segregate
  `discoveryCreated` contacts into their own collection instead of the primary
  book. Depends on multi-collection support (D3). The `discoveryCreated` flag
  added here is the predicate it would segregate on.
- **D3 — general user-created multiple address books over CardDAV:** arbitrary
  named books (MKCOL, multi-collection home set, per-book sync cursors) + client
  UI. Large, mostly CardDAV/sync infrastructure; today CardDAV exposes exactly
  one fixed book per user (`dav_server.go`).
- **Sync-path parity:** implicit suppression on delete is wired only on the web
  API delete paths; CardDAV and mobile-sync deletes do not auto-suppress in D1
  (same boundary as Spec A's manual-key fingerprint backfill).
