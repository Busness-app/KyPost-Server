# Groups

## Purpose

Per-user contact groups: named `Group` records that `contacts.Contact`
references by ID (`GroupIDs`). Renaming a group is an `Upsert` on its
existing `ID`, so contacts never need rewriting when a group is renamed.

## Ownership

All code under `backend/internal/groups/`. Consumed by `api/` (group CRUD
handlers, and the contact CRUD handlers when validating/resolving
`GroupIDs`). Deliberately independent of `contacts/` — neither package
imports the other; `api/` is the only place that knows about both.

## Local Contracts

- `Store` is instantiated per user directory (`groups.New(userStateDir)`),
  mirroring `contacts.Store` — one file, `groups.json`, sibling to
  `contacts.json` in `$STATE_DIR/users/<userID>/`.
- Every read and mutation re-reads `groups.json` from disk first
  (`refreshFromDiskLocked`), then writes atomically via
  `fsutil.AtomicWriteFile`, for the same shared-nothing-process reason as
  `contacts.Store`.
- **`List` and `Get` return that re-read's error.** A group is a recipient set,
  and `api.Server.sanitizeGroupIDsForUser` writes its result straight onto the
  contact being saved — so an unreadable `groups.json` answered as "no groups"
  erased the user's memberships on the next contact write. See root
  `backend/AGENTS.md`.
- Unlike `contacts.Store`, `Store.Delete` is a **hard delete**, not a
  tombstone — groups aren't synced incrementally by CardDAV or mobile sync
  today (a contacts-sync response embeds the full groups list rather than a
  delta), so there's nothing that needs to observe a group deletion after
  the fact. If group sync ever needs a delta/cursor, switch to the
  tombstone+`ChangedSince` shape `contacts.Store` already uses.
- Deleting a group does **not** touch any `Contact.GroupIDs` — that's the
  caller's (`api/`) responsibility, to keep this package from depending on
  `contacts/`.

## Work Guidance

- Keep this package free of HTTP concerns — those live in
  `api/contacts_handlers.go` (or a sibling `api/groups_handlers.go`).

## Verification

- `go vet ./internal/groups/...` must pass.
- Unit tests should cover: create/rename/delete, and that `List` reflects
  disk state written by a separate `Store` instance (cross-process
  consistency, matching `contacts` package test conventions).

## Child DOX Index

No child AGENTS.md files.
