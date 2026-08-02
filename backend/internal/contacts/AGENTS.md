# Contacts

## Purpose

Per-user address book storage: `Contact` records with a stable `UID`, a
monotonic per-user `Rev` used as both the CardDAV ETag/sync-token source and
the mobile-sync cursor, and tombstoned (not hard) deletes so incremental sync
consumers (CardDAV `sync-collection`, the mobile `/api/contacts/sync`
endpoint) can observe deletions.

Also provides server-side deduplication (`dedupe.go`, `Store.Dedupe`): because
web CRUD, mobile sync, and the CardDAV client pull each assign their own UIDs,
the same person arrives multiple times. `Dedupe` merges live contacts that
share a normalized email/phone (or a name, when a contact is otherwise empty)
into their oldest member and tombstones the losers, so the merge propagates
through the existing sync model. Merge provenance is carried in two
server-side-only fields: the survivor's `MergedUIDs` and each loser
tombstone's `MergedInto`.

Also provides `Store.Search(query, limit)`: a case-insensitive substring
search over `FormattedName`/`GivenName`/`FamilyName`/emails, ranked by match
quality and truncated to `limit`, backing the compose-autocomplete
`GET /api/contacts/search` endpoint.

## Ownership

All code under `backend/internal/contacts/`. Consumed by `api/` (web CRUD
handlers, the CardDAV backend, the mobile sync endpoints); never imported by
`processor/` or the daemon today.

## Local Contracts

- `Store` is instantiated per user directory (`contacts.New(userStateDir)`),
  mirroring `state.Store` — one file, `contacts.json`, sibling to `state.db`
  in `$STATE_DIR/users/<userID>/`.
- Every read and mutation re-reads `contacts.json` from disk first
  (`refreshFromDiskLocked`), then writes atomically via
  `fsutil.AtomicWriteFile` — required because the API and daemon processes
  share no memory (see root `backend/AGENTS.md`), even though only `api/`
  touches contacts today.
- `Contact.Rev` is bumped by `Store.Upsert`/`Store.Delete` on every mutation;
  `Contact.ETag()` derives `"rev-<Rev>"` from it — there is no separately
  stored ETag field.
- Deletes tombstone (`Contact.Deleted = true`, PII fields cleared) rather than
  removing the record, so `ChangedSince` can report deletions to sync
  clients. Tombstones are permanently purged by `Store.GC` after
  `defaultTombstoneRetention` (30 days); `ChangedSince` returns `tooOld=true`
  when a caller's cursor predates the GC watermark, signaling "your delta may
  be missing deletions — discard the cursor and re-fetch a full snapshot".
- Conflict/concurrency policy (e.g. CardDAV `If-Match`, mobile-sync
  last-write-wins) is decided by callers in `api/`, not by `Store` itself —
  `Store.Upsert`/`Store.Delete` always apply the write unconditionally. Read
  the current record first if a conflict check is needed.

## Work Guidance

- Keep this package free of HTTP/CardDAV/vCard concerns — those live in
  `api/contacts_handlers.go` and `api/dav_server.go`, which translate to/from
  `Contact`.
- Any new sync-relevant field must participate in `Contact.tombstone()`'s
  clear-list if it carries PII, so deletes don't leak stale data. Exception:
  `MergedInto` is deliberately preserved through `tombstone()` (it is non-PII
  and set by `Dedupe` right after tombstoning the loser).
- Dedupe stays pure data logic here (matching/merge in `dedupe.go`, applied by
  `Store.Dedupe`); the HTTP surface (`POST /api/contacts/dedupe`) lives in
  `api/contacts_handlers.go`.

## Verification

- `go vet ./internal/contacts/...` must pass.
- Unit tests should cover: create/update/delete, tombstone field-clearing,
  `ChangedSince` cursor semantics (including `tooOld` after GC), GC
  actually removing old tombstones while preserving live contacts, and dedupe
  (email/phone normalization, group selection incl. the name guard, merge
  policy, provenance fields, and idempotency).

## Child DOX Index

No child AGENTS.md files.
