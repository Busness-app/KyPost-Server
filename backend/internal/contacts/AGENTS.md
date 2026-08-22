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
handlers, the CardDAV backend, the mobile sync endpoints) **and by `processor/`**
(`poller.go`, and `autocrypt_harvest.go`, which writes contact key material from
inbound mail). Both processes therefore mutate this store, which is why anything
derived from it must be invalidated by a mechanism the daemon can reach — see
`PGPKeyGeneration` below.

## Local Contracts

- `Store` is instantiated per user directory (`contacts.New(userStateDir)`),
  mirroring `state.Store` — one file, `contacts.json`, sibling to `state.db`
  in `$STATE_DIR/users/<userID>/`.
- Every read and mutation re-reads `contacts.json` from disk first
  (`refreshFromDiskLocked`), then writes atomically via
  `fsutil.AtomicWriteFile` — required because the API and daemon processes
  share no memory (see root `backend/AGENTS.md`), and here it is not
  hypothetical: both actually write, the daemon through the Autocrypt harvest.
- **Every reader returns that re-read's error**: `List`, `Get`, `GetSelf`,
  `Search`, `ChangedSince` and `PGPKeyGeneration`. This store decides which key
  a message is encrypted to and whose signature counts as verified, so a stale
  answer is not a degraded answer — it is the removed key still working. New
  readers follow suit; a reader that cannot fail is a reader that fails open.
  See root `backend/AGENTS.md` for the repo-wide rule and the three fail-closed
  shapes callers may use.
- `Contact.Rev` is bumped by `Store.Upsert`/`Store.Delete` on every mutation;
  `Contact.ETag()` derives `"rev-<Rev>"` from it — there is no separately
  stored ETag field.
- Deletes tombstone (`Contact.Deleted = true`, PII fields cleared) rather than
  removing the record, so `ChangedSince` can report deletions to sync
  clients. Tombstones are permanently purged by `Store.GC` after
  `defaultTombstoneRetention` (30 days); `ChangedSince` returns `tooOld=true`
  when a caller's cursor predates the GC watermark, signaling "your delta may
  be missing deletions — discard the cursor and re-fetch a full snapshot".
  **`GC` only purges because something calls it** — `api.Server.StartContactsTombstoneSweeper`,
  wired in `app.startBackgroundSweepers` beside its ten siblings. It had no
  caller anywhere in the repo, tests included, so every deletion left a
  permanent residue (the tombstone keeps its client-chosen `UID`) and a sync
  client that added and removed entries grew the file without bound.
- **`MaxContactsPerUser` (10,000) bounds live contacts**, checked in
  `applyUpsertLocked` so every writer inherits it. Every sibling per-user store
  has a total cap and this one had none — `maxContactsSyncChanges` bounds one
  REQUEST, not the store. The cap bounds GROWTH, not editing: an existing
  contact (and a tombstone being revived) stays writable at the cap, or a full
  address book becomes read-only and the user cannot delete their way out.
  Tombstones do not count, so a deletion frees headroom immediately.
- **`PGPKeyGeneration` returns `(int64, error)` and changes whenever key
  material or the ADDRESS SET changes**, bumped in `applyUpsertLocked`/`applyDeleteLocked` via
  `bumpPGPKeyGenIfBindingChanged`. It exists so consumers can invalidate
  anything derived from this store — see `mailcache`'s `ContactKeyGen`. Two
  properties are load-bearing: it must move when addresses narrow (that changes
  what a key is an anchor for, without changing its bytes), and it must NOT
  move for unrelated edits like a rename, or every signed message re-fetches
  its body on every contact edit.
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
- Unit tests should cover: readers refusing to answer from memory while
  `contacts.json` is unreadable (`apply_batch_test.go`, and
  `api/store_fail_closed_test.go` for the caller side),
  create/update/delete, tombstone field-clearing,
  `ChangedSince` cursor semantics (including `tooOld` after GC), GC
  actually removing old tombstones while preserving live contacts, and dedupe
  (email/phone normalization, group selection incl. the name guard, merge
  policy, provenance fields, and idempotency).

## Child DOX Index

No child AGENTS.md files.
