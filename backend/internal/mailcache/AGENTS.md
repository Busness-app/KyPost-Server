# Mail cache

## Purpose

Per-user, per-mailbox metadata cache for `GET /api/inbox`: UIDs, flags,
envelope headers, and (only via the daemon's opportunistic warm path) a
message's body — so a polling client doesn't force a live IMAP fetch on
every call, and the classic (no-`since`) response can usually be served with
zero IMAP round trips once the background poller has warmed it.

## Ownership

All code under `backend/internal/mailcache/`. Consumed by both `api/`
(`handleInbox`'s cache-first classic path and `since`-based delta path) and
`processor/` (the 90s poller's opportunistic warm-on-tick call) — unlike
`contacts`, which only `api/` touches today.

## Local Contracts

- `Store` is instantiated per user directory (`mailcache.New(userStateDir)`),
  mirroring `state.Store`/`contacts.Store` — one file, `mailcache.json`,
  sibling to `state.db`/`contacts.json` in
  `$STATE_DIR/users/<userID>/`.
- Every read and mutation re-reads `mailcache.json` from disk first
  (`refreshFromDiskLocked`), then writes atomically via
  `fsutil.AtomicWriteFile` — required because `api` and `processor` run as
  separate processes sharing no memory (see root `backend/AGENTS.md`), and
  here it's not hypothetical: both actually call into this package.
- A `Store` holds one independent window per mailbox key (`map[string]*mailboxWindow`)
  — a user can poll several folders, each with its own cursor.
- **Not a permanent store, unlike `contacts`.** A window represents "the
  current top-N view," which churns by nature. `Sync` (the live-IMAP-backed
  path) replaces the window's contents wholesale each call; there is no
  tombstone list and no GC pass — see `Store.Sync`'s doc comment for the one
  accepted correctness gap this implies (a second concurrent poller with an
  older cursor can miss a `Removed` notification if it wasn't the caller
  that drove the window-changing `Sync` call). Mitigation is client-side:
  periodically pass `since=0` to force a full resync, not a server-side
  retention mechanism.
- `Entry.Rev` vs `Entry.FirstRev`: `Rev` bumps on every metadata change;
  `FirstRev` is set once, at creation, and never changes. `SyncResult`
  classifies an entry as `New` (client needs the body) vs `Updated`
  (client already has this UID, flag/label-only) by comparing `FirstRev`
  to the caller's `since`, not `Rev` — an entry whose flags changed twice
  is still just "Updated" to a caller who saw it before either change.
- `Entry.Body` is **only** ever written by `Store.Upsert` (the poller's warm
  path). `Store.Sync` never sets or clears it — `imapadapter.ListOverviews`
  deliberately never fetches bodies, so `Sync` has nothing to write there;
  it only carries forward whatever `Body` an entry already had.
- **Asymmetric coverage by design:** the poller only ever calls `Upsert` for
  the `"INBOX"` key (it never polls other folders). Non-INBOX mailboxes are
  warmed lazily, the same way INBOX gets warmed for a brand-new user: the
  first `Snapshot` miss in `handleInbox` falls back to a live fetch and then
  calls `Upsert` itself. This is expected, not a bug — see root
  `Mobile_Mail_Relay.md` Part 5.

## Work Guidance

- Keep this package free of HTTP/IMAP concerns — `Overview` is a plain
  struct so this package never imports `adapters/imap`; translation from
  `*goimap.Email` happens in `adapters/imap`, translation to the wire
  `inboxEmail` JSON shape happens in `api/server.go`.
- If a new field needs to participate in cache-vs-live diffing, add it to
  both `overviewMetaEqual` and `entryMetaEqual` (mailcache.go) — they must
  stay in sync or `Sync`/`Upsert` will silently stop detecting that field's
  changes.

## Verification

- `go vet ./internal/mailcache/...` must pass.
- Unit tests should cover: new-message detection, flag-change detection,
  window-fallout removal, cursor monotonicity, the multi-poller
  `since`-filtering case (a lower `since` caller still sees changes bumped
  by a different caller's intervening `Sync`), limit-change window reset,
  persistence round-trip, independent per-mailbox windows, `Upsert`'s
  no-removal-inference and window-cap trimming, and `Snapshot`'s
  `fullyWarmed` boundary conditions.

## Child DOX Index

No child AGENTS.md files.
