# Backend

## Purpose

Go module owning the email classification engine, HTTP API server, IMAP integration, Ollama integration, polling loop, configuration, state persistence, health tracking, logging, and PII redaction.

## Ownership

All code under `backend/`. Produces the `kypost-server` binary consumed by the container at runtime.

## Local Contracts

- Go 1.26.4; direct dependencies: `go-imap`, `yaml.v3`, `webpush-go`, `golang.org/x/crypto`, `emersion/go-webdav` (CardDAV protocol handling, `carddav` subpackage; transitively pulls `emersion/go-vcard`)
- Entry point: `cmd/main.go` → `app.Run(os.Args)`
- All business logic lives under `internal/`; `cmd/` contains only the entry point
- Binary output: `kypost-server`, deployed to `/app/bin/kypost-server` in the container
- HTTP API listens on `WEB_PORT` (default 5866)
- Three runtime modes: `daemon` (poller only), `server` (API only), `all` (both)
- In Docker `server` and `daemon` run as separate processes that share no memory; all cross-process coordination happens through disk. Any store mutated by both processes must re-read from disk before mutating and write atomically (see `state.Store` and `users.Store`)
- Multi-user with roles (`admin`, `user`): accounts in `$CONFIG_DIR/users.json` (`users.Store`); sessions map token → `{userID, issuedAt, expiresAt, csrfToken}`; role is looked up live per request so deactivation/role changes apply immediately.
- **Sessions are in-memory only and are never persisted**, so every process restart logs every user out — and restarts are routine (`scheduleContainerRestart`). Deliberate: a stolen token cannot outlive the process, and no bearer-equivalent credential is written to the volume. Ruled out by the same reasoning: a second API replica would not share them. See `Session`'s doc comment in `api/server_auth_session.go`
- Outbound requests to a user- or client-supplied URL (CardDAV server config in `api/`, UnifiedPush endpoints in `processor/`) must screen the destination IP through `netguard.IsPrivateOrReserved` — one definition, deliberately in a leaf package, because the two call sites previously held separate copies that drifted out of correctness together. Screening happens twice: up front at config time, and again at dial time against DNS rebinding. `api`'s SSRF-safe client additionally refuses an https→http redirect
- An account can authenticate three ways — web session, paired device secret, CardDAV Basic Auth — and all three are revoked together by `revokeAllUserCredentials`. Any admin action that cuts off access (deactivate, reset-password, clear-MFA) must call it rather than revoking sessions and devices individually. The CardDAV credential cache additionally re-checks `u.Active` on every hit, so a deactivated account is refused even if it populated the cache in the window between the deactivation and the invalidation; the cache saves the scrypt verification, never the authorization decision
- **Any per-account state keyed off a client-supplied username must key it off `users.NormalizeUsername(...)`**, the same fold `GetByUsername` resolves the account with. The login lockout keyed on the raw string, which made `"victim"`, `"Victim"` and `" victim "` one account to the lookup and three independent strike budgets to the lockout — with whitespace padding that key space is unbounded, so three-strikes became unlimited online guessing from one IP
- Login CAPTCHA is an operator opt-in (`CAPTCHA_PROVIDER`) with three providers: `turnstile` and `friendly` verify a token against a third-party siteverify endpoint; `pow` is self-hosted (`captcha/pow.go`) and verifies an HMAC-signed hashcash challenge this server issued via `GET /api/auth/pow-challenge`. All three are checked in `handleLogin` before scrypt, so a bad solution never pays the password-hash cost. `pow` alone reports two outcomes as distinct errors so they refund the lockout strike instead of spending it: `captcha.ErrChallengeExpired` (a stale tab) and `captcha.ErrChallengeWrongClient` (the solution arrived from a different address than the challenge was issued to — a phone changing networks mid-solve). A wrong solution still spends one. Its three maps (spent salts, per-IP challenge budget, per-IP difficulty escalation) are swept by `StartPoWSweeper` in both `app.go` mode blocks. The first two are swept only when `pow` is the configured provider; the escalation map is swept **unconditionally**, because `handleLogin` records a failure against the client IP on every failed login whatever `CAPTCHA_PROVIDER` says — skipping the sweep on a default install left an unbounded map on the installs that never opted in.
  `pow` difficulty is adaptive: `powEscalation` (`api/pow_escalation.go`) multiplies the base `maxnumber` by 4 per recent failed login from the same client IP, capped at 1,000,000 and decaying after 15 minutes or on success. It keys on IP alone because the challenge is issued before the user has typed a username. The cap is load-bearing — uncapped, a persistent attacker drives the difficulty past what anyone behind that address can solve. A challenge is bound to the IP that requested it: `IssueAt` takes the client IP, puts it in the `clientip` field **and** in the signed preimage, and `Verify` compares it against `remoteIP`. Both, not just the preimage — carrying it in the payload is what lets `Verify` tell "your address changed" (`ErrChallengeWrongClient`, strike refunded) from "this signature is forged" (plain false, strike spent). The address check sits after the signature and expiry checks and before `consume`, so a foreign solution never burns its salt and a user retrying from the issuing address still succeeds. What escalation is still worth is bounded: it counts per address, so an attacker spraying from many addresses gets the base difficulty at each. It prices repetition — not a distributed attacker.
- **Every route in `server.go` must declare its auth model on its own line**, and the marker must be TRUE. Four tests enforce it: `TestEveryRouteDeclaresItsAuthModel` (a marker is present), `TestAuthMarkersMatchTheirHandlers` (the handler makes the call the marker claims — `withDeviceAuth`→`deviceAuthFromRequest`, `withTokenAuth`→`validatePairingToken`/`consumeQRToken`/`decodeAndVerifyPairingToken`, `withSelfAuth`→`currentUser`), and `TestAuthMarkersAreInert` (the markers stay no-ops). Use the middleware that gates it (`withAuth`/`withMailAuth`/`withAdmin`/`withDAVBasicAuth`), or the inert marker that says how the handler authenticates itself (`api/route_auth_markers.go`). Presence alone was not enough: the fastest way to green a forgotten `withAuth` was to type `withPublicRoute`, and a marker that lies launders "someone forgot" into "documented decision" — the first run of the match test found `/api/notifications/native/register` marked `withDeviceAuth` when it actually verifies a pairing token. `withPublicRoute` has no call to verify, so it is constrained two ways: the `publicRoutes` allowlist in `route_auth_test.go`, which demands a written reason per route, and `TestPublicRoutesDoNotAuthenticate`, which fails if a handler marked public calls an auth primitive at all. The allowlist alone was not enough — it accepts free prose, and `POST /api/mfa/push/respond` sat in it justified as authenticating "with the signed push nonce", a mechanism that does not exist anywhere in this codebase, while the handler's first act was `deviceAuthFromRequest`. A negative is checkable where a rationale is not. A rate limiter (`withWKDRateLimit`) is not an auth model
- **`Server`'s mutexes have a declared rank and it is machine-checked.** `cfgMu` before `sessMu` before `userMu` before `ollamaMu`. `TestLockOrderIsRespected` parses this package and fails on a function that takes one while holding a higher-ranked one — directly, or through any call chain inside `api/`. Adding a mutex to `Server` means adding it to `lockRank` in `lock_order_test.go`; one missing from that map is simply not checked. The rule was stated in `Server`'s doc comment and enforced nowhere, alongside the note that "nothing currently takes more than one, which is the only reason there is no deadlock to find today" — an ABBA deadlock that appears only under concurrent load in production, which no unit test would provoke. A deferred `Unlock` is deliberately NOT treated as an unlock at its source position: `defer mu.Unlock()` is written right after the `Lock`, so honouring it there releases a lock held for the rest of the function and silently defeats the check, since every critical section here is written that way.
- **Rate/cooldown state is one type per ALGORITHM, not one per call site.** `cooldown` (per-key "not again for N", send-as probes and classifier tests) and `singleUseTokens` (one-shot tokens: pairing nonces, spent QR tokens) each replaced two byte-identical copies. Copies do not inherit the fix made to the original, and both pairs had drifted: only one cooldown had a sweep, and only one token store hashed what it kept — the other held raw bearer values in a map that ends up in a heap dump one day. `singleUseTokens` keys are namespaced per caller (`qr:`, `pair:`) because one map now backs two token systems. The genuinely different algorithms — `failureLockout` (strikes), `ipRateLimiter` (token bucket), `powChallengeLimiter` (fixed window), `mfaPushLimiter` (sliding window) — stay separate; merging those would be forcing unlike things together, not deduplication.
- **Every scrypt derivation performed in response to a request must hold a KDF slot** (`Server.withKDFSlot`, `maxConcurrentKDF` = 4 × 128 MiB), including authenticated paths: a session bounds who may ask, not what the asking costs. The instance-wide login budget is a *rate* limit and admits before the work runs, so it does not substitute for the slot. **`withKDFSlot` takes a `context.Context` and RETURNS AN ERROR — handle it.** It waits at most `kdfMaxQueueWait` (2 s) and then returns `errKDFBusy` without running `fn`; a caller that ignores that reports "the server is overloaded" as "your password is wrong", which is a lie and a lockout. Every shed path must (a) answer `writeKDFBusy` (503 + `Retry-After`) and (b) REFUND the lockout strike it reserved, because no credential was examined — same reasoning as `ErrChallengeExpired`. It was an unbounded blocking send, which capped scrypt's memory and replaced it with an unbounded goroutine backlog draining four-at-a-time; neither `ReadTimeout` nor a client hanging up unblocks a channel send. Work that is many derivations (the recovery-code check is up to ten) takes the slot PER DERIVATION, not once around the loop — one slot held for ~2 s is a quarter of the instance's capacity, and four such callers stall every login
- **A reservation taken against the instance-wide login budget must be settled on every exit path.** `handleLogin` calls `admitCost` FIRST — before the per-IP lockout, the per-account lockout and the CAPTCHA check, deliberately, so an outbound CAPTCHA verification is inside the budget too — and every one of those can return without running a derivation. Holding the reservation on those returns made a request the server does NO work for more expensive to the budget than one it does: the bucket refills at `loginKDFDutyCycle` (0.2 s/s), so a caller already locked out drained it faster than it recovered for the price of an empty POST, and every legitimate sign-in on the instance — the admin's included — was answered 429 at the first check, indefinitely. The reservation is now held in a `loginBudget` value, settled exactly once by `chargeLoginKDF` (billing the true cost, or refunding a shed slot) or by `handleLogin`'s `defer budget.refund()`; `refund` is idempotent so the deferred call is inert once charged. Do not add a return between `admitCost` and the charge that bypasses the defer. `ipRateLimiter` additionally FLOORS the debt at one burst below zero in both `admitCost` and `settleCost`, so an unsettled reservation bounds recovery at `burst/refillPerSec` instead of growing without limit. Pinned by `TestRejectedLoginRefundsTheInstanceBudget`, `TestLockedOutFloodDoesNotDenySignInToEveryoneElse`, `TestBudgetIsSettledExactlyOnce`, `TestBucketDebtIsFloored`
- **`failureLockout` never evicts a live entry to stay under its cap; it SHEDS new keys instead.** Past `loginLockoutHardCap`, `tryAttempt` refuses keys the table has not seen (429) and sets `saturated`; keys already tracked proceed normally, so a flood cannot lock out users mid-accumulation. There used to be a second sweep stage that evicted locked entries to make room, and that was a lockout bypass with a price tag rather than a memory bound: an attacker wanting more guesses at one account pushed the table past the cap with rotating keys, and their target's cooldown was in the first tranche deleted — fifteen minutes became zero, repeatably. Shedding is fail-CLOSED; losing availability for unseen keys is visible and ends with the flood, whereas silently unlocking accounts is invisible and is what the flood is for. `logSaturatedLockouts` (on the session sweeper) reports it, because from outside a shed is indistinguishable from "login is broken". The sweep that remains reclaims only entries idle past `lockoutFor`, and keys off `lastSeen` NOT off "is this locked right now" — the latter deleted 1-of-3 and 2-of-3 progress and stopped the lockout engaging at all. Pinned by `TestFailureLockoutIsHardBounded`, `TestSaturatedTableStillServesKnownKeys`, `TestCrowdedTableDoesNotErasePartialStrikes`
- `users.Store`'s read cache is reached only through `withCachedUsers`, which passes the cached slice to a callback instead of returning it. The slice IS the cache's backing array, so a reader that retains, sorts or writes through it corrupts every subsequent request in the process; a callback makes that impossible to do by accident rather than forbidden by comment. `Get`/`GetByUsername`/`List` clone what they keep (`User.clone`, which also copies `RecoveryCodesHash` — the one field a struct copy still shares). Mutators do not use it at all: a read-modify-write must start from disk inside the file lock (`readFileUnlocked`). `Get`/`GetByUsername` resolve through `withIndexedUsers` against id and normalized-username maps built alongside the cache, not by scanning: `api.currentUser` calls `Get` on every authenticated request, and `GetByUsername` ran `NormalizeUsername` over every stored username on every login attempt, so per-attempt cost grew with the size of the instance on the one endpoint that is deliberately expensive and reachable anonymously. The index stores POSITIONS, not `*User` — the slice aliases the cache — and is rebuilt only when the file's stat changes, by the same check that governs the cache
- `users.HashPassword` writes at `hashCostN`, which is `users.ProductionScryptN` (`scryptN`, 2^17) except under `users.SetHashCostForTest`. That function **panics outside a test binary** (`testing.Testing()`): it exists to weaken password hashing and is exported from a package production code imports, so a dev flag or fixture loader calling it would drop every subsequent credential to 16 MiB — and since `NeedsRehash` also measures against `hashCostN`, nothing would ever flag them. It refuses anything below `users.MinVerifiableScryptN`, the floor `verifyScryptHash` accepts. Call it only from `TestMain`, never mid-run (unsynchronized package variable). `internal/api` applies the override (four minutes of tests → forty seconds); tests whose subject *is* the cost opt back out via `withProductionHashCost`, which uses `t.Cleanup` and `users.ProductionScryptN` rather than a returned restore func and a hardcoded `1<<17`. The sequential-tests invariant that makes this safe is enforced by `TestNoTestInThisPackageCallsParallel`, not by a comment. `api.timingDummyHash` re-derives when the cost changes so login-timing equalization cannot silently compare against the wrong figure
- The inbox wire format carries `bodyMode` (`"html"`/`"plain"`) alongside `body`, sourced from the MIME part the body was actually taken from (`imapadapter.clientBody`, `pgpmail.ParseContent`) and carried through `mailcache.Entry`. **Absent (`""`) means the server cannot know, and `clientBody` must return `""` — not `"plain"` — for an empty body**, or a confident answer gets stamped on a body that was never parsed and `mailcache.Store.Sync` preserves it forever. `bodyMode` describes the message the SERVER holds; for a client-protected account that is the ENVELOPE, and a `multipart/encrypted` envelope says nothing about the plaintext inside. The browser reads its own mode off the decrypted entity's `Content-Type` (`lib/mimeContent.ts`, mirroring `pgpmail.ParseContent`) and pairs body-with-mode in exactly one place (`pages/read/body.ts` `displayBody`). Clients must not re-derive the mode by inspecting bytes: `<user@example.com>` is plain text and treating it as markup deletes the address, while a tag allowlist calls `the <p> tag` markup and deletes that
- Usernames are validated by `users.ValidateUsername` at `Store.Create`: alphanumeric first character, then letters/digits/`.`/`_`/`-`, max 64. The rule exists because the CardDAV surface builds principal and address-book URLs out of the username and then guards access by comparing the first path segment back against it — `alice/bob` served its own owner a principal URL it then refused, and `..` produced paths outside the `/dav` mount. Existing accounts are not re-validated, so a pre-rule username keeps working
- Legacy `admin.env` is imported into `users.json` on first start (`users.LoadOrMigrate`), and legacy global data files are copied into the first admin's per-user dirs (`app/migrate.go`)
- Every bounded in-memory map in `api/` has an explicit sweep — sessions, MFA login challenges, the login/DAV/MFA/device lockouts, the single-use token set (pairing nonces and spent QR tokens), both cooldowns, the pickup store, and `deviceIndex`. `deviceIndex` was the last holdout and the one with attacker-influenced keys; `sweepDeviceIndex` rides `StartUserStoreSweeper` because it needs the same walk over every account's store, and it exempts in-flight reservations (`deviceReserving`) because those are precisely the entries with no disk row yet. "Swept lazily on access" is not a sweep: an entry nobody comes back for is never accessed. New per-request state that can be created by an unauthenticated (or merely password-holding) caller needs a sweeper wired in **both** `app.go` mode blocks
- Per-user data: IMAP credentials/tuning/notification prefs/CardDAV app-password hash under `$CONFIG_DIR/users/<userID>/`; mailbox state (checkpoint, processed set, decisions, push subscriptions, native devices, pairing `subscriberId`, contacts, mail cache) under `$STATE_DIR/users/<userID>/`. Global: `config.yaml` (timezone, log level, scan interval, rate limits, redaction, labels, Remote LLM, VAPID keys), root `$STATE_DIR/state.json` (AI-credits flag only)
- Contacts: per-user address book (`contacts/` package) synced two ways — a session-authenticated JSON CRUD API for the web UI, a real CardDAV surface (`/dav/{username}/contacts/`, HTTP Basic Auth against a separate app-specific password, not the login password) for native OS/CardDAV clients, and a per-device-credential-authenticated two-way JSON sync endpoint (`/api/contacts/sync`) mirroring the native push pull/pairing mechanism, for the companion mobile app. See [internal/contacts/AGENTS.md](internal/contacts/AGENTS.md) and root `Mobile_Contact_Sync.md`
- Mail cache: per-mailbox metadata cache (`mailcache/` package) backing `GET /api/inbox` — warmed opportunistically by the `processor/` poller's existing ~90s fetch (INBOX only) and by `api/`'s own live-fetch fallback, so the classic (no-`since`) response is usually served with zero IMAP calls, and a `since`-based delta mode avoids re-fetching bodies for already-seen messages. Not a permanent store like contacts — see [internal/mailcache/AGENTS.md](internal/mailcache/AGENTS.md) and root `Mobile_Mail_Relay.md`
- Anti-phishing: inbound mail that impersonates KyPost itself is flagged **in place** with the IMAP keyword `$Phishing` and recorded as a `flagged_phishing` decision (`processor/phish_scan.go`). Flagging never moves, archives, files to Junk, deletes, bounces, or re-marks a message — the mail stays in INBOX and stays unread. Detection is deterministic (kypost:// URIs, host-agnostic links to this app's own pairing/pickup paths, forged system-notice subjects) and is gated by real DKIM over the account's own domain, run **only** when the content check trips, so ordinary mail costs no DNS. The Ollama classifier is never consulted. `$Phishing` is deliberately **not** in `config.Labels.Allowlist`, so it never becomes an inbox tab. The clients refuse non-allowlisted URI schemes on their own, unconditionally — this server-side flag is advisory, which is why every step of it is best-effort
- Contact photos (`api/contacts_photo.go`): 5 MiB per photo, 200 MiB per account, content-hashed filenames, reference-counted sweep. **Every content type in `contentTypeExt` must have a decoder registered by a blank import in that file** — the upload path gates on `image.DecodeConfig`, so an advertised type with no decoder behind it is rejected 100% of the time with "file is not a decodable image". `image/webp` was exactly that (Go's stdlib has no webp decoder as of 1.26) and has been removed; restoring it means adding `golang.org/x/image/webp`, not a map entry
- Secrets (IMAP passwords) are encrypted at rest with the single master key `$SECRET_DIR/imap-config.key`
- Logs are structured JSON, written to stdout and a rotating file (16 MB max × 8 backups) under `LOG_DIR`

### Internal Package Layout

| Package | Responsibility |
|---------|---------------|
| `app/` | Mode flag parsing; bootstrap logger, config, users store, legacy migration, poller, API server |
- **Per-user mailbox state is SQLite** (`STATE_DIR/users/<id>/state.db`), not JSON. `state.Store` owns processed-message ids, the decision audit log, native devices, web-push subscriptions, the App Pull queue and desktop pairing. Every method reads and writes the database directly — there is no in-memory copy, no dirty flags, and no `fsutil.WithFileLock`, because SQLite's own WAL locking is what makes the api and daemon processes safe against each other. Two rules that are load-bearing rather than tuning:
  - the DSN sets `_txlock=immediate`. `database/sql`'s `Begin` issues a DEFERRED `BEGIN`, which cannot upgrade to a writer under contention and fails `SQLITE_BUSY_SNAPSHOT` (517) — `busy_timeout` does not retry an upgrade. Pinned by `TestConcurrentPairingCodeConsumedOnce`.
  - `state.Store` releases its handle on UNREACHABILITY, via the `runtime.AddCleanup` registered in `state.New` — **not** on cache eviction. `api.Server.sweepIdleUserStores` must only drop the map entry. The caches hand out bare pointers and release `userMu` before the caller is done, and `userLastSeen` records acquisition rather than release, so "idle" never means "unheld": closing at eviction severed the handle under long-running callers and their next query failed `sql: database is closed`. `Close()` remains, is idempotent, and is for callers that genuinely own the last reference. Pinned by `TestEvictedStoreStaysUsableForItsHolder`.
- **Never read a store's file behind its back.** `rescanSubscriberIndex`/`rescanDeviceIndex` parsed `state.json` directly and so broke silently on the SQLite move — every device registration answering "unknown subscriber". They now go through `state.Store`.
- The other per-user stores (contacts, rules, groups, sendas, mailcache) and `users.json` are still JSON under `fsutil.WithFileLock`. They mutate on user action rather than per message, so they do not have the rewrite-per-event cost that moved `state.Store`.
- On first start after upgrade, `state.json`/`decisions.json` are imported into `state.db` in one transaction and renamed `.migrated` — never deleted. An unparseable file fails the open loudly rather than starting empty.

| `api/` | HTTP endpoints; session auth with role enforcement (`withAuth`/`withAdmin`, `AuthContext` via request context); user management; per-user config/IMAP/tuning/notification scoping. The surface is split by concern: `server.go` (struct, wiring, route table, lifecycle, sweepers), `server_auth_session.go` (login, MFA completion, sessions, auth middleware), `server_mail_send.go` (recipient parsing, PGP recipient plan, send/draft), `server_mail_attachments.go` (attachment list/download), `server_imap_config.go` (per-user IMAP credential storage + test), `server_settings.go` (config, notification/label preferences, tuning, decisions), `server_admin.go` (logs, setup state, restart/poll triggers, classifier test), `server_notifications.go` (push, native pairing, pairing tokens), `server_inbox.go` (mailbox read/act/search), `server_request_context.go` (proxy-header trust, client IP, base URL, TLS detection) |
| `users/` | Multi-user account store (`users.json`): roles, scrypt password hashing, soft-delete lifecycle, legacy `admin.env` migration |
| `adapters/imap/` | IMAP UID-based email fetching; credential decrypt; one `APIClient` per credential file (per user). An `APIClient` holds a live authenticated connection for its whole life, so both cache owners (`api`'s `userMailClient`/`invalidateUserMail`, `processor`'s `userMailClient`) must `Close()` the client they evict — see `api.closeMailClient` |
| `adapters/classifier/` | Ollama `/api/generate` HTTP calls; 3s inter-request pacing; retry backoff; tuning text passed per classify call |
| `processor/` | Timed polling loop (~90s default); polls every active user's mailbox per tick with bounded concurrency (4); per-user rate budgets; fault isolation (only all-users-failing flips global health) |
| `config/` | YAML config load/init; global `Config` plus per-user `UserSettings` (notification prefs) |
| `state/` | Per-user checkpoint, processed-set, decisions, subscriptions, devices; instantiated per user directory |
| `contacts/` | Per-user address book (`contacts.json`); monotonic `Rev`/tombstoned deletes double as the CardDAV ETag/sync-token and the mobile-sync cursor; instantiated per user directory |
| `mailcache/` | Per-user, per-mailbox mail metadata cache (`mailcache.json`); not permanent like `contacts/` — represents only the current top-N window, warmed by both `api/` (live-fetch fallback) and `processor/` (opportunistic, INBOX-only); instantiated per user directory in both processes |
| `fsutil/` | Shared atomic file write + UUIDv4 helpers. Directories are created `0700` to match the `0600` secrets written into them; an already-existing directory keeps its mode |
| `health/` | Health status; sticky `aiCreditsExhausted` flag |
| `logging/` | Structured logger; rotating file writer |
| `redaction/` | Regex-based PII masking applied to sender, subject, and body before prompting Ollama (shared engine, rebuilt on pattern change) |

### Classification Loop (daemon mode)

1. Poller fires on timer; lists active users from `users.json` and fans out over those with a stored IMAP config (bounded concurrency 4, per-user panic recovery)
2. Per user: fetch unread emails from their IMAP mailbox since their checkpoint
3. Scan each newly-seen message for KyPost self-impersonation and flag it with the `$Phishing` keyword if it does not authenticate to the account's own domain (`flagAppImpersonation`). Runs before every step below on purpose: a security verdict must not be rationed by the classifier rate limit, nor suppressed by a filter rule's `stop` action or a classifier outage
4. Apply global redaction patterns to sender, subject, body
5. POST to Ollama `/api/generate` with the user's tuning prompt + redacted email text (one shared, serialized classifier client across all users)
6. Fuzzy-match Ollama response against the global label allowlist
7. Apply matched label as an IMAP keyword in the user's mailbox
8. Send browser and native push notifications using the user's notification-mode gate (`none`, `all`, `keywords`) and the shared VAPID keys
9. Persist decision to the user's `decisions.json`
10. Advance the user's checkpoint to next UID

One failing mailbox never blocks other users; global health flips unhealthy only when every polled mailbox fails in the same tick.

### API Contract (consumed by frontend)

Auth values: `no` (public), `yes` (any signed-in user), `admin` (admin role required; non-admin gets 403). All `yes` routes that touch mailbox/notification/tuning data operate on the calling user's own resources.

| Route | Auth | Notes |
|-------|------|-------|
| `POST /api/auth/login` | no | Validates against `users.json`; inactive users rejected |
| `GET /api/auth/me` | no | Returns `userId`, `username`, `role`, `mustChangePassword`, `subscriberId` when authenticated. Read-only: `subscriberId` is empty until `GET /api/notifications/pairing` mints one, because this route is polled on every auth refresh and must not turn a read into a file-locked write |
| `POST /api/auth/logout` | yes | — |
| `POST /api/auth/password` | yes | Changes the calling user's own password |
| `GET\|POST /api/users` | admin | List / create users; `POST` rejects a username outside `users.ValidateUsername` with 400 |
| `PUT /api/users/{id}` | admin | Change role; demoting the last active admin is rejected |
| `POST /api/users/{id}/reset-password` | admin | Sets a temp password with forced change on next login |
| `POST /api/users/{id}/deactivate` | admin | Soft delete; last active admin protected; live sessions die on next request |
| `POST /api/users/{id}/reactivate` | admin | — |
| `GET /api/setup` | no | Returns admin credential bootstrap status |
| `GET /api/health` | no | 503 when unhealthy |
| `POST /api/health/repair` | admin | Clears sticky failure state (container restart) |
| `GET /api/status` | yes | Scan interval, rate limits, caller's checkpoint and emails processed in the last hour, server time |
| `GET\|PUT /api/config` | yes | Global config; PUT rejects Remote LLM (`classifier.*`) changes from non-admins with 403; PUT broadcasts to running poller |
| `GET /api/labels` | yes | Allowed label list + labels discovered in the caller's mailbox |
| `GET /api/decisions?limit=N` | yes | Caller's own audit trail |
| `GET /api/inbox?limit=N&mailbox=<name>` | yes | Live IMAP mailbox (read + unread) grouped by allowed keywords + Uncategorized |
| `GET\|POST\|PUT\|DELETE /api/inbox/folders` | yes | `GET` lists immediate child folders under an IMAP mailbox parent and marks which folders are deletable in the UI; omit `parent` to list top-level non-Archive mailbox links for the inbox nav. `POST` creates a single child folder under the requested parent (Inbox UI uses `parent=INBOX`). `PUT` renames a custom child folder by replacing only the leaf name. `DELETE` removes a custom child folder after moving its messages to the parent mailbox; built-in folders are rejected |
| `POST /api/inbox/actions` | yes | Bulk inbox actions: `delete`, `archive`, `spam`, `read`, `move` by `messageIds[]`, optional `mailbox`, and `targetMailbox` for `move`; actions execute in the selected mailbox, and `archive` moves to `Archive/<email sent year>` (fallback received year/current year) and creates folder if needed |
| `GET /api/logs?file=<name>.log&lines=<n>` | admin | Log tail |
| `GET /api/logs/list` | admin | Log file inventory |
| `POST /api/classifier/test` | yes | Classify a test email |
| `GET\|POST\|DELETE /api/imap/config` | yes | Caller's encrypted IMAP credentials plus optional SMTP host/port override used by `/api/mail/send` |
| `POST /api/imap/test` | yes | Live IMAP connectivity check (falls back to caller's stored config) |
| `POST /api/mail/draft` | yes | Saves compose content to the caller's IMAP Drafts folder |
| `POST /api/mail/send` | yes | Sends compose email via SMTP using the caller's credentials, logs send attempts/results, applies a send timeout, and appends successful sends to Sent mailbox (response can include warning when Sent append fails) |
| `GET\|PUT /api/tuning` | yes | Caller's own tuning prompt (`users/<id>/tuning.md`); GET falls back to the install default `TUNING.md`; PUT needs no classifier restart (tuning is passed per classify call) |
| `GET\|PUT /api/notifications/preferences` | yes | Caller's delivery mode + keywords (moved out of global config) |
| `GET /api/notifications/vapid-public-key` | yes | Shared VAPID public key for browser push subscription setup |
| `POST\|DELETE /api/notifications/subscriptions` | yes | Upsert or remove a browser push subscription in the caller's store |
| `POST /api/notifications/test` | yes | Sends a test push notification to the caller's subscriptions/devices and prunes stale endpoints |
| `GET /api/notifications/pairing` | yes | Returns native pairing info for the desktop QR code: caller's `subscriberId`, `serverBaseUrl`, `registerEndpoint`, `pairingToken`, `pairingExpiresAt`, `pairingTtlSeconds`, `configured` |
| `POST /api/notifications/native/register` | no | Native mobile registration. Accepts `subscriberId`, `pairingToken`, `deviceToken` + device metadata; validates pairing token, resolves `subscriberId` → owning user (in-memory index over `$STATE_DIR/users/*/state.json`, lazily rescanned), mints a per-device secret and stores only its hash, returns `deviceId` + `deviceSecret` (raw, one-time) |
| `GET\|DELETE /api/notifications/native/devices` | yes | Lists (secret hash redacted) or removes the caller's native devices by `deviceId` |
| `POST /api/notifications/native/unpair` | yes | Removes all of the caller's paired native devices |
| `POST /api/notifications/native/deregister` | device | Lets a paired device remove itself, authenticated with its own `X-Kypost-Device-Id`/`X-Kypost-Device-Secret` headers instead of a web session |
| `GET\|POST /api/contacts` | yes | List / create in the caller's address book |
| `GET /api/contacts/search` | yes | Compose-autocomplete search (`?q=&limit=`) over the caller's address book; `limit` defaults to 5, capped at 25 |
| `GET\|PUT\|DELETE /api/contacts/{id}` | yes | Read / update / tombstone-delete a single contact by `uid` |
| `GET\|POST\|DELETE /api/contacts/dav-password` | yes | Manage the caller's app-specific CardDAV Basic Auth password (separate from their login password); `POST` returns the raw secret exactly once |
| `GET\|POST /api/contacts/sync` | device | Mobile two-way sync (`?since=` / body `{baseCursor, changes[]}`), authenticated with the caller's own `X-Kypost-Device-Id`/`X-Kypost-Device-Secret` headers like `native/pull` — not a web session. Conflict policy is last-write-wins |
| `PROPFIND\|REPORT\|GET\|PUT\|DELETE /dav/{username}/contacts/...` | CardDAV Basic Auth | Real CardDAV surface (`emersion/go-webdav`) for native OS/CardDAV clients; authenticated with the app-specific password above, not session cookies or the login password. `/.well-known/carddav` is also mounted here for client auto-discovery |

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|--------|
| `CONFIG_DIR` | `/kypost/config` | Config and admin files |
| `STATE_DIR` | `/kypost/state` | State JSON files |
| `LOG_DIR` | `/kypost/logs` | Log file directory |
| `SECRET_DIR` | `/kypost/private` | Encrypted secrets (IMAP key) |
| `WEB_PORT` | `5866` | HTTP API listen port |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama service endpoint |
| `OLLAMA_MODEL` | `nemotron-3-nano:4b` | Classification model name |
| `TUNING_FILE` | `$CONFIG_DIR/TUNING.md` | Classification prompt template |
| `IMAP_CONFIG_FILE` | `$SECRET_DIR/imap-config.json` | Encrypted IMAP credentials |
| `IMAP_CONFIG_KEY_FILE` | `$SECRET_DIR/imap-config.key` | AES key for IMAP credentials |
| `SERVER_BASE_URL` | empty | Public backend URL embedded in mobile pairing QR (`srv`) and used to build register endpoint (`reg`) |
| `PAIRING_SECRET` | generated | HMAC secret for pickup links, PGP QR exchange and pairing tokens. Generated into `PAIRING_SECRET_FILE` when unset; set it only to share one across replicas |
| `PAIRING_SECRET_FILE` | `/kypost/private/pairing.key` | Where the generated pairing secret is persisted |
| `PUSH_RELAY_URL` | empty | Base URL of the central Android push relay (Cloudflare Worker) that delivers native push to FCM. When set with `PUSH_RELAY_KEY`, enables Android native push |
| `PUSH_RELAY_KEY` | empty | Per-server API key for Android push relay; sent as `Authorization: Bearer` to the relay |
| `APNS_RELAY_URL` | empty | Base URL of the central iOS push relay (Cloudflare Worker) that delivers native push via APNs. When set with `APNS_RELAY_KEY`, enables iOS native push |
| `APNS_RELAY_KEY` | empty | Per-server API key for iOS push relay; sent as `Authorization: Bearer` to the relay |

### Key Data Files

| File | Purpose |
|------|---------|
| `$CONFIG_DIR/config.yaml` | Global system config (admin-editable) |
| `$CONFIG_DIR/users.json` | User accounts, roles, scrypt password hashes (version-marked) |
| `$CONFIG_DIR/users/<userID>/imap-config.json` | User's encrypted IMAP credentials (master key encrypted) |
| `$CONFIG_DIR/users/<userID>/tuning.md` | User's classification prompt |
| `$CONFIG_DIR/users/<userID>/config.yaml` | User's notification delivery preferences |
| `$CONFIG_DIR/TUNING.md` | Default prompt template for users without their own tuning |
| `$CONFIG_DIR/notifications-vapid-private.pem` | Shared browser push private key |
| `$CONFIG_DIR/admin.env` | Legacy single-admin seed; imported once into `users.json`, then unused |
| `$SECRET_DIR/imap-config.key` | Master AES key for all stored IMAP credentials |
| `$SECRET_DIR/imap-config.json` | Legacy global IMAP credentials; migrated to the first admin, then unused |
| `$STATE_DIR/state.json` | Global state: sticky AI-credits flag |
| `$STATE_DIR/users/<userID>/state.json` | User's checkpoint + processed-set + push subscriptions + pairing `subscriberId` + native devices |
| `$STATE_DIR/users/<userID>/decisions.json` | User's decision audit log |
| `$STATE_DIR/users/<userID>/contacts.json` | User's address book (contacts, revisions, tombstones) |
| `$STATE_DIR/users/<userID>/mailcache.json` | User's mail metadata cache, per mailbox (not full message bodies except where opportunistically warmed) |
| `$CONFIG_DIR/users/<userID>/carddav-auth.json` | Scrypt hash of the user's app-specific CardDAV password (never the raw secret) |

### Log Files

| File | Written by | Content |
|------|------------|--------|
| `app.log` | Go backend Logger | Structured API/app events |
| `api.log` / `api.err.log` | supervisord | stdout/stderr of the `api` process |
| `daemon.log` / `daemon.err.log` | supervisord | stdout/stderr of the `daemon` process |
| `ollama.log` / `ollama.err.log` | supervisord | Ollama runtime output |
| `classifier.log` | classifier adapter | Ollama raw output |
| `classifier-server.log` | classifier adapter | Classify/warmup trace lines |
| `classifier.err.log` | classifier adapter | Classifier error lines |
| `bootstrap.log` / `bootstrap.err.log` | supervisord | Bootstrap script output |
| `supervisord.log` | supervisord | Process manager events |

## Work Guidance

- Build: `cd backend && go build -buildvcs=false ./...`
- Test: `cd backend && go test ./...` (CI runs `-race`; several stores are shared across the api and poller goroutines in `all` mode)
- Keep adapter packages free of direct state mutation; they communicate via interfaces and channels defined in `processor/`
- PII redaction must be applied before any text is sent to Ollama
- Do not add dependencies outside the go.mod without explicit approval
- **Cutting a release**: bump `serverVersion` in `internal/api/server_version.go` in the same commit as the tag, and publish the GitHub release with a dotted-numeric tag (`v0.2.0`, not `v0.2-alpha`). Every install polls this repo's releases hourly and emails its admin once per newly-seen release; a tag that is not dotted-numeric fails the comparison closed and no one is told, and a `serverVersion` left behind mails everyone about a release they are already running

## Verification

- `go build -buildvcs=false ./...` must succeed with zero errors
- `go vet ./...` must pass
- `gofmt -l .` must print nothing
- `go test -race ./...` must pass

## Child DOX Index

- `internal/adapters/` — external protocol clients (IMAP + Ollama); see [internal/adapters/AGENTS.md](internal/adapters/AGENTS.md)
- `internal/contacts/` — per-user address book storage; see [internal/contacts/AGENTS.md](internal/contacts/AGENTS.md)
- `internal/mailcache/` — per-user, per-mailbox mail metadata cache; see [internal/mailcache/AGENTS.md](internal/mailcache/AGENTS.md)
