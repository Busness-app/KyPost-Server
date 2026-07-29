# Adapters

## Purpose

External protocol clients that isolate third-party integration details from the rest of the backend. Contains two sub-packages: `imap/` and `classifier/`.

## Ownership

All code under `backend/internal/adapters/`. Owned by the backend team. Changes to either adapter affect the classification loop and must be coordinated with `processor/`.

## Local Contracts

### `imap/` — IMAP Client

- Split by concern: `client.go` (connection lifecycle, credentials, message fetch/search), `client_folders.go` (mailbox list/create/delete/rename, keyword apply/remove), `client_attachments.go` (attachment enumeration and fetch), `client_append.go` (draft and Sent APPEND), `protocol_safety.go` (the keyword/mailbox validators below)
- Wraps `go-imap` to fetch unread emails by UID range from a configured mailbox
- Reads IMAP credentials from an encrypted file at rest (decrypted at connection time via `SECRET_DIR`)
- Does not cache or buffer messages; callers receive a slice of messages and are responsible for processing
- Returns errors on connection failure; callers (processor) handle retry logic
- **An `APIClient` holds one live, authenticated connection for its whole life, and the caller owns closing it.** `Close()` is nil-safe and idempotent; it is deliberately NOT on the `Client` interface, because six test fakes implement that interface and have nothing to close — the two cache owners (`api`'s `userMailClient`/`invalidateUserMail` and `processor`'s `userMailClient`) type-assert `io.Closer` instead. Both rebuild their client whenever the stored credentials change, so an eviction that skips the close leaks a server-side IMAP session per credential save, per process, until the far end times it out — and providers cap concurrent sessions per account (Gmail: 15), so the leak surfaces as mail simply ceasing to sync
- **`go-imap` does not escape enough to be handed untrusted strings.** Keywords are interpolated raw into `UID STORE <uid> +FLAGS (%s)`, and mailbox names go into a quoted argument escaped by `AddSlashes`, which replaces only `"`. Neither handles CR/LF or `\`. Every keyword and every mailbox name reaching this package must therefore pass `ValidateKeyword` / `ValidateMailboxName` (`protocol_safety.go`) first — these guards live on the adapter methods, not in the callers, because both the API handlers and the poller apply keywords. `selectMailboxLocked` is the single shared select path the read methods use so the mailbox guard cannot be forgotten by a new one. Held in place by `protocol_safety_test.go`
- Errors from those validators wrap `ErrUnsafeKeyword` / `ErrUnsafeMailbox` so callers can answer 400 rather than 502 (see `api.writeMailboxError`)

### `classifier/` — Classifier HTTP Client

- Sends classification requests to Ollama `/api/generate` via HTTP POST
- Admission control lives in `http_client.go`: `CLASSIFY_CONCURRENCY` (default 1) bounds in-flight generations via a channel semaphore, `CLASSIFY_PACE_MS` (default 0) inserts dead time between request starts. The pace was an unconditional 3 s, which capped the whole instance at 20 classifications/minute regardless of user count — it is not backpressure, since Ollama queues internally and the retry loop already backs off. Raise `CLASSIFY_CONCURRENCY` to match `OLLAMA_NUM_PARALLEL` or the extra capacity is unreachable
- Implements exponential backoff on transient HTTP errors
- `client.go` — high-level interface: accepts prompt + email text, returns raw model output string
- `http_client.go` — low-level transport: request construction, admission control, retry loop, `Stats()` for queue depth

### Shared Rules

- Adapters do not read or write application state (`STATE_DIR`)
- Adapters do not call other internal packages; they receive all config via constructor arguments
- All external I/O errors are returned to callers, not swallowed

## Work Guidance

- Keep each sub-package's external interface minimal: one constructor, one or two methods
- Admission and retry logic lives exclusively in `http_client.go`; do not duplicate in `client.go`
- The classify slot is held across the whole retry sequence but the WAIT for it is abandonable — keep the semaphore a channel selected against `ctx.Done()`, never a `sync.Mutex`, or a cancelled poll tick blocks behind another user's 15-second backoff
- IMAP credential decryption must use the same key derivation as `api/` encryption — coordinate any changes with `api/server_imap_config.go`

## Verification

- `go vet ./internal/adapters/...` must pass
- Integration tests requiring live IMAP or Ollama endpoints are run manually; unit tests mock the HTTP transport

## Child DOX Index

No child AGENTS.md files. `imap/` and `classifier/` are documented here.
