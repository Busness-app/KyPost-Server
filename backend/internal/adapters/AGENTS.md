# Adapters

## Purpose

External protocol clients that isolate third-party integration details from the rest of the backend. Contains two sub-packages: `imap/` and `classifier/`.

## Ownership

All code under `backend/internal/adapters/`. Owned by the backend team. Changes to either adapter affect the classification loop and must be coordinated with `processor/`.

## Local Contracts

### `imap/` — IMAP Client

- Wraps `go-imap` to fetch unread emails by UID range from a configured mailbox
- Reads IMAP credentials from an encrypted file at rest (decrypted at connection time via `SECRET_DIR`)
- Does not cache or buffer messages; callers receive a slice of messages and are responsible for processing
- Returns errors on connection failure; callers (processor) handle retry logic
- **`go-imap` does not escape enough to be handed untrusted strings.** Keywords are interpolated raw into `UID STORE <uid> +FLAGS (%s)`, and mailbox names go into a quoted argument escaped by `AddSlashes`, which replaces only `"`. Neither handles CR/LF or `\`. Every keyword and every mailbox name reaching this package must therefore pass `ValidateKeyword` / `ValidateMailboxName` (`protocol_safety.go`) first — these guards live on the adapter methods, not in the callers, because both the API handlers and the poller apply keywords. `selectMailboxLocked` is the single shared select path the read methods use so the mailbox guard cannot be forgotten by a new one. Held in place by `protocol_safety_test.go`
- Errors from those validators wrap `ErrUnsafeKeyword` / `ErrUnsafeMailbox` so callers can answer 400 rather than 502 (see `api.writeMailboxError`)

### `classifier/` — Classifier HTTP Client

- Sends classification requests to Ollama `/api/generate` via HTTP POST
- Enforces a minimum 3-second gap between consecutive requests (`http_client.go` pacing)
- Implements exponential backoff on transient HTTP errors
- `client.go` — high-level interface: accepts prompt + email text, returns raw model output string
- `http_client.go` — low-level transport: handles request construction, pacing timer, retry loop

### Shared Rules

- Adapters do not read or write application state (`STATE_DIR`)
- Adapters do not call other internal packages; they receive all config via constructor arguments
- All external I/O errors are returned to callers, not swallowed

## Work Guidance

- Keep each sub-package's external interface minimal: one constructor, one or two methods
- Pacing and retry logic lives exclusively in `http_client.go`; do not duplicate in `client.go`
- IMAP credential decryption must use the same key derivation as `api/` encryption — coordinate any changes with `api/server.go`

## Verification

- `go vet ./internal/adapters/...` must pass
- Integration tests requiring live IMAP or Ollama endpoints are run manually; unit tests mock the HTTP transport

## Child DOX Index

No child AGENTS.md files. `imap/` and `classifier/` are documented here.
