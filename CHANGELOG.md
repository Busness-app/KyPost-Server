# Changelog

Versions are dotted-numeric (`MAJOR.MINOR.PATCH`) and published as GitHub
releases tagged `v<version>`. The tag, `serverVersion` in
`backend/internal/api/server_version.go`, and `frontend/package.json` must all
agree — `release-image.yml` refuses to publish a release where they do not.

Each release publishes an immutable `ghcr.io/<owner>/kypost-server:<version>`
image. `:stable` is moved to that image only after its build attestation has
been published *and* verified, and only when the release is the newest published
non-prerelease version.

## Unreleased — 0.2.0

### Fixed

- **Transient failures no longer discard mail-processing work.** A keyword
  write, rule action, or state write that failed after its own retries used to
  mark the message processed and advance the poll checkpoint past it: the
  message was classified correctly, the label was never applied, and no later
  tick would look at it again. These failures are now marked retryable, leave
  the message unprocessed, and hold the checkpoint below it so the next tick
  retries. Errors that are not explicitly marked retryable still retire the
  message, so an unrecognised repeating failure cannot stall a mailbox.

- **A failed rule action is no longer recorded as applied.** An IMAP error
  during "archive and stop" recorded an `applied` decision and permanently
  retired the message, with the failure visible only as extra text in the
  decision's detail. The message is now deferred and recorded as `failed`.

- **Deferrals are bounded.** Holding the checkpoint for a failure that never
  clears would re-fetch a growing batch every tick forever. Attempts are counted
  per message (`deferrals` table in `state.db`); after 120 consecutive deferrals
  — roughly three hours at the default 90-second interval — the message is
  retired with a decision recording that it was given up on.

### Added

- `GET /api/status` reports `deferredMessages` and `oldestDeferredUtc`:
  how much mail is waiting to be retried and how long the oldest has waited.
  `checkpointHeldSinceUtc` says the poller is holding position; these say how
  much is behind that hold.

- Full-tick regression tests (`backend/internal/processor/poller_tick_test.go`)
  drive `tickUser` end to end against a scripted mailbox and assert the
  processed set, the poll checkpoint, and the audit log together. The defects
  above were each invisible to the existing per-piece tests.

- A documented, restore-tested backup procedure (README, "Backup and Restore").

### Changed

- `release-image.yml` publishes the immutable version tag, attests it, verifies
  the attestation, and only then promotes that exact digest to `:stable`.
  Previously both tags were pushed by the same build step, so a failed
  attestation left `:stable` already moved onto an unattested image. The
  workflow also refuses to move `:stable` backward and serializes concurrent
  release runs.

### Documentation

- Corrected the persistent-state paths. The README told operators that mailbox
  state lived in `state.json` and `decisions.json`; it has lived in `state.db`
  since the SQLite migration.

## Upgrade and rollback

| From | To | Path | Rollback |
|---|---|---|---|
| 0.1.x | 0.2.0 | `./scripts/update-host.sh`, or `docker compose pull && docker compose up -d` | Automatic on failed health check; otherwise pin the previous digest |
| Locally built | any published release | `git pull --ff-only && docker compose up --build -d` | Rebuild at the previous commit |
| Any | older release | Set `KYPOST_VERSION=<older>` in `.env`, then `docker compose up -d` | — |

Notes:

- **Schema changes are additive and applied on open.** Every statement in
  `backend/internal/state/schema.go` is `IF NOT EXISTS`, so starting 0.2.0
  against a 0.1.x `state.db` adds the `deferrals` table and changes nothing
  else. An older server started against a newer `state.db` ignores tables it
  does not know about.

- **`scripts/update-host.sh` rolls back by itself.** It records the running
  image's digest before updating, verifies the new image's attestation, and
  restores the recorded digest if the post-update health check fails. An install
  running a locally built image has no published digest, so the updater refuses
  it rather than guessing a rollback target.

- **Rolling back the container does not roll back the data.** Restore a backup
  (README, "Backup and Restore") if a downgrade needs the old state too.

## 0.1.0

Initial development release.
