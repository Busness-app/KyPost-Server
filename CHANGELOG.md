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

### Added

- **Client-protected PGP identities can be backed up and restored.** Security
  now downloads a browser-encrypted recovery file and displays its separate
  secret once. Restoring decrypts locally, verifies the existing fingerprint,
  and uploads only a new account-password-wrapped envelope; the server never
  receives the recovery secret or plaintext private key.

- **Server-held PGP keys can be backed up too.** The recovery backup was wired
  only to client-protected identities, because it is built from the key held in
  the browser and a server-custody account never has one there. That left the
  one group who most needs a file without a way to make it: migrating to
  end-to-end puts the key beyond the server's reach, and from that moment an
  admin password reset destroys it and every message ever encrypted to it. The
  legacy path now offers the same download, through the existing one-time key
  export it already uses to migrate, producing the identical browser-encrypted
  file and one-time secret. A bare `.asc` download is deliberately still not
  offered — an unprotected private key in a downloads folder is what the format
  exists to avoid.

- **The inbox has an encryption column.** Every encrypted message now carries a
  padlock in its own column, in both the inbox and search results, whether or
  not it opened — previously the marking lived inside the Subject cell and
  appeared only when a message could not be read without a further step, so a
  message the server decrypted successfully looked exactly like one that
  arrived in the clear. A failed decrypt keeps the padlock and tints it rather
  than switching to a second symbol, so the column reads as "padlock or
  nothing" at a glance.

- **CI runs the scripts that install and update a deployment.** `scripts/` is
  the supported install and update path and nothing in CI touched it — the
  updater's own self-check existed and was never run. A `ci-scripts` job now
  runs it, the new model-installer self-check, shell syntax across `scripts/`,
  and `docker compose config`, and it is part of the release gate. The container
  smoke test additionally asserts the daemon is reporting its own health, so
  "healthy" cannot mean "the API answered".

### Security

- **A recipient whose PGP key changed no longer gets a plaintext pickup link.**
  The resolver already refused to switch keys when a contact's pinned
  fingerprint stopped matching what discovery served, but the send path threw
  that verdict away and treated the recipient as having no key at all — which is
  precisely the case the "Secure link if no key" fallback covers, by storing the
  message in the clear on this server for seven days. A broken pin is the one
  signal that the key published for an address may have been substituted, so it
  is now refused outright and the checkbox cannot override it. The compose error
  says so, and no longer offers the fallback.

- **Filter rules with an unusable regular expression are rejected when saved.**
  An invalid pattern used to be accepted and only fail while running, where
  "did not match" combined with *Not* inverted into "matched every message" — so
  one mistyped character could quietly sweep an inbox into Trash. A pattern that
  expands to an unreasonable size is refused for the same reason. Existing rules
  are unaffected unless they were already broken.

- **Address books have a size limit, and deleted contacts are now reclaimed.**
  Tombstones from deleted contacts were kept forever because nothing ever ran
  the collector, so a sync client that repeatedly added and removed entries grew
  the file without bound. Deletions past the retention window are now swept
  hourly, and an account is capped at 50,000 live contacts — far above any real
  address book, and a backstop rather than a limit anyone will meet.


- **The poll daemon refuses plaintext mailbox credentials.** The API's reader
  already rejected an unencrypted IMAP config and named the remedy, but the
  daemon's kept a copy of the fallback that had been removed from the shared
  helper — so a legacy config produced a daemon happily polling mail from a
  password sitting in cleartext on disk while the settings page reported the
  file unreadable. Re-save your IMAP/SMTP settings once if you see the new
  error; nothing else is needed.

- **A weak `PAIRING_SECRET` is refused instead of used.** The server generates
  a strong one by default, but an operator-supplied value was taken verbatim
  however short — and one guessable string signs pickup links, device pairing
  tokens and PGP QR key exchange alike. Values under 32 bytes are now
  rejected, with the reason and the remedy logged, and those three features stay
  disabled rather than being signed with something forgeable. Only deployments
  that set the variable by hand are affected.

- **The Security page re-authenticates before it draws.** It lists key
  fingerprints and paired devices and hands out a backup of the private key, and
  a session cookie only ever proved that somebody signed in on this browser
  once. Opening it now asks for the account password and, on an account with
  two-factor auth, a TOTP or recovery code — verified by the server
  (`POST /api/auth/step-up`), on the same throttles and the same per-account
  replay guard as signing in. The confirmation lasts five minutes, is dropped at
  logout, and does not survive a reload. It is a gate on the screen, not a new
  authorisation boundary: every operation behind it still re-verifies for
  itself, so nothing changes for a caller who skips the page.

- **Replacing or deleting a PGP identity requires the account password.** A
  session cookie was enough, and unlike everything else a session authorises,
  the damage outlives it: a replaced public key is published through WKD and
  Autocrypt, so every future correspondent encrypts to it, and a deleted
  identity cannot be recovered at all. Generate, import, client-key upload,
  rewrap and delete now take the same credential the legacy-key export already
  did. First-time setup is not gated — there is no key to redirect yet.

### Changed

- **Notification settings moved to Configuration → Notifications.** They were
  sharing a page with device pairing under a nav entry labelled "Pairing" that
  routed to `/notifications` and rendered a heading reading "Notifications and
  Pairing" — three names for two unrelated things. Delivery mode, IMAP keywords,
  content previews, the test notification and this-device unsubscribe are now a
  tab on Configuration, visible to every user because they are per-account
  preferences rather than system config. `/notifications` keeps only pairing for
  now. Configuration's active tab also moved into the URL (`?tab=`), so a link
  can open one and a reload no longer drops you back on the first tab; an
  unrecognised value, or an admin-only tab requested by a non-admin, falls back
  to that user's default rather than rendering a tab strip with no panel. The
  test notification and any push carrying no explicit url now land on the new
  tab.

- **Encrypted mail no longer goes to the classifier.** A PGP-encrypted message
  has no readable body — the poller never decrypts, and the payload is detected
  precisely *because* no MIME part rendered — so every one of them spent an
  Ollama call on an empty body, handed the model the sender and (for
  third-party PGP/MIME without protected headers) the real subject, and was
  then retired unlabeled into Uncategorized. Such a message is now tagged with
  the account's default label and skips the model. It is deliberately not given
  an `Encrypted` keyword: IMAP keywords are stored on the mail server in the
  clear, so that would hand whoever runs that server an index of which messages
  are worth attacking while looking like a security feature — and the published
  contract says keywords are a sorting hint, never a security boundary.

### Fixed

- **Encrypted Sent copies no longer lose their BCC recipients.** The copy was
  built by encrypting the delivered message, which omits `Bcc` on purpose so no
  recipient can see who else received it — and `SaveSent` ignores the draft's
  recipient fields entirely once it has raw bytes to append. So an encrypted
  send recorded no blind recipients while a plaintext one recorded them
  normally. The copy is now built from its own source that carries them.

- **The attachment listing looks inside real encrypted mail, not just test
  mail.** It required a message to have exactly one MIME part before treating it
  as an envelope, which no real encrypted message satisfies: the MIME parser
  files the ciphertext under both attachments and inlines, so it arrives listed
  twice. The check now asks whether every part is one an envelope could carry.

- **An ordinary message carrying an encrypted file is no longer mistaken for an
  encrypted message.** Detection accepted any bodyless message with an armored
  attachment, so `document.pgp` sent alongside a spreadsheet skipped
  classification, suppressed its own notification preview and showed a padlock.
  Every part must now be one a PGP/MIME envelope could contain.

- **Downloading an encrypted file returns that file.** The download endpoint
  decrypted anything whose bytes began with a PGP armor header, with no check
  that the message was an envelope, and then re-indexed into the decrypted
  contents — so clicking `archive.pgp` in a message that also had other
  attachments returned something from inside it, or a 404, for a file the
  listing said was there. Both endpoints now apply the same test.

- **An encrypted send never stores a readable Sent copy.** When the copy could
  not be encrypted, it was saved in plain text instead — and the argument for
  that ("this server holds the account's key anyway, so a readable copy reveals
  nothing new") missed where the copy goes: it is APPENDed to the account's IMAP
  host, which holds no key at all and now holds the body and real subject of a
  message the sender encrypted. Nothing is saved in that case now, the send
  reports `sentSaved:false`, and the reason comes back as a warning. The
  client-custody path has always refused to save cleartext here; the two paths
  agree again. The sender with no key of their own — previously the one case
  that produced plaintext with no warning anywhere — is included.

- **Whole-message encryption is decided by the message's root Content-Type.**
  Detection inferred it from the shape of a message's MIME parts, because the
  IMAP library does not parse root headers, and a bodyless message carrying one
  armored attachment is indistinguishable from a real PGP/MIME envelope that
  way. A sender could build one deliberately and be rewarded with a padlock and
  a message the classifier skips. The part shapes are now only a candidate
  filter; the real `multipart/encrypted; protocol="application/pgp-encrypted"`
  header is fetched for the few that pass it and decides.

- **The daemon's health reaches the health endpoint.** Under supervisord the
  poller runs as its own process with its own in-memory health, and
  `/api/health` served the API process's copy — so `classifierFailing` and
  `nativePushFailing` were permanently false, because nothing in the API
  process classifies mail or sends a push. A container whose poller had been
  dead for a week answered "healthy" and the health page rendered "Working".
  The daemon now publishes its subsystem health and a heartbeat to shared
  state; the API merges it and treats a heartbeat that stopped as unhealthy.

- **Shutdown actually cancels the work it waits for.** Poll ticks and per-message
  processing ran under `context.Background()` with 8- and 4-minute timeouts, so
  `Stop()` returned immediately, the tick loop exited, and the IMAP, SMTP and
  state writes underneath carried on — while shutdown blocked on exactly those.
  Against Docker's 10-second default grace period, routine updates reached
  SIGKILL mid-write. Both contexts now derive from the poller's own, no new
  message is admitted after cancellation, and Compose and supervisord are given
  grace periods that match.

- **One poll tick cannot exhaust the container's memory.** Every unread message
  past the checkpoint was fetched in a single call that buffers and MIME-decodes
  each one, with a 25 MiB per-message cap and no cap on the count — so the peak
  memory of a tick was a function of how much unread mail happened to be
  waiting, and the poller's rate limit could not help because it applies during
  processing, after the fetch. Fetching is now paged with a byte budget, and
  what it does not reach stays above the checkpoint for the next tick.

- **The model installer no longer gives up.** It exited after five failed pull
  attempts, which under `autorestart=false` was terminal — the program went
  EXITED rather than FATAL, so nothing restarted it and a container that met a
  few minutes of registry trouble at boot ran forever without the model it
  classifies with. It now retries on a capped interval until the model is
  installed, so a cause fixed later is picked up without anyone restarting
  anything.

- **An attachment-only encrypted message no longer tells you to unlock a key.**
  The inbox padlock read "unlock your PGP key to read" whenever an encrypted
  message had no text body — including one the server had already decrypted
  whose plaintext was attachments only, where there is nothing to unlock. The
  locked state now requires client-protected custody, which is the only kind
  that has a vault.

- **An encrypted message's sender and subject no longer reach FCM or APNs.**
  Native push travels to the relay Worker and on to Google or Apple in
  cleartext at every hop, and a third-party PGP/MIME message that does not use
  protected headers carries its real subject in the clear — so turning on
  Content Preview was shipping the subject of end-to-end encrypted mail through
  two third parties, invisibly. Both are now withheld for encrypted messages
  whatever that setting says. Web push is unchanged: RFC 8291 encrypts those
  payloads to the browser's own subscription keys, so Content Preview remains
  the user's call there.

- **The Sent folder now shows that an encrypted message was encrypted.** A
  server-custody encrypted send delivered ciphertext but appended its Sent copy
  as cleartext, rebuilt from the request. The web reader derives its "PGP:
  encrypted" badge by sniffing the stored message, so an encrypted send and a
  plain one rendered identically in Sent — with no indicator on either — and the
  plaintext and real subject of every encrypted message sat on the IMAP store
  regardless. The copy is now encrypted to the sender's own key, matching what
  the client-custody path has done since run-4. A sender who has no key of their
  own (encrypting to recipients never required one) keeps the previous plaintext
  copy: there is nothing to encrypt it to.

- **Attachments on encrypted mail are readable again.** The attachment endpoints
  served a message's outer MIME parts, which for PGP/MIME is only the armored
  payload — so an encrypted message with a file attached listed `encrypted.asc`,
  and downloading it produced armor instead of the file. Both endpoints now look
  inside the ciphertext when the server holds a key that opens it. Unencrypted
  mail is unaffected and still costs a single fetch; a client-protected account
  still receives the untouched ciphertext, since the server cannot read it.

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

- **A rule stops at its first failed action.** Remaining actions used to run
  anyway. Since the retry the failure triggers is an unread-inbox search, an
  action that archived or read the message after an earlier one failed put it
  out of reach of the retry it had just been promised: the remaining work was
  lost silently while the audit row recorded a failure. Rule actions also stop
  at a cancelled context instead of running the rest of the list against a
  connection that is going away.

- **Rule actions are validated and bounded at every write.** Creating or
  updating a rule — by form, by API, or by Sieve script — now checks the action
  list, which nothing did before: at most 20 actions, only action types the
  engine can execute, bounded rule names and values, and at most one action that
  changes a message's visibility (read, move, archive, spam, delete), which must
  come last. An unknown action type used to be stored happily and then fail on
  every matching message for three hours before the message was retired
  unlabelled. Rules already saved are checked the same way when loaded; one that
  cannot be executed is skipped with a log line instead of failing per message.

- **A deferral counter that cannot be written no longer discards the message.**
  If the state database failed while recording a retry attempt, the poller
  retired the message and advanced the checkpoint past it — turning a momentary
  database contention into lost work. The message is now kept for retry and the
  poll tick is reported as failed so the database problem is visible.

- **A prerelease can no longer take over `:stable`.** GitHub's `published`
  release event fires for prereleases too, and while the promotion step
  excluded prereleases from the versions it compared against, it added the
  release being published back unconditionally — so the one release whose
  prerelease flag was never checked was the current one. Publishing a
  prerelease tagged with a plain `v<major>.<minor>.<patch>` (the flag is a
  checkbox, independent of the tag) compared as newest and moved `:stable` onto
  it, upgrading every install that follows that tag to code nobody released.
  The immutable version tag is still published, so testers can pull it by name.

- **A malformed release tag now fails the release instead of skipping it.** The
  version check was a job-level `if:`, which does not refuse anything — it
  skips the job, and a skipped job is green. A release tagged `1.0.0` or
  `release-1.0.0` produced no image and no failure. Tag validation now runs as
  the first step, before the checkout that consumes the tag.

- **Contact import accepts the upload the browser actually sends.** The
  frontend posts `multipart/form-data`; the handler read the raw request body
  into the vCard decoder. That did not fail loudly — the decoder reported
  "no BEGIN field found" for the MIME boundary and part headers and then
  decoded every card correctly — so every successful import in the UI reported
  "Imported N contacts. (2 errors)". Multipart uploads are now parsed properly,
  raw vCard bodies are still accepted, and an over-limit upload is refused with
  413 rather than silently truncated mid-card and reported as a partial
  success.

- **The relay no longer logs Google's OAuth response body.** A failed
  service-account token exchange interpolated the whole upstream body into an
  error string that the worker logged as `send.error`. It now reports the
  status and the RFC 6749 error enum — which is the actual diagnostic, since
  `invalid_client` means `FCM_CLIENT_EMAIL` is wrong and `invalid_grant` means
  `FCM_PRIVATE_KEY` is wrong or the clock has drifted — validated against a
  narrow pattern so the field cannot carry free text. The success-path
  `JSON.parse` is guarded for the same reason: V8 quotes the first ten
  characters of its input back in the `SyntaxError` message, and on a 200 that
  input is the access token. Pinned by
  `worker/src/fcm-oauth-redaction.test.mts`.

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

- Recorded the one exception to the relay's "no upstream response bodies in
  logs" rule. `send.fcm_failed` and `send.apns_failed` carry the provider's
  reason clipped to 200 characters, deliberately: since `isStaleResponse`
  stopped retiring devices on the 400s that name a token, that log line is the
  only way an operator learns `FCM_PROJECT_ID` or `APNS_TOPIC` is wrong rather
  than the phones being dead. The rule and the code had disagreed silently;
  `push-relay-shared/AGENTS.md` now states the exception and its limits.

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
