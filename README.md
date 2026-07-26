<img src="./ky50p.png" alt="KyPost" />

# KyPost

KyPost is a self-hosted IMAP web client with automatic keyword labeling powered by a local Ollama model.

It polls unread mail, classifies messages, applies IMAP keywords, and includes a full browser UI for reading, configuration, notifications, logs, and compose (send + draft).

## Features

- Docker-first single-container runtime managed by supervisord
- Multi-user with roles: admins manage users and system settings; each user connects their own IMAP mailbox
- IMAP inbox reader with folder management and drag/drop move actions
- Automatic keyword labeling for unread mail (each active user's mailbox is polled independently)
- Filter Rules: a GUI condition/action builder plus a raw Sieve script editor, with a run-now panel to apply rules on demand
- Built-in compose flow with SMTP send and IMAP draft save
- PGP mail encryption: generate or import a key, look up recipient keys on keys.openpgp.org, and check recipient key status before sending. Two key-protection modes — see [Where your PGP private key lives](#where-your-pgp-private-key-lives) before you rely on this
- Contacts address book with groups, dedupe, bulk delete, CSV/vCard import/export, and photo support
- Built-in CardDAV server (`/dav`, `/.well-known/carddav`) for syncing contacts to phones/desktop apps, plus an optional CardDAV client sync against an external address book
- Multi-factor authentication: TOTP authenticator apps, one-time recovery codes, and push-approval sign-in
- Optional CAPTCHA (Turnstile or Friendly Captcha) on login, layered on top of the built-in 3-strikes/15-minute lockout
- Browser push notifications (all mail or keyword-only), per user, plus native push pairing for mobile apps
- Config UI for IMAP, SMTP, model auth, tuning, logs, health, and decisions
- A dozen Theme presets

## Architecture

The container runs these processes:

- API server: `kypost-server --mode server`
- Polling daemon: `kypost-server --mode daemon`
- Ollama service: `ollama serve`
- One-shot startup pull: `ollama pull <configured model>`

Classification flow:

1. Fetch unread messages from IMAP (`INBOX` by default).
2. Redact sensitive patterns.
3. Build prompt from sender, subject, body, and tuning context.
4. Call Ollama `/api/generate`.
5. Match output against allowed labels.
6. Apply IMAP keyword(s).
7. Persist checkpoint and decision history.

## Requirements

- Docker
- Docker Compose

Optional for local development (outside Docker):

- Go 1.26+
- Node.js 20+
- npm

## Quick Start

1. Clone the repository.
2. Optional: copy environment defaults.

```bash
cp .env.example .env
```

3. Build and start.

```bash
docker compose up --build -d
```

4. Open the UI:

- http://localhost:5866

5. Sign in with the bootstrap credentials:

- Username: `admin`
- Password: printed once to the container logs on first start
  (`Generated first-run admin credentials …`). To set your own instead,
  pass `BOOTSTRAP_ADMIN_PASS` (and optionally `BOOTSTRAP_ADMIN_USER`) on the
  first run.

6. Change the password when prompted — until you do, the account can reach
   nothing but the password-change screen.
7. In Config, save IMAP and SMTP settings and run IMAP Test.
8. In Tuning, update labels/prompt and save.

## Where your PGP private key lives

This is the question that decides what PGP actually buys you here, so it gets
its own section rather than a bullet.

KyPost supports two protection modes for your PGP private key.

**Client-protected (end-to-end).** Your browser generates or imports the key,
wraps it under a key derived from your account password (PBKDF2-HMAC-SHA256,
600,000 iterations, AES-256-GCM), and uploads only the wrapped blob plus the
public half. The server stores that blob and cannot open it: it holds a scrypt
hash of your password, not the password, so it cannot derive the wrapping key.
Decryption and signing happen in your browser. Someone who takes the disk, a
backup, or this process's memory gets ciphertext.

The costs are real and you should know them up front:

- **An admin password reset destroys the key.** The wrapping key comes from
  your password. An admin can reset the password but cannot rewrap a key they
  cannot open, so the key becomes unrecoverable and you must import or
  generate a new one. Keep an exported backup of your private key somewhere
  safe.
- **You unlock once per browser session.** The unwrapped key is held in page
  memory only, never in localStorage or sessionStorage. A reload means
  re-entering your password.
- **Verified send-as addresses are not added to your key automatically.** That
  edit re-signs the key and needs the private half, so it happens in the
  browser rather than in the background poller.

**Server-protected (legacy).** The key is sealed with a master key stored on
the same volume, which means the server — and anyone who can read that
volume — can decrypt everything you have ever received. This is the mode
KyPost used before client protection existed, and the only reason it still
exists is so upgrading installs keep working. It is **not** end-to-end
encryption, and earlier versions of this README described it as if it were.
Migrate when you can: the Security page offers a one-time migration that hands
the key to your browser, rewraps it under your password, and deletes the
server-readable copy.

Either way, some things are outside PGP's reach and worth stating plainly:

- **Subject lines are not encrypted** by ordinary PGP/MIME, so they are
  visible to your mail provider regardless of mode. KyPost does protect the
  subject inside the encrypted part when it can, but the outer header still
  exists.
- **Mobile push notifications** are generic by default for exactly this
  reason — see the Notifications page.
- **Recipients without a key** can get a one-time pickup link instead, and
  that message is stored on this server (encrypted with the server's own key)
  until it is read or expires. It is not end-to-end encrypted; nothing sent to
  someone with no key can be. This is opt-in, not automatic: an encrypted send
  to a keyless recipient refuses with an error unless the request explicitly
  asks for the pickup-link fallback, so plaintext does not land on the server
  as a side effect of an otherwise-encrypted send.

## Session Behavior

- Login sessions expire after 24 hours of inactivity.
- Session expiry is sliding (each authenticated request extends TTL by 24h),
  but capped: a session dies 7 days after it was issued no matter how active
  it has been, so a stolen cookie cannot be kept alive indefinitely by the
  thief's own traffic.
- Expired sessions are swept hourly rather than only when their own cookie is
  presented again.
- Logout invalidates the server-side session and clears the cookie.
- Deactivating a user or changing their role takes effect on their very next request, not just at next login.

## Users and Roles

Accounts live in `/kypost/config/users.json` (roles: `admin`, `user`).

- Admins: manage users (create, change role, reset password, deactivate/reactivate) via the Manage Users page, view system logs, edit global settings (Application, Labels, Remote LLM), and trigger health repair.
- Users: connect their own IMAP/SMTP account, read and label their own mail, pair their own devices, set their own notification preferences, and tune their own prompt.
- Deactivation is a soft delete: the user can no longer sign in, but their data is retained on disk until removed manually.
- The last active admin cannot be deactivated or demoted.

Per-user data layout:

- `/kypost/config/users/<userID>/`: encrypted IMAP credentials, tuning prompt (`tuning.md`), notification preferences (`config.yaml`)
- `/kypost/state/users/<userID>/`: mailbox checkpoint + processed set (`state.json`), decision history (`decisions.json`), push subscriptions, paired devices

Upgrading from a single-admin install: on first start the legacy `admin.env` account is imported into `users.json`, and the legacy global mailbox state, IMAP credentials, tuning file, and notification preferences are copied into that admin's per-user directories. Legacy files are left in place but no longer read. There is no automated rollback; deleting `users.json` and the `users/` directories resets to a fresh multi-user state.

## Ports

- `5866`: web UI + backend API
- `11434`: Ollama API (not exposed by default in `docker-compose.yml`)

## Environment Variables

Common variables:

- `WEB_PORT` (default `5866`)
- `TZ` (default `America/New_York`)
- `SECRET_DIR` (default `/kypost/private`)
- `OLLAMA_BASE_URL` (default `http://127.0.0.1:11434`)
- `OLLAMA_MODEL` (Compose default `gemma4:e4b`)
- `TUNING_FILE` (default `/kypost/config/TUNING.md`)
- `OLLAMA_MODELS_HOST_DIR` (default `./share/ollama/models`)
- `IMAP_CONFIG_FILE` (default `/kypost/private/imap-config.json`)
- `IMAP_CONFIG_KEY_FILE` (default `/kypost/private/imap-config.key`)
- `TOTP_SECRET_KEY_FILE` (default `/kypost/private/totp-secret.key`)
- `SERVER_BASE_URL` (optional but recommended for mobile pairing; public URL embedded as `srv` in QR and used to build `reg`)
- `PAIRING_SECRET` (required for mobile pairing token signing/validation)
- `PUSH_RELAY_URL` (optional; base URL of the central push relay Worker that delivers Android native push to FCM)
- `PUSH_RELAY_KEY` (per-server API key issued by the relay operator; required together with `PUSH_RELAY_URL` to enable Android native push)
- `APNS_RELAY_URL` (optional; base URL of the central APNs relay Worker that delivers iOS native push)
- `APNS_RELAY_KEY` (per-server API key issued by the relay operator; required together with `APNS_RELAY_URL` to enable iOS native push)
- `CAPTCHA_PROVIDER` (optional; `turnstile` or `friendly` to require a CAPTCHA solution on login, on top of the built-in 3-strikes/15-minute account lockout)
- `CAPTCHA_SITE_KEY` / `CAPTCHA_SECRET_KEY` (required together with `CAPTCHA_PROVIDER`; site key is public, secret key verifies solutions server-side)

Notes:

- `Dockerfile` sets a fallback model of `nemotron-3-nano:4b`.
- `docker-compose.yml` overrides model default to `gemma4:e4b` unless you set `OLLAMA_MODEL`.
- The image sets `OLLAMA_MODELS=/kypost/ollama-models`.

Create model cache directory once before first run:

```bash
mkdir -p share/ollama/models
```

## Mobile App Pairing (Native)

Mobile pairing is backend-native and does not require Novu.

- Set `PAIRING_SECRET` on the server.
- Optionally set `SERVER_BASE_URL` so QR payloads always point to the correct public backend URL.
- Keep all pairing secrets server-side only.

Desktop pairing behavior:

- Notifications page renders a QR link with `sub`, `hash`, `srv`, `reg`, and `pt`.
- Set `SERVER_BASE_URL` in `.env` so `srv` and `reg` always point to the deployment address the mobile app should use (no manual server URL entry required).
- `pt` is a signed pairing token valid for 90 seconds.
- UI shows a 4px countdown bar under the QR that shrinks over 90 seconds, transitions green to red, and is red during the last 15 seconds.
- Mobile app scans QR and registers its push token through `reg` (or `srv + /api/notifications/native/register` fallback).

Native registration behavior:

- `POST /api/notifications/native/register` validates pairing token and stores native device metadata/token in backend state.
- `GET /api/notifications/native/devices` lists paired native devices.
- `DELETE /api/notifications/native/devices` removes a paired native device by `deviceId`.
- `POST /api/notifications/native/unpair` revokes all paired native devices for the current signed-in user.

Firebase credential guidance:

- The backend never holds Firebase credentials and never reads `google-services.json`.
- Native push is delivered through a central **push relay** (Cloudflare Worker) that holds the single Firebase service account the published mobile app is built against. This is what lets anyone run their own server with the same app without a Firebase account or a recompile.
- `google-services.json` belongs in the mobile project (Android app module, typically `app/google-services.json`) and should never be committed.

## Push Relays (Cloudflare Workers)

Native push delivery lives in Cloudflare Workers, run by the project maintainer:
- **Android/FCM**: [`worker/`](worker/) — Firebase Cloud Messaging relay
- **iOS/APNs**: [`worker-apns/`](worker-apns/) — Apple Push Notification service relay

Self-hosters ask the relay operator for per-server API keys:
- Android: set `PUSH_RELAY_URL` and `PUSH_RELAY_KEY` (Firebase relay)
- iOS: set `APNS_RELAY_URL` and `APNS_RELAY_KEY` (APNs relay)

Self-hosters need no Firebase or Apple Developer account, and the app is never recompiled.

Maintainers/relay operators: deploy both Workers and mint per-server keys. See [`worker/README.md`](worker/README.md) and [`worker-apns/README.md`](worker-apns/README.md) for setup, secrets, and key management.

## Persistence

Named volumes:

- `kypost_config` -> `/kypost/config`
- `kypost_private` -> `/kypost/private`
- `kypost_logs` -> `/kypost/logs`
- `kypost_state` -> `/kypost/state`

Host bind mount:

- `${OLLAMA_MODELS_HOST_DIR:-./share/ollama/models}` -> `/kypost/ollama-models`

Important files:

- `/kypost/config/config.yaml` (global system config)
- `/kypost/config/users.json` (user accounts and roles)
- `/kypost/config/users/<userID>/` (per-user IMAP credentials, tuning, notification preferences)
- `/kypost/config/TUNING.md` (default tuning for new users)
- `/kypost/config/notifications-vapid-private.pem` (shared web-push signing key)
- `/kypost/private/imap-config.key` (master encryption key for stored IMAP credentials)
- `/kypost/private/totp-secret.key` (master encryption key for stored TOTP secrets)
- `/kypost/state/state.json` (global state: AI-credits flag)
- `/kypost/state/users/<userID>/` (per-user mailbox state, decisions, devices, subscriptions)
- `/kypost/config/admin.env` (legacy single-admin seed; imported once, then unused)

## API Highlights

Auth:

- `POST /api/auth/login`
- `GET /api/auth/captcha-config`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `POST /api/auth/password`

Multi-factor authentication:

- `GET /api/mfa/status`
- `POST /api/mfa/totp/setup`
- `POST /api/mfa/totp/confirm`
- `POST /api/mfa/totp/disable`
- `POST /api/mfa/recovery-codes/regenerate`
- `PUT /api/mfa/push/enabled`
- `POST /api/auth/mfa/totp` / `POST /api/auth/mfa/recovery-code` (login-time verification)
- `POST /api/auth/mfa/push/poll` / `POST /api/auth/mfa/push/finish` / `POST /api/mfa/push/respond` (push-approval sign-in)

User management (admin only):

- `GET|POST /api/users`
- `PUT /api/users/{id}` (change role)
- `POST /api/users/{id}/reset-password`
- `POST /api/users/{id}/deactivate`
- `POST /api/users/{id}/reactivate`
- `POST /api/users/{id}/clear-mfa`

Runtime:

- `GET /api/status`
- `GET /api/health`
- `POST /api/health/repair` (admin only)
- `POST /api/admin/mail/poll-now` (admin only; trigger an immediate poll)
- `GET /api/setup` (whether initial admin setup has completed)
- `GET /pickup/{id}?t=<token>` (single-use mobile pickup link)

Config and data:

- `GET|PUT /api/config` (PUT of Remote LLM fields is admin only)
- `GET /api/labels`
- `GET /api/decisions` (caller's own decisions)
- `GET|PUT /api/tuning` (caller's own tuning prompt)

IMAP and inbox:

- `GET|POST|DELETE /api/imap/config`
- `POST /api/imap/test`
- `GET /api/inbox?limit=500&mailbox=<name>`
- `POST /api/inbox/actions`
- `GET|POST|PUT|DELETE /api/inbox/folders`
- `GET /api/mail/search`

Mail:

- `POST /api/mail/send` (optional `attachments: [{name, mimeType, dataBase64}]`, 25 MB total; optional `encrypt`/`sign`; `allowPickupFallback` — see [Where your PGP private key lives](#where-your-pgp-private-key-lives) — refuses with 409 by default if a recipient has no usable key)
- `POST /api/mail/draft` (same optional `attachments` shape)
- `GET /api/mail/attachments?mailbox=&messageId=` (list a message's attachment metadata)
- `GET /api/mail/attachment?mailbox=&messageId=&index=` (download one attachment)

Filter Rules (caller's own rules):

- `GET|POST /api/rules`
- `PUT|DELETE /api/rules/{id}`
- `POST /api/rules/reorder`
- `GET|PUT /api/rules/{id}/sieve` (raw Sieve script view/edit)
- `POST /api/rules/run` (run rules now, on demand)

PGP:

- `POST /api/pgp/identity/generate` / `POST /api/pgp/identity/import`
- `GET|DELETE /api/pgp/identity`
- `GET /api/pgp/keyserver/lookup` (query keys.openpgp.org)
- `POST /api/pgp/recipients/check` (key status for a set of recipients before sending)
- `GET /api/pgp/qr/token` / `GET /api/pgp/qr/key` (public key exchange via QR)

Contacts:

- `GET|POST /api/contacts`
- `GET|PUT|DELETE /api/contacts/{id}`
- `POST /api/contacts/dedupe`
- `GET /api/contacts/search`
- `POST /api/contacts/bulk-delete`
- `GET /api/contacts/export` / `POST /api/contacts/import`
- `GET|POST|DELETE /api/contacts/dav-password` (app-specific CardDAV password)
- `GET|POST|DELETE /api/contacts/carddav-client/config` and `POST /api/contacts/carddav-client/sync` (sync from an external CardDAV server)
- `POST|GET|DELETE /api/contacts/{id}/photo`
- `POST /api/contacts/{id}/self`
- `GET|POST /api/contacts/sync` (mobile two-way sync, authenticated via pairing token)

Groups:

- `GET|POST /api/groups`
- `PUT|DELETE /api/groups/{id}`

CardDAV server (address book sync for phones/desktop apps, authenticated with a per-user DAV password):

- `/.well-known/carddav`
- `/dav/...`

Notifications (all scoped to the signed-in user):

- `GET|PUT /api/notifications/preferences`
- `GET /api/notifications/vapid-public-key`
- `POST|DELETE /api/notifications/subscriptions`
- `POST /api/notifications/test`
- `GET /api/notifications/pairing`
- `POST /api/notifications/native/register`
- `GET|DELETE /api/notifications/native/devices`
- `POST /api/notifications/native/unpair`

Logs (admin only):

- `GET /api/logs?file=<name>.log&lines=<n>`
- `GET /api/logs/list`

## Build and Dev Checks

Backend:

```bash
cd backend
go build -buildvcs=false ./...
go test ./...
```

Frontend:

```bash
cd frontend
npm install
npm run build
```

## Operations

Useful runtime checks:

```bash
docker compose ps
docker compose logs -f kypost-server
docker exec -it kypost-server ps aux
docker exec -it kypost-server ls -la /kypost/config /kypost/state
docker volume ls | grep kypost
```

Persistence behavior:

- `docker compose up --build` keeps named volumes.
- `docker compose down -v` removes named volumes and stored app data.

## Troubleshooting

### Ollama or model issues

- Check logs with `docker compose logs -f kypost-server`.
- Confirm model pull completed for your configured `OLLAMA_MODEL`.
- Restart if needed: `docker compose restart`.

### IMAP connectivity issues

- Verify host, port, username, password, and mailbox in Config.
- Run IMAP Test in Config.
- Check `daemon.log` and `app.log` for auth/TLS/keyword failures.

### SMTP send issues

- Verify SMTP host and port in Config.
- Port 465 requires implicit TLS (supported).
- Use app passwords if your provider requires them.
- Check `app.log` for `mail send failed` details.

### Labels not being applied

- Confirm labels exist in allowlist/tuning.
- Confirm unread inbox has eligible messages.
- Check Decisions page and poller logs.

### PWA install on Firefox

- Firefox may not emit the same install prompt event as Chromium browsers.
- Service worker and manifest are still provided, but install UX can differ by browser.

## Project Structure

- `backend/`: Go API, poller, adapters, config, state, health
- `frontend/`: React + Vite UI
- `scripts/`: bootstrap and test helpers
- `Dockerfile`: single image build (backend, frontend, Ollama runtime)
- `docker-compose.yml`: local orchestration
- `supervisord.conf`: in-container process supervision