<img src="./ky50p.png" alt="KyPost" />

# KyPost

KyPost is a self-hosted IMAP web client. It applies keyword labels to your mail automatically with a local Ollama model.

KyPost polls unread mail, classifies each message, and applies IMAP keywords. It also gives you a web UI to read mail, change the configuration, manage notifications, view logs, and compose mail. Compose supports send and draft save.

## Features

- Single-container Docker runtime. supervisord manages the processes.
- Multi-user with two roles. Admins manage users and system settings. Each user connects their own IMAP mailbox.
- IMAP inbox reader with folder management and drag-and-drop move actions
- Automatic keyword labels for unread mail. KyPost polls each active user's mailbox separately.
- Filter Rules: a GUI condition and action builder plus a raw Sieve script editor. A run-now panel applies the rules on demand.
- Compose flow with SMTP send and IMAP draft save
- PGP mail encryption. Generate or import a key, search for recipient keys on keys.openpgp.org, and check recipient key status before you send. KyPost has two key-protection modes. Read [Where your PGP private key lives](#where-your-pgp-private-key-lives) before you rely on this.
- Contacts address book with groups, dedupe, bulk delete, CSV and vCard import and export, and photo support
- CardDAV server (`/dav`, `/.well-known/carddav`) to sync contacts to phones and desktop apps. An optional CardDAV client syncs against an external address book.
- Multi-factor authentication: TOTP authenticator apps, one-time recovery codes, and push-approval sign-in
- Optional CAPTCHA on login: self-hosted proof-of-work, Turnstile, or Friendly Captcha. It works together with the built-in lockout of 3 strikes and 15 minutes.
- Browser push notifications for each user, for all mail or for keyword matches only. KyPost also supports native push pairing for mobile apps.
- Config page for IMAP, SMTP, model authentication, tuning, logs, health, and decisions
- A dozen theme presets

## Architecture

The container runs these processes:

- API server: `kypost-server --mode server`
- Polling daemon: `kypost-server --mode daemon`
- Ollama service: `ollama serve`
- One-shot startup pull: `ollama pull <configured model>`

Classification flow:

1. Fetch unread messages from IMAP (`INBOX` by default).
2. Redact sensitive patterns.
3. Build the prompt from sender, subject, body, and tuning context.
4. Call Ollama `/api/generate`.
5. Match the output against the allowed labels.
6. Apply the IMAP keywords.
7. Save the checkpoint and the decision history.

## Requirements

- Docker
- Docker Compose

Optional for local development (outside Docker):

- Go 1.26+
- Node.js 20+
- npm

## Quick Start

1. Clone the repository.
2. Optional: copy the environment defaults.

   ```bash
   cp .env.example .env
   ```

3. Build and start the container.

   ```bash
   docker compose up --build -d
   ```

4. Open the web UI at http://localhost:5866.

   > **Before exposing this to a network, put TLS in front of it.** KyPost
   > serves plain HTTP and does not terminate TLS itself. The session cookie is
   > marked `Secure` only when the request demonstrably arrived over TLS, so on
   > a bare `http://` deployment the cookie is sent in the clear on every
   > request. Run a TLS-terminating reverse proxy and set
   > `TRUST_PROXY_HEADERS=true` so the server sees the real scheme, host and
   > client IP — without it the cookie stays non-`Secure` and the login and
   > CardDAV lockouts key off the proxy's IP instead of the caller's. `http://`
   > on localhost, for one machine, is fine.
5. Sign in with the bootstrap credentials. The username is `admin`. KyPost
   prints the password once to the container logs on the first start. Look for
   `Generated first-run admin credentials …`. To set your own password instead,
   pass `BOOTSTRAP_ADMIN_PASS` on the first run. You can also pass
   `BOOTSTRAP_ADMIN_USER`.
6. Change the password when KyPost prompts you. Until you change it, the
   account can reach only the password-change screen.
7. In Config, save the IMAP and SMTP settings. Then run IMAP Test.
8. In Tuning, change the labels and the prompt. Then save.

## Where your PGP private key lives

The location of your private key decides what PGP protects here. This question
gets its own section for that reason, not a bullet.

KyPost has two protection modes for your PGP private key.

**Client-protected (end-to-end).** Your browser generates or imports the key.
The browser then wraps the key under a key derived from your account password.
It uses PBKDF2-HMAC-SHA256 with 600,000 iterations and AES-256-GCM. The browser
uploads only the wrapped blob and the public half.

The server stores that blob and cannot open it. The server holds a scrypt hash
of your password, not the password, so it cannot derive the wrapping key. Your
browser decrypts and signs. A person who takes the disk, a backup, or the memory
of this process gets ciphertext.

The costs are real. Know them before you choose this mode:

- **An admin password reset destroys the key.** The wrapping key comes from
  your password. An admin can reset the password but cannot rewrap a key they
  cannot open. The key becomes unrecoverable and you must import or generate a
  new one. Keep an exported backup of your private key in a safe place.
- **You unlock the key once for each browser session.** The browser holds the
  unwrapped key in page memory only, never in localStorage or sessionStorage.
  After a reload you must enter your password again.
- **KyPost does not add verified send-as addresses to your key
  automatically.** That edit re-signs the key and needs the private half. The
  browser makes the edit, not the background poller.

**Server-protected (legacy).** The server seals the key with a master key on the
same volume. The server, and any person who can read that volume, can decrypt
everything you have ever received. KyPost used this mode before client
protection existed. It remains only so that upgraded installations keep working.

This mode is **not** end-to-end encryption, and earlier versions of this README
described it as if it were. Migrate when you can. The Security page offers a
one-time migration. The migration hands the key to your browser, rewraps it
under your password, and deletes the server-readable copy.

Some facts apply to both modes, and they are worth a plain statement:

- **Ordinary PGP/MIME does not encrypt subject lines.** Your mail provider sees
  them in both modes. KyPost protects the subject inside the encrypted part when
  it can, but the outer header remains.
- **Mobile push notifications are generic by default** for this reason. See the
  Notifications page.
- **A recipient without a key can get a one-time pickup link.** KyPost stores
  that message on this server and encrypts it with the server's own key. The
  message stays until the recipient reads it or it expires. It is not end-to-end
  encrypted. Nothing sent to a person with no key can be. This fallback is
  opt-in, not automatic. An encrypted send to a keyless recipient fails with an
  error unless the request asks for the pickup-link fallback. Plaintext
  therefore never reaches the server as a side effect of an encrypted send.

## Session Behavior

- Login sessions expire after 24 hours without activity.
- Session expiry slides forward. Each authenticated request extends the TTL by
  24 hours.
- A session also has a hard cap. It dies 7 days after KyPost issued it, whatever
  the activity. A thief cannot keep a stolen cookie alive with their own traffic.
- KyPost sweeps expired sessions every hour. It does not wait for the cookie to
  arrive again.
- Logout invalidates the server-side session and clears the cookie.
- A deactivation or a role change takes effect on the user's next request, not
  at the next login.

## Users and Roles

Accounts live in `/kypost/config/users.json`. The roles are `admin` and `user`.

- Admins manage users from the Manage Users page. They create users, change
  roles, reset passwords, and deactivate or reactivate accounts. Admins also
  view system logs, edit global settings (Application, Labels, Remote LLM), and
  start a health repair.
- Users connect their own IMAP and SMTP account. They read and label their own
  mail, pair their own devices, set their own notification preferences, and tune
  their own prompt.
- Deactivation is a soft delete. The user can no longer sign in. KyPost keeps
  their data on disk until you remove it manually.
- KyPost does not let you deactivate or demote the last active admin.

Per-user data layout:

- `/kypost/config/users/<userID>/`: encrypted IMAP credentials, tuning prompt (`tuning.md`), notification preferences (`config.yaml`)
- `/kypost/state/users/<userID>/`: mailbox checkpoint and processed set (`state.json`), decision history (`decisions.json`), push subscriptions, paired devices

Upgrade from a single-admin installation: on the first start, KyPost imports the
legacy `admin.env` account into `users.json`. KyPost also copies the legacy
global mailbox state, IMAP credentials, tuning file, and notification
preferences into that admin's per-user directories. KyPost leaves the legacy
files in place but no longer reads them. There is no automatic rollback. To
reset to a fresh multi-user state, delete `users.json` and the `users/`
directories.

## Ports

- `5866`: web UI and backend API
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
- `SERVER_BASE_URL` (optional. Recommended for mobile pairing. KyPost embeds this public URL as `srv` in the QR code and uses it to build `reg`.)
- `PAIRING_SECRET` (optional. HMAC secret for pickup links, PGP QR key exchange and mobile pairing tokens. Generated automatically on first start and persisted at `PAIRING_SECRET_FILE` — set it only if several replicas must share one secret, and use `openssl rand -base64 32` if you do.)
- `PAIRING_SECRET_FILE` (default `/kypost/private/pairing.key`)
- `PUSH_RELAY_URL` (optional. Base URL of the central push relay Worker that delivers Android native push to FCM.)
- `PUSH_RELAY_KEY` (per-server API key from the relay operator. Set it together with `PUSH_RELAY_URL` to enable Android native push.)
- `APNS_RELAY_URL` (optional. Base URL of the central APNs relay Worker that delivers iOS native push.)
- `APNS_RELAY_KEY` (per-server API key from the relay operator. Set it together with `APNS_RELAY_URL` to enable iOS native push.)
- `CAPTCHA_PROVIDER` (optional. Set `pow`, `turnstile`, or `friendly` to require a CAPTCHA solution on login. It works together with the built-in lockout of 3 strikes and 15 minutes.)
  - `pow` is self-hosted proof-of-work: the only provider that makes no third-party network call and adds no third-party origin to the CSP. It requires no account with anyone and no keys to obtain — the signing key is generated on first use at `POW_SECRET_FILE`. It raises the cost of scripted login spraying by roughly one to two orders of magnitude; it does **not** replace the three-strikes lockout, which remains the real brute-force defence. Multi-replica deployments must set `POW_SECRET` so every replica agrees on one signing key.
  - `turnstile` and `friendly` verify a token against a third-party siteverify endpoint and need a site key + secret key.
- `CAPTCHA_SITE_KEY` and `CAPTCHA_SECRET_KEY` (required together with `CAPTCHA_PROVIDER=turnstile` or `friendly`; not used by `pow`. The site key is public. The server verifies solutions with the secret key.)
- `POW_MAX_NUMBER`, `POW_SECRET_FILE`, `POW_SECRET` (optional, `CAPTCHA_PROVIDER=pow` only — see `.env.example` for tuning notes)

Notes:

- `Dockerfile` sets a fallback model of `nemotron-3-nano:4b`.
- `docker-compose.yml` changes the model default to `gemma4:e4b` unless you set `OLLAMA_MODEL`.
- The image sets `OLLAMA_MODELS=/kypost/ollama-models`.

Create the model cache directory once before the first run:

```bash
mkdir -p share/ollama/models
```

## Mobile App Pairing (Native)

The backend handles mobile pairing directly. It does not require Novu.

- Nothing to configure: the pairing secret is generated on first start and kept at `/kypost/private/pairing.key`. Set `PAIRING_SECRET` only if you run multiple replicas that must share one.
- Optional: set `SERVER_BASE_URL` so that QR code payloads always point to the correct public backend URL. Use an `https://` URL: pairing tokens, pickup links and QR key-exchange URLs are all built from it, and each carries a bearer credential in the query string. See the TLS note in Quick Start.
- Keep all pairing secrets on the server only.

Desktop pairing behavior:

- The Notifications page renders a QR code link with `sub`, `hash`, `srv`, `reg`, and `pt`.
- Set `SERVER_BASE_URL` in `.env`. Then `srv` and `reg` always point to the deployment address that the mobile app must use. Nobody enters a server URL by hand.
- `pt` is a signed pairing token. It is valid for 90 seconds.
- The UI shows a 4px countdown bar under the QR code. The bar shrinks over 90 seconds and changes from green to red. It is red for the last 15 seconds.
- The mobile app scans the QR code and registers its push token through `reg`. If `reg` is absent, the app uses `srv` plus `/api/notifications/native/register` instead.

Native registration behavior:

- `POST /api/notifications/native/register` validates the pairing token. It stores the native device metadata and token in the backend state.
- `GET /api/notifications/native/devices` lists the paired native devices.
- `DELETE /api/notifications/native/devices` removes one paired native device by `deviceId`.
- `POST /api/notifications/native/unpair` revokes all paired native devices for the signed-in user.

Firebase credential guidance:

- The backend never holds Firebase credentials. It never reads `google-services.json`.
- A central **push relay** (a Cloudflare Worker) delivers native push. The relay holds the one Firebase service account that the published mobile app is built against. This lets anyone run their own server with the same app, with no Firebase account and no recompile.
- `google-services.json` belongs in the mobile project, usually at `app/google-services.json` in the Android app module. Never commit it.

## Push Relays (Cloudflare Workers)

Cloudflare Workers deliver native push. The project maintainer runs them.
- **Android/FCM**: [`worker/`](worker/) — Firebase Cloud Messaging relay
- **iOS/APNs**: [`worker-apns/`](worker-apns/) — Apple Push Notification service relay

Self-hosters ask the relay operator for per-server API keys.
- Android: set `PUSH_RELAY_URL` and `PUSH_RELAY_KEY` (Firebase relay)
- iOS: set `APNS_RELAY_URL` and `APNS_RELAY_KEY` (APNs relay)

Self-hosters need no Firebase account and no Apple Developer account. You never recompile the app.

Maintainers and relay operators deploy both Workers and mint per-server keys. See [`worker/README.md`](worker/README.md) and [`worker-apns/README.md`](worker-apns/README.md) for setup, secrets, and key management.

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
- `/kypost/config/admin.env` (legacy single-admin seed. KyPost imports it once, then stops reading it.)

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
- `POST /api/auth/mfa/totp` and `POST /api/auth/mfa/recovery-code` (login-time verification)
- `POST /api/auth/mfa/push/poll`, `POST /api/auth/mfa/push/finish`, and `POST /api/mfa/push/respond` (push-approval sign-in)

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
- `POST /api/admin/mail/poll-now` (admin only. Starts an immediate poll.)
- `GET /api/setup` (reports whether the initial admin setup completed)
- `GET /pickup/{id}?t=<token>` (single-use mobile pickup link)

Config and data:

- `GET|PUT /api/config` (a PUT of Remote LLM fields is admin only)
- `GET /api/labels`
- `GET /api/decisions` (the caller's own decisions)
- `GET|PUT /api/tuning` (the caller's own tuning prompt)

IMAP and inbox:

- `GET|POST|DELETE /api/imap/config`
- `POST /api/imap/test`
- `GET /api/inbox?limit=500&mailbox=<name>`
- `POST /api/inbox/actions`
- `GET|POST|PUT|DELETE /api/inbox/folders`
- `GET /api/mail/search`

Mail:

- `POST /api/mail/send`. Optional `attachments: [{name, mimeType, dataBase64}]`, 25 MB in total. Optional `encrypt` and `sign`. If `encrypt` is true and a recipient has no usable key, the call fails with 409. To allow the pickup-link fallback instead, set `allowPickupFallback`. See [Where your PGP private key lives](#where-your-pgp-private-key-lives).
- `POST /api/mail/draft` (the same optional `attachments` shape)
- `GET /api/mail/attachments?mailbox=&messageId=` (lists the attachment metadata of a message)
- `GET /api/mail/attachment?mailbox=&messageId=&index=` (downloads one attachment)

Filter Rules (the caller's own rules):

- `GET|POST /api/rules`
- `PUT|DELETE /api/rules/{id}`
- `POST /api/rules/reorder`
- `GET|PUT /api/rules/{id}/sieve` (view and edit the raw Sieve script)
- `POST /api/rules/run` (runs the rules on demand)

PGP:

- `POST /api/pgp/identity/generate` and `POST /api/pgp/identity/import`
- `GET|DELETE /api/pgp/identity`
- `GET /api/pgp/keyserver/lookup` (queries keys.openpgp.org)
- `POST /api/pgp/recipients/check` (key status for a set of recipients before you send)
- `GET /api/pgp/qr/token` and `GET /api/pgp/qr/key` (public key exchange through a QR code)

Contacts:

- `GET|POST /api/contacts`
- `GET|PUT|DELETE /api/contacts/{id}`
- `POST /api/contacts/dedupe`
- `GET /api/contacts/search`
- `POST /api/contacts/bulk-delete`
- `GET /api/contacts/export` and `POST /api/contacts/import`
- `GET|POST|DELETE /api/contacts/dav-password` (app-specific CardDAV password)
- `GET|POST|DELETE /api/contacts/carddav-client/config` and `POST /api/contacts/carddav-client/sync` (sync from an external CardDAV server)
- `POST|GET|DELETE /api/contacts/{id}/photo`
- `POST /api/contacts/{id}/self`
- `GET|POST /api/contacts/sync` (mobile two-way sync. A pairing token authenticates the call.)

Groups:

- `GET|POST /api/groups`
- `PUT|DELETE /api/groups/{id}`

CardDAV server (address book sync for phones and desktop apps. A per-user DAV password authenticates the call.):

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

Runtime checks:

```bash
docker compose ps
docker compose logs -f kypost-server
docker exec -it kypost-server ps aux
docker exec -it kypost-server ls -la /kypost/config /kypost/state
docker volume ls | grep kypost
```

Persistence behavior:

- `docker compose up --build` keeps the named volumes.
- `docker compose down -v` removes the named volumes and the stored app data.

## Troubleshooting

### Ollama or model issues

- Check the logs with `docker compose logs -f kypost-server`.
- Confirm that the model pull completed for your `OLLAMA_MODEL`.
- If necessary, restart with `docker compose restart`.

### IMAP connection issues

- Verify the host, port, username, password, and mailbox in Config.
- Run IMAP Test in Config.
- Check `daemon.log` and `app.log` for authentication, TLS, and keyword failures.

### SMTP send issues

- Verify the SMTP host and port in Config.
- Port 465 requires implicit TLS. KyPost supports it.
- If your provider requires app passwords, use them.
- Check `app.log` for `mail send failed` details.

### KyPost does not apply labels

- Confirm that the labels exist in the allowlist and the tuning file.
- Confirm that the unread inbox holds eligible messages.
- Check the Decisions page and the poller logs.

### PWA installation on Firefox

- Firefox can omit the install prompt event that Chromium browsers emit.
- KyPost still provides a service worker and a manifest. The installation flow differs by browser.

## Project Structure

- `backend/`: Go API, poller, adapters, config, state, health
- `frontend/`: React and Vite UI
- `scripts/`: bootstrap and test helpers
- `Dockerfile`: single image build (backend, frontend, Ollama runtime)
- `docker-compose.yml`: local orchestration
- `supervisord.conf`: in-container process supervision
