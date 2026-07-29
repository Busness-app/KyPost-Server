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
- CAPTCHA on login, **self-hosted proof-of-work by default** (also Turnstile or Friendly Captcha; `CAPTCHA_PROVIDER=none` turns it off). It works alongside a 3-strikes/15-minute account lockout, a looser per-IP lockout, and an instance-wide login rate limit. Note that proof-of-work needs a secure context in the browser — read the CAPTCHA notes in `.env.example` if you serve over plain HTTP on a LAN.
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

   > **Before exposing this to a network, get TLS in front of it.** By default
   > KyPost serves plain HTTP. The session cookie is marked `Secure` only when the
   > request demonstrably arrived over TLS, so on a bare `http://` deployment the
   > cookie is sent in the clear on every request. `http://` on localhost, for one
   > machine, is fine.
   >
   > The shipped compose file publishes port 5866 on `127.0.0.1` only. Behind a
   > proxy, **leave it that way** — the proxy reaches it over loopback, and
   > anything else leaves an unproxied plain-HTTP port listening beside your TLS
   > one.
   >
   > Three ways to get TLS, and they are not equivalent:
   >
   > **1. Terminate TLS in KyPost.** Set `TLS_CERT_FILE` and `TLS_KEY_FILE` to
   > mounted certificate paths (see `.env.example` and the commented volume in
   > `docker-compose.yml`). This is the only option where "did this arrive over
   > TLS?" is answered by the connection itself rather than by a header, so
   > `TRUSTED_PROXY_CIDRS` does not apply at all. Renewals are picked up without a
   > restart, which matters because a restart logs everyone out. Setting only one
   > of the two paths is a startup error, not a fallback to cleartext.
   > Certificates are deliberately never baked into the image.
   >
   > **2. Cloudflare Tunnel.** cloudflared gives the browser a real HTTPS origin,
   > which is all the login proof-of-work needs, with no TLS configuration of your
   > own.
   >
   > **3. A reverse proxy you run** (nginx, Caddy).
   >
   > Options 2 and 3 need `TRUSTED_PROXY_CIDRS` set to the proxy's address — e.g.
   > `127.0.0.1/32` for a proxy on the same host, or the bridge address of a proxy
   > container. Only then does the server believe
   > `X-Forwarded-Proto`/`-Host`/`-For`, which is what marks the cookie `Secure`
   > and keys the login and CardDAV lockouts off the real caller rather than the
   > proxy. **Name the proxy's address specifically, not a wide range:** any peer
   > inside the range you name can forge its own client IP and bypass every rate
   > limit and lockout keyed on it. This replaces the old
   > `TRUST_PROXY_HEADERS=true`, which is no longer read — it trusted forwarded
   > headers on *every* connection from any peer, so it was only ever safe when
   > nothing but the proxy could reach the port.
   >
   > Behind Cloudflare specifically, the client address is read from
   > `CF-Connecting-IP` in preference to `X-Forwarded-For`: the edge appends the
   > visitor IP to XFF, but cloudflared can append its own hop after it, which
   > would make every visitor look like `127.0.0.1` and collapse the per-IP lockout
   > into one shared bucket.
   >
   > If the proxy runs on a **different host**, combine option 1 with 2 or 3 — that
   > hop carries session cookies across a real network. A self-signed certificate
   > is enough there; tell the proxy to skip verification (cloudflared
   > `noTLSVerify: true`, nginx `proxy_ssl_verify off`).
   >
   > **Verify rather than assume.** Sign in and fetch `GET /api/status`: `clientIp`
   > must be your own public address and `proxyHeadersTrusted` must be `true`
   > (option 1 reports `false`, correctly — it trusts no headers). If `clientIp` is
   > a loopback or bridge address, every user is sharing one lockout key and the
   > session cookie is not being marked `Secure`.
5. Sign in with the bootstrap credentials. The username is `admin`. On the
   first start KyPost writes the generated password to
   `first-run-password.txt` in the config volume, mode `600`. Read it, then
   delete the file:

   ```bash
   docker compose exec kypost-server cat /kypost/config/first-run-password.txt
   docker compose exec kypost-server rm /kypost/config/first-run-password.txt
   ```

   The password is deliberately not printed to the container logs: those are
   unrotated by default, kept for the life of the container, readable by
   anything with access to the Docker socket, and forwarded to whatever log
   aggregator you have configured. To set your own password instead, pass
   `BOOTSTRAP_ADMIN_PASS` on the first run (no file is written in that case,
   since you already have it). You can also pass `BOOTSTRAP_ADMIN_USER`.
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

The server stores that blob and cannot open it, and two things have to be true
for that to hold:

1. **Your password never reaches the server.** The browser stretches it with a
   per-account login salt (fetched from `GET /api/auth/login-params`) and splits
   the result: an authentication half, which is what gets sent, and a
   key-wrapping half, which never leaves the page.
2. **The two halves are derived under different salts.** The wrapping key uses a
   random salt stored inside the envelope; authentication uses the account's
   login salt. Neither value can be computed from the other without the password.

Point 1 was not true before. Earlier versions POSTed the plaintext password to
`/api/auth/login` on every sign-in, so the server was handed the wrapping key's
source material repeatedly and merely chose not to keep it — a few lines in the
login handler would have opened every client-protected key on the instance. That
made the claim in this section, and in the code, false. Existing accounts convert
automatically on their next sign-in; nothing needs to be re-imported.

Your browser decrypts and signs. A person who takes the disk, a backup, or the
memory of this process gets ciphertext.

**What this does not defend against.** This server ships the JavaScript that does
the derivation. A server that wants your password can serve a modified bundle
that sends it, and no amount of client-side cryptography prevents that. What you
get is protection against a server that keeps too much, against your password
reaching logs, heap dumps and backups, and against someone who obtains the data
at rest. That is the same trust boundary as every other end-to-end product
delivered through a browser.

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
- `SECRET_DIR` (default `/kypost/private`. Every `*_KEY_FILE` / `*_SECRET_FILE` default below is derived from this, so moving it moves all of them together.)
- `OLLAMA_BASE_URL` (default `http://127.0.0.1:11434`)
- `OLLAMA_MODEL` (default `nemotron-3-nano:4b`; see the model note below)
- `TUNING_FILE` (default `/kypost/config/TUNING.md`)
- `OLLAMA_MODELS_HOST_DIR` (default `./share/ollama/models`)
- `IMAP_CONFIG_FILE` (default `$SECRET_DIR/imap-config.json`)
- `IMAP_CONFIG_KEY_FILE` (default `$SECRET_DIR/imap-config.key`)
- `TOTP_SECRET_KEY_FILE` (default `$SECRET_DIR/totp-secret.key`)
- `SERVER_BASE_URL` (optional. Recommended for mobile pairing. KyPost embeds this public URL as `srv` in the QR code and uses it to build `reg`.)
- `PAIRING_SECRET` (optional. HMAC secret for pickup links, PGP QR key exchange and mobile pairing tokens. Generated automatically on first start and persisted at `PAIRING_SECRET_FILE` — set it only if several replicas must share one secret, and use `openssl rand -base64 32` if you do.)
- `PAIRING_SECRET_FILE` (default `$SECRET_DIR/pairing.key`)
- `PUSH_RELAY_URL` (optional. Base URL of the central push relay Worker that delivers Android native push to FCM.)
- `PUSH_RELAY_KEY` (per-server API key from the relay operator. Set it together with `PUSH_RELAY_URL` to enable Android native push.)
- `APNS_RELAY_URL` (optional. Base URL of the central APNs relay Worker that delivers iOS native push.)
- `APNS_RELAY_KEY` (per-server API key from the relay operator. Set it together with `APNS_RELAY_URL` to enable iOS native push.)
- `CAPTCHA_PROVIDER` (optional. Set `pow`, `turnstile`, or `friendly` to require a CAPTCHA solution on login. It works together with the built-in lockout of 3 strikes and 15 minutes.)
  - `pow` is self-hosted proof-of-work: the only provider that makes no third-party network call and adds no third-party origin to the CSP. It requires no account with anyone and no keys to obtain — the signing key is generated on first use at `POW_SECRET_FILE`. **It requires HTTPS**: the browser half uses `crypto.subtle`, which browsers expose only in a secure context, so on a plain-`http://` deployment (anything but `localhost`) the check cannot run and nobody can sign in — put TLS in front of the server, as the note in Quick start says to anyway, or pick another provider. Its difficulty adapts per client IP: an honest first login solves the cheap base challenge in a blink, and each recent failed login from the same address multiplies the next challenge's difficulty, up to a ceiling, decaying after 15 minutes or on a successful login. Each challenge is bound to the address that requested it — the address is signed into the challenge and re-checked when the solution arrives — so the escalation cannot be sidestepped by fetching cheap challenges from a clean address and spending them from an escalated one. (If your own address changes mid-check, say a phone moving from wifi to cellular, the sign-in page tells you to try again and costs you no lockout strike.) Escalation is still counted per address, so an attacker spraying from many addresses gets the base difficulty at each: it prices repetition, not a distributed attacker. An attacker running native code is also one to two orders of magnitude faster than a browser, so this deters casual scripted spraying, not a determined campaign. It does **not** replace the three-strikes lockout, which remains the real brute-force defence. Multi-replica deployments must set `POW_SECRET` so every replica agrees on one signing key — generate it with `openssl rand -base64 32`; anything shorter than 16 characters is refused and the login CAPTCHA then rejects every attempt.
  - `turnstile` and `friendly` verify a token against a third-party siteverify endpoint and need a site key + secret key.
- `CAPTCHA_SITE_KEY` and `CAPTCHA_SECRET_KEY` (required together with `CAPTCHA_PROVIDER=turnstile` or `friendly`; not used by `pow`. The site key is public. The server verifies solutions with the secret key.)
- `POW_MAX_NUMBER`, `POW_SECRET_FILE`, `POW_SECRET` (optional, `CAPTCHA_PROVIDER=pow` only — see `.env.example` for tuning notes)

Notes:

- The classifier model defaults to `nemotron-3-nano:4b` everywhere — `Dockerfile`,
  `docker-compose.yml`, `.env.example`, and the backend's own fallback.
- The image sets `OLLAMA_MODELS=/kypost/ollama-models`.

### Choosing a classifier model

The default is picked to run on modest hardware. Measured on a 60-email
benchmark (`backend/cmd/modeleval`), five repeats each with zero run-to-run
variance:

| Model | Unambiguous mail | Keyword traps | Prompt injection | RAM resident |
|---|---|---|---|---|
| `nemotron-3-nano:4b` (default) | 100% | 75% | 63% | 2.9 GB |
| `gemma4:e4b` | 100% | 75% | 88% | 8.8 GB |

Both label ordinary mail equally well, and both are perfect on unambiguous
messages. `gemma4:e4b` resists two more of the eight prompt-injection probes —
emails written to talk the classifier into filing them somewhere they do not
belong — but wants three times the memory. Set `OLLAMA_MODEL=gemma4:e4b` if the
host has 12 GB or more free.

Classification speed is not tabulated because it depends far more on your CPU
and on what else the host is doing than on the model: the same request measured
between 13 and 19 seconds on one machine purely as background load varied. The
two models were within about 20% of each other under identical conditions, with
`gemma4:e4b` slightly ahead. The poller paces itself at one message every three
seconds regardless, so throughput is bounded by that unless the host is very
slow.

Either way the damage from a successful injection is bounded: the label
allowlist means a hostile email can at most choose which of the four folders it
lands in, and one probe (an email claiming the label set itself had changed)
defeated every model and every prompt variant tested. Do not treat the assigned
label as a security decision.

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
- `GET /api/auth/login-params` — the per-account salt and work factor a client
  needs to derive its auth secret, so the password is never transmitted. Public,
  and deliberately answers identically for a username that does not exist.
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
