<img src="./ky50p.png" alt="KyPost" />

# KyPost

KyPost is a self-hosted IMAP web client. It applies keyword labels to your mail automatically with a local Ollama model.

KyPost polls unread mail, classifies each message, and applies IMAP keywords. It also gives you a web UI to read mail, change the configuration, manage notifications, view logs, and compose mail. Compose supports send and draft save.

## Features

- Single-container Docker runtime. supervisord manages the processes.
- Multi-user with two roles. Admins manage users and system settings. Each user connects their own IMAP mailbox.
- IMAP inbox reader with folder management and drag-and-drop move actions
- Automatic keyword labels for unread mail. KyPost polls each active user's mailbox separately. Labels are a sorting hint a determined sender can influence — see [Classification flow](#architecture).
- Filter Rules: a GUI condition and action builder plus a raw Sieve script editor. A run-now panel applies the rules on demand.
- Compose flow with SMTP send and IMAP draft save
- PGP mail encryption. Generate or import a key, search for recipient keys on keys.openpgp.org, and check recipient key status before you send. KyPost has two key-protection modes. Read [Where your PGP private key lives](#where-your-pgp-private-key-lives) before you rely on this.
- Contacts address book with groups, dedupe, bulk delete, CSV and vCard import and export, and photo support
- CardDAV server (`/dav`, `/.well-known/carddav`) to sync contacts to phones and desktop apps. An optional CardDAV client syncs against an external address book.
- Multi-factor authentication: TOTP authenticator apps, one-time recovery codes, and push-approval sign-in
- CAPTCHA on login, **self-hosted proof-of-work by default** (also Turnstile or Friendly Captcha; `CAPTCHA_PROVIDER=none` turns it off). It works alongside a 3-strikes/15-minute account lockout, a looser per-IP lockout, and an instance-wide login rate limit. Note that proof-of-work needs a secure context in the browser — read the CAPTCHA notes in `.env.example` if you serve over plain HTTP on a LAN.
- Browser push notifications for each user, for all mail or for keyword matches only. KyPost also supports native push pairing for mobile apps.
- Settings grouped into panels: Appearance, Mail (IMAP/SMTP, send-as, contact sync, filters), Security, Notifications and Status — plus Automation for each user's own prompt tuning and classification decisions — and an Admin group for server runtime and diagnostics
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

> **Labels are a hint, not a security boundary.** The classifier reads
> attacker-supplied text, so a sender can write instructions into their message
> and influence which keyword it gets. No small local model resists this
> reliably. Running `backend/cmd/modeleval` against the injection bucket of its
> corpus puts the shipped default at roughly 50–87% resistance depending on
> prompt config, and every model measured let some through. Treat it as a known
> property of the feature rather than a bug with a fix pending.
>
> What that buys an attacker is small and bounded: they can steer the label on
> **their own message** — typically into `Primary` instead of `Promotions`. The
> keyword allowlist is enforced in Go after the model answers (step 5), so
> output that is not an allowed label is discarded; a message cannot be labelled
> as something you never configured, cannot be moved, deleted, or marked read,
> and cannot affect any other message. The worst case is a promotional email
> that sorts itself into your main tab — the same thing a sender achieves by
> writing a more convincing subject line.
>
> Do not build a security control on top of these keywords: no filter rule that
> grants trust based on a label, and no "auto-archive anything labelled X."
> Every decision is recorded, so you can audit what the model actually did on
> the Decisions page.

## Requirements

- Docker
- Docker Compose

Optional for local development (outside Docker):

- Go 1.26+
- Node.js 20+
- npm

## Quick Start

1. Clone the repository.
2. Copy the environment defaults and set `KYPOST_BIND`.

   ```bash
   cp .env.example .env
   ```

   `.env.example` ships with `KYPOST_BIND=127.0.0.1`, which is right when your
   reverse proxy runs on this same host. It is **required** — compose refuses to
   start without it — because the alternative is a silent default, and this port
   serves plain HTTP unless `TLS_CERT_FILE` is set. See step 4.

3. Build and start the container.

   ```bash
   docker compose up --build -d
   ```

4. Open the web UI at http://localhost:5866.

   > **Before exposing this to a network, get TLS in front of it.** By default
   > KyPost serves plain HTTP. The session cookie is marked `Secure` only when the
   > request demonstrably arrived over TLS, so on a bare `http://` deployment the
   > cookie is sent in the clear on every request. `http://` on localhost, for one
   > machine, is fine. Compose refuses a non-loopback cleartext bind unless you
   > explicitly set `ALLOW_INSECURE_HTTP=true`; that escape hatch is for a
   > deliberately trusted network, not a TLS substitute.
   >
   > `KYPOST_BIND` decides which interface port 5866 is published on, and it has
   > no default — compose will not start until you set it. An unproxied 5866 is
   > plain HTTP, and with `TRUSTED_PROXY_CIDRS` set, anything that reaches it
   > directly can forge `X-Forwarded-For` and bypass the lockouts. Use
   > `127.0.0.1` for a proxy on this host, your LAN IP for a proxy elsewhere, or
   > `0.0.0.0` to publish everywhere deliberately. **Check where your proxy
   > actually reaches this container from before choosing**: loopback publishing
   > severs a proxy that arrives by the host's LAN address, which is the usual
   > shape for cloudflared or an nginx on another machine.
   > Better still, run the proxy as a container on `kypost-net` — the network the
   > compose file defines for exactly this — and point it at
   > `http://KyPost-Server:5866`. That network has DNS, so the name keeps working
   > across rebuilds, and the path ignores published ports entirely so nothing
   > needs publishing. The snippet for joining it from another compose project,
   > and how to recover from the two Docker errors this setup produces, are in
   > [docs/Reverse_Proxy_Networking.md](docs/Reverse_Proxy_Networking.md).
   >
   > **This is what makes the client IP correct, not a nicety.** A proxy on a
   > *separate* Docker network — or one that reaches this container through the
   > published port, even from `kypost-net` — is source-NATed on the way in, so the
   > server sees the same `172.x.0.1` gateway for every caller. That address is the
   > lockout key, so every user shares one bucket, and the MFA sign-in push names
   > the gateway instead of whoever is signing in.
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
   > `127.0.0.1/32` for a proxy on the same host, or the address you pinned for a
   > proxy container on `kypost-net` (e.g. `10.89.0.10/32`). Putting the proxy on
   > that network is what makes such an address meaningful, but it is not a
   > substitute for setting this: with it empty, forwarded headers are discarded
   > and every caller is keyed as the proxy. Only with it set does the server believe
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
  new one. Security offers a browser-generated encrypted recovery backup: keep
  its downloaded file and separately displayed recovery secret offline. The
  server never receives the plaintext key or secret, and both are required to
  restore the same identity after the reset.
- **You unlock the key once for each browser session.** The browser holds the
  unwrapped key in page memory only, never in localStorage or sessionStorage.
  After a reload you must enter your password again.
- **KyPost does not add verified send-as addresses to your key
  automatically.** That edit re-signs the key and needs the private half. The
  browser makes the edit, not the background poller.

**Server-protected.** The server seals the key with a master key on the same
volume and unwraps it whenever it needs to. You get the convenience: mail
decrypts without you unlocking anything, a password reset never costs you the
key, send-as addresses get signed in for you, and the background poller can do
its work while no browser is open. Nothing about the key is your problem after
setup.

You pay for that with the trust boundary. This mode is **not** end-to-end
encryption, and earlier versions of this README described it as if it were. The
server, and any person who can read that volume — whoever holds root, whoever
holds a backup, whoever seizes the disk — can decrypt everything you have ever
received. If you run this server yourself on hardware you control, that may be a
trade you are happy to make. If someone else runs it, you are trusting them with
your mail in the clear.

Choose this mode deliberately, not by accident. If you decide the trade is not
worth it, the Security page offers a one-time migration: it hands the key to your
browser, rewraps it under your password, and deletes the server-readable copy.

Some facts apply to both modes, and they are worth a plain statement:

- **Ordinary PGP/MIME does not encrypt subject lines.** Your mail provider sees
  them in both modes. KyPost protects the subject inside the encrypted part when
  it can, but the outer header remains.
- **Mobile push notifications are generic by default** for this reason. See
  Settings → Notifications.
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

- Admins manage users from Settings, under Admin. The Server panel creates
  users, changes roles, resets passwords, and deactivates or reactivates
  accounts, alongside runtime settings, updates and verified mail domains.
  Diagnostics holds the full health view, the system logs and health repair.
  Label rules are a Server tab, since the allowlist is instance-wide.
  Automation is entirely per-user — each account's own prompt tuning and
  classification decisions — so it is not admin-only.
- Users connect their own IMAP and SMTP account. They read and label their own
  mail, pair their own devices, set their own notification preferences, and tune
  their own prompt.
- Deactivation is a soft delete. The user can no longer sign in. KyPost keeps
  their data on disk until you remove it manually.
- KyPost does not let you deactivate or demote the last active admin.

Per-user data layout:

- `/kypost/config/users/<userID>/`: encrypted IMAP credentials, tuning prompt (`tuning.md`), notification preferences (`config.yaml`)
- `/kypost/state/users/<userID>/`: `state.db` — an SQLite database holding the mailbox checkpoint, the processed set, decision history, push subscriptions, and paired devices. SQLite runs in WAL mode, so `state.db-wal` and `state.db-shm` sit alongside it while the database is open and are part of the state, not scratch files.

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
- `PAIRING_SECRET` (optional. HMAC secret for pickup links, PGP QR key exchange and mobile pairing tokens. Generated automatically on first start and persisted at `PAIRING_SECRET_FILE` — set it only if several replicas must share one secret, and use `openssl rand -base64 32` if you do. A value shorter than 32 bytes is refused and those three features stay disabled, with the reason logged. Bytes, not characters, because the value is used as the HMAC key verbatim; for the ASCII `openssl rand -base64 32` produces they are the same number.)
- `PAIRING_SECRET_FILE` (default `$SECRET_DIR/pairing.key`)
- `PUSH_RELAY_URL` (optional. Base URL of the central push relay Worker that delivers Android native push to FCM. Must be `https://` — the relay key travels on every request — except for loopback.)
- `PUSH_RELAY_KEY` (per-server API key from the relay operator. Set it together with `PUSH_RELAY_URL` to enable Android native push.)
- `APNS_RELAY_URL` (optional. Base URL of the central APNs relay Worker that delivers iOS native push. Must be `https://` — the relay key travels on every request — except for loopback.)
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

- Security's Devices tab renders a QR code link with `sub`, `hash`, `srv`, `reg`, and `pt`.
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
- `/kypost/state/state.db` (global state: AI-credits flag)
- `/kypost/state/users/<userID>/state.db` (per-user mailbox state, decisions, devices, subscriptions)
- `/kypost/config/admin.env` (legacy single-admin seed. KyPost imports it once, then stops reading it.)

## Backup and Restore

Back up with the container **stopped**. This is not caution for its own sake:

- `state.db` is SQLite in WAL mode. Copying `state.db` while KyPost is writing
  gives you a file whose committed data is still sitting in `state.db-wal`. It
  will open, and it will be missing whatever was in flight.
- The four volumes are not independent. `kypost_private` holds the keys that
  decrypt what is in `kypost_config`, and `kypost_state` holds mailbox
  checkpoints that only make sense against the accounts in `kypost_config`.
  Archiving them at different moments produces a set that never existed
  together — the failure shows up at restore, as credentials that will not
  decrypt or a checkpoint pointing past mail that was never processed.

Nothing here is Ollama: the model bind mount is a cache and re-downloads.

### Back up

```bash
cd /path/to/kypost-server

# 1. Record what you are backing up, as an immutable digest. A backup you cannot
#    match to a version is a backup you cannot safely restore, and a tag is not
#    a version — `stable` will mean something different by the time you need it.
docker image inspect --format '{{index .RepoDigests 0}}' \
  "$(docker compose images -q kypost-server)" > backup-version.txt
cat backup-version.txt

# 2. Stop. Not `pause`, not `kill` — a clean stop lets SQLite check its WAL back
#    into the database file.
docker compose down

# 3. Archive all four volumes in ONE pass, so they are consistent with each other.
#    The volumes are Compose-managed, so their real Docker names carry the
#    project prefix from `name:` in docker-compose.yml — `kypost_config` in the
#    Compose file is `kypost-server_kypost_config` to `docker volume`. Confirm
#    with `docker volume ls | grep kypost` before running this.
docker run --rm \
  -v kypost-server_kypost_config:/v/config:ro \
  -v kypost-server_kypost_private:/v/private:ro \
  -v kypost-server_kypost_logs:/v/logs:ro \
  -v kypost-server_kypost_state:/v/state:ro \
  -v "$PWD":/backup \
  alpine tar czf /backup/kypost-backup.tar.gz -C /v .

# 4. Start again.
docker compose up -d
```

Check the archive is not empty before trusting it — a mistyped volume name
mounts a new empty volume rather than failing:

```bash
tar tzf kypost-backup.tar.gz | grep -E 'private/|state/users/' | head
```

Store `kypost-backup.tar.gz` and `backup-version.txt` together, and store them
encrypted or somewhere you would be willing to keep your mail. The archive
contains `imap-config.key` and `totp-secret.key`, which unwrap every stored IMAP
credential and TOTP secret on the install. It does **not** contain anything that
can decrypt a user's PGP private key — that half of the wrapping key never
leaves the browser (see [Where your PGP private key lives](#where-your-pgp-private-key-lives)).

### Restore

Restore into **empty** volumes, running the **same version** the backup was
taken from. Restoring an old state directory under a newer server means the
newer server's migrations run against it — which is a supported path, but it is
an upgrade, and doing it in the same step as a restore means a failure has two
possible causes.

```bash
cd /path/to/kypost-server

docker compose down -v          # removes the named volumes and their contents

# Let Compose create the volumes, so they carry the project labels Compose
# expects to find on them. `create`, not `up`: creating them by hand with
# `docker volume create` makes Compose treat them as foreign, and starting the
# server would run first-run bootstrap — generating an admin account and a
# first-run password file into the volumes you are about to restore over.
docker compose create

docker run --rm \
  -v kypost-server_kypost_config:/v/config \
  -v kypost-server_kypost_private:/v/private \
  -v kypost-server_kypost_logs:/v/logs \
  -v kypost-server_kypost_state:/v/state \
  -v "$PWD":/backup \
  alpine tar xzf /backup/kypost-backup.tar.gz -C /v

# Start the exact image recorded in backup-version.txt. A locally built install
# has no published digest — restore it with `docker compose up --build -d` from
# the commit it was built at instead.
printf 'services:\n  kypost-server:\n    image: %s\n' "$(cat backup-version.txt)" \
  > docker-compose.restore.yml
docker compose -f docker-compose.yml -f docker-compose.restore.yml up -d
```

### Verify the restore

A backup nobody has restored is a hypothesis. Check all four volumes actually
came back, because each one fails differently and three of the four failures are
silent until someone needs them:

1. **Sign in** as an existing user — proves `kypost_config` (`users.json`) and
   session/password material.
2. **Open an encrypted message** — proves `kypost_private` and the PGP key
   wrapping. This is the check people skip; a wrong `imap-config.key` looks fine
   until mail needs decrypting.
3. **Confirm a paired device is still listed**, and that TOTP still validates —
   proves `totp-secret.key` and per-user `state.db`.
4. **Watch one poll tick** in Configuration > Application (or
   `docker compose logs -f`) and confirm the checkpoint advances rather than
   reprocessing the whole mailbox — proves the per-user `state.db` mailbox state
   survived. A reset checkpoint re-labels and re-notifies everything.

Only once that passes should you upgrade to a newer version, as a separate step.

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

- `GET|PUT /api/config` (GET omits `redaction.patterns` for non-admins; PUT is admin only)
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

## Updating KyPost

KyPost checks GitHub releases hourly. When a newer KyPost release is found, it
emails the primary admin once and shows the update in Configuration >
Application. The container reports availability but never controls Docker on
its host.

See [`CHANGELOG.md`](CHANGELOG.md) for what changed in each release and for the
upgrade/rollback matrix. Take a backup before upgrading — see
[Backup and Restore](#backup-and-restore).

Published releases are available from GitHub Container Registry. From the
checkout, apply the current `stable` image with health-gated rollback:

```bash
./scripts/update-host.sh
```

The script resolves `stable` to an immutable digest, verifies its GitHub build
attestation with `gh attestation verify`, and preserves that exact digest for
rollback. It requires Docker Compose v2, Docker Buildx, and the GitHub CLI
(`gh`), and checks for each up front; it fails closed
when either verification or the health check fails. To stay on a specific
release instead, set `KYPOST_VERSION=0.2.0` in `.env` before running it.

An install still running a locally built image has no published immutable
digest, so the updater refuses it rather than guessing at a rollback target.
Update that install from source with `git pull --ff-only && docker compose up
--build -d`, then use published-image updates going forward.

Automatic updates are opt-in and require a systemd host. Run this from the
checkout to install a daily timer (03:15 local time plus up to one hour of
jitter). It enables systemd lingering for the Docker-operating user so the
timer continues after logout and reboot; if that needs approval, run the
printed `sudo loginctl enable-linger <user>` command once and rerun it:

```bash
./scripts/install-auto-update.sh
```

Disable it with `systemctl --user disable --now kypost-update.timer`. The timer
runs as the Docker-operating user and uses the same host-side updater, not code
inside the container. On systems without systemd, schedule
`./scripts/update-host.sh --auto` with
`KYPOST_AUTO_UPDATE=true` in the scheduler environment.

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

[![OctoCounts](https://api.octocounts.com/badge/Yoshiofthewire/KyPost-Server/branch/main)](https://octocounts.com/github/Yoshiofthewire/KyPost-Server/tree/main)