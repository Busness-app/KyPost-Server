<img src="./ky50p.png" alt="KyPost" />

# KyPost

KyPost is a self-hosted IMAP web client. It applies keyword labels to your mail automatically with a local Ollama model.

KyPost polls unread mail, classifies each message, and applies IMAP keywords. It also gives you a web UI to read mail, change the configuration, manage notifications, view logs, and compose mail. Compose supports send and draft save.

## Features

- Repeatable installer setup: runtime-owned `apply-setup --file` preserves existing SSO/webhook/domain/recovery configuration and returns a secret-free JSON report. `setup-status` lists configuration blockers and external acceptance checks. See [clean installation](docs/INSTALLER_SETUP.md).

- Guided dedicated-domain qualification: `bash scripts/setup-mail.sh <public-KyPost-origin>` walks through native deployment, KyIdentity/DNS proof, operator relay, protected engine/TLS inputs, backups and receiving launch. It requires Docker-operator authority and explicit configuration/start confirmations; live delivery remains an operator check. See [guided setup](docs/RECEIVING_SETUP.md#guided-operator-setup).

- Optional local Rspamd sidecar rejects messages meeting the configured spam threshold before native SMTP acceptance. False positives can reject legitimate mail; scanner outages defer new mail, and enabling it gives the scanner message access. Accepted mail remains unchanged. See [spam setup](docs/RECEIVING_SETUP.md#optional-rspamd-sidecar).
- Continuous Cloudflare receiving (offline-qualified, not yet qualified live): with `KYPOST_CLOUDFLARE_RECEIVING_ORIGIN` set, the daemon publishes a signed routing table of every admitted address to the operator's Email Worker and picks mail up from its private R2 queue over outbound HTTPS every 30 seconds. Each message is checked against the owner and address generation frozen when Cloudflare accepted it, scanned by the local Rspamd sidecar (a reject verdict files it to Junk, since accepted mail cannot bounce) and committed to the mailbox before the provider copy is deleted. A restored copy starts fenced; `kypost-server receiving cloudflare takeover` moves receiving to it and locks the previous host out. See [continuous receiving](docs/CLOUDFLARE_CONTINUOUS_RECEIVING.md) and [operator commands](docs/RECEIVING_SETUP.md#continuous-cloudflare-profile).
- One-message Cloudflare receiving pilot: an operator-owned Email Worker retains exact mail in a private R2 slot for manual authenticated HTTPS pickup into a native mailbox. Local scanning follows provider capture; refusal retains the provider copy. This finite-window test is not continuous reception. See [setup, trust and rollback](docs/CLOUDFLARE_RECEIVING.md).
- Controlled direct receiving profile generation from verified domain and existing native storage; mandatory STARTTLS refuses plaintext senders. An optional Compose profile supervises the operator-supplied pinned receiver, which shares the instance’s mail-storage authority; public deployment remains gated. See [receiver setup](docs/RECEIVING_SETUP.md).

- Opt-in native primary-address sending through the operator-owned relay: ordinary compose and client PGP record encrypted outbox intent before SMTP; recovery retains interrupted claims, retries definite temporary refusals and files Sent independently. Failed relay attempts log a bounded SMTP code and outbox correlation ID without provider text or correspondence. Included in sealed backups; see [outbox contract](docs/NATIVE_OUTBOX.md).

- Admin → Server → Mail domain lists every configured mail domain (add, verify, retire, re-add; per-domain TXT proof and status), chooses the relay's sending domains and guides DNS proof, encrypted operator-owned relay configuration and a no-mail TLS/authentication check, protected by account confirmation and fresh DNS proof. KyPost holds the domain-wide relay credential on the server. Primary-address sending requires explicit native mode and fresh sender admission; saving credentials does not prove delivery or public receiving readiness; see [setup and controlled tests](docs/DOMAIN_RELAY.md).

- Admin → Server → Mail addresses lists native mailboxes and their addresses (kind, state, generation; filter by user), adds aliases to an everyday identity's mailbox, releases them (kept reserved; delivery and sending stop at once, existing mail stays) and reassigns reserved ones to a chosen mailbox, and creates, disables and re-enables additional mailboxes for an everyday identity, each with account or KySignOn confirmation. Primary mailboxes and addresses come from KyIdentity and offer no actions; see [addresses](docs/NATIVE_PROVISIONING.md#addresses-aliases-and-generations).
- Administrators block abusive senders by address or domain (Admin → Server → Sender blocks, `receiving blocks` CLI or admin API); both receiving profiles refuse them before storing anything. With the Rspamd sidecar, Maddy also blocks a sender automatically after 5 spam rejections in an hour, but only when SPF and aligned DKIM prove the sender address (1 hour, then 24 hours, then 7 days), and a whole domain only after 5 such addresses on a domain you never received authenticated mail from (after 30 days of collecting that history). Automatic blocks use at most half the list and always give way to administrator blocks. The Sender blocks tab shows every block in force (automatic domain blocks called out in words, since one can cover a whole provider) and the automatic-evidence status: damaged or reset evidence, when automatic domain blocks start, and when automatic blocking or the protected-domain record is full. Removing any block suppresses automatic re-blocking of that exact address or domain for 30 days. See [sender blocks](docs/NATIVE_PROVISIONING.md#sender-blocks).
- Admin → Server → Quarantine lists quarantined native deliveries by envelope only (received time, sender, recipients with their frozen mailbox and user, size, gateway/ID; never body or subject), shown as plain text with hidden characters made visible, and releases each to its original mailboxes or discards it permanently, with account or KySignOn confirmation; see [quarantine release](docs/NATIVE_PROVISIONING.md#quarantine-release).

- Per-user opt-in incoming encryption under Security → Encryption: classify unread, unprocessed inbox mail, then replace it with a verified public-key-encrypted copy. Requires a client-protected key, saved-key-backup acknowledgment and fresh account confirmation. The provider sees plaintext before processing; losing the private key makes replaced mail unreadable. Unreplaceable messages remain plaintext with explicit failure decisions; [read the replacement and recovery contract](docs/E2E_PGP.md#incoming-mail-encryption-opt-in).

- Sealed configuration/state backups to KyRecovery or a local directory, with admin scheduling and restore drills. Internal native mailbox/receiving databases use SQLite snapshots including committed WAL rows; historical ownership is checked, restored queued/retryable outgoing mail is quarantined against replay, native device/browser push registrations and pairing tokens are revoked (fresh pairing/enrollment required), offline restore raises native ID-token revocation cutoffs beyond the accepted 30-second future skew, and native restores remain held with no release path yet. Held native accounts cannot sign in or exercise existing session/admin authority; retain a separate legacy recovery administrator. Offline restore also rotates a separate reference generation without changing encryption namespaces; native reads/actions reject stale-generation or bare numeric references before access. Protected admin APIs can record fresh signed KyIdentity evidence and revision barriers for unpublished reservations; published accounts retain ordinary offboarding and demotion. A separate protected repair API reconciles published native activity/roles and revokes stale transport credentials while preserving mail, labels, passwords, PGP material and the restore hold. Hold release remains pending. Custodian shares are used only by the offline restore command; see [sealed backup and restore](docs/RESTORE.md). With `KYPOST_BULK_BACKUP_REPOSITORY` set, mailbox and receiving databases go to an encrypted restic repository instead of the capsule, which seals the snapshot ID and every file digest, so mailboxes are no longer limited to 64 MiB; native mail with real quotas (5 GiB per mailbox by default) needs it, since a capsule-only backup fails once a mailbox passes 64 MiB, with an error naming the variable. Prefer an append-only rest-server: a local repository is writable by KyPost, unlike deposit-only KyRecovery; see [mail bulk backup](docs/RESTORE.md#mail-bulk-backup).
- Self-service mail import under Security → Import Mail: an mbox file, one EML or a zip of EML files into a native mailbox folder, after account or KySignOn confirmation, as a background job with progress and cancel. Messages are stored as parsed from the file and marked read; duplicates are skipped; imported mail is not scanned for spam or run through rules, even if later marked unread. A job handles at most 20,000 messages and an upload at most 20 minutes. Refused while incoming encryption is on, since imported mail would be stored unencrypted. Or import from another mail account over IMAP: the server signs in with a password or app password used only for that import and never stored, lists the folders to choose from, and copies them read-only, keeping each message's read and flagged state and received date; it connects only to public servers over verified TLS.
- Users with additional native mailboxes switch between them in the webmail sidebar and read, search, file and send from each; compose offers the open mailbox's addresses as From. The choice lasts for the browser tab.
- Self-service mail export under Security → Export Mail: a native mailbox, or one folder, as an mbox file or a zip of EML files holding the exact stored bytes, after account or KySignOn confirmation. Encrypted messages stay encrypted; flags and labels are not included.
- Shared JSON application logs on stderr, controlled by `KY_LOG_LEVEL`; see [logging](LOGGING.md).

- Single-container Docker runtime. supervisord manages the processes.
- Multi-user with two roles. Admins manage users and system settings. Each user connects their own IMAP mailbox. Signed KySignOn directory events retain desired account data; admins can configure and verify mail-specific DNS domain claims for several domains under one issuer (each with its own proof, retirable once unused), and a primary address may sit on any of them. Internal allocation prepares reserved native mailboxes before exposing new accounts; administrator identities get mailbox-less accounts. Native state access refuses held or unqualified storage before cache returns and uses an existing-only state opener. `KYPOST_NATIVE_MAIL=true` opts into new domain-account provisioning, native mailbox access and primary-address relay sending in API/daemon; separate `KYPOST_NATIVE_RECEIVING=true` enables local receiving commands and daemon import for controlled qualification. Every native mailbox has a storage quota (`KYPOST_MAILBOX_QUOTA_BYTES`, default 5 GiB), a 25 MiB message limit and 1,000,000 records; `migrate-native` applies a changed quota to existing mailboxes at the next start, and a lowered one never locks a mailbox, it only refuses new mail. Users see their usage under Settings → Mail → Storage, with warnings at 80% and 95%; Server → Mail addresses shows each mailbox's usage and warns when the quotas could outgrow the drive. Receiving answers a full mailbox and a nearly full drive (the reserve: 10% of the state filesystem or 5 GiB, whichever is larger) with temporary 452 replies so senders retry, and imports stop at the same reserve; see [mailbox quotas](docs/NATIVE_PROVISIONING.md#mailbox-quotas). Bundled public receiving remains unavailable; see [the provisioning contract](docs/NATIVE_PROVISIONING.md).
- IMAP inbox reader with background body preloading, folder management, and drag-and-drop move actions
- Verification-code card: a code in INBOX mail under 15 minutes old is shown with a Copy button and a never-share warning. It makes no claim about the sender and makes no network request; phishing-flagged mail gets no card
- Automatic keyword labels for unread mail. KyPost polls each active user's mailbox separately, and each account has its OWN label list — copied from the instance defaults when the account is created, then theirs to change. Labels are a sorting hint a determined sender can influence — see [Classification flow](#architecture).
- On-device embedding sorter in front of the LLM: a ~30 MB embedding model baked into the image labels mail in well under a millisecond and sends only what it is unsure of to Ollama. It learns per account from you — change a message's label in the reader (or in another IMAP client; noticed when the KyPost inbox syncs) and similar mail follows; give a new label an optional description and it is recognised straight away. It stores vectors, never message text, and never trains on the LLM's own answers. `CLASSIFIER_ENGINE=llm` turns it off.
- Pre-sort before the model: mail from a contact you added is labelled `Primary` without an LLM call, and mail with mailing-list or automated headers (`List-Id`, `List-Unsubscribe`, `Precedence: bulk/list/junk`, `Auto-Submitted`) can never be labelled `Primary`. Same input, same answer; edit your contacts or add a rule to change it.
- Filter Rules: a GUI condition and action builder plus a raw Sieve script editor. A run-now panel applies the rules on demand. Rules can test any header, so a provider's spam verdict (for example `X-Spam-Flag: YES`) can move mail to Junk.
- Compose flow with SMTP send and IMAP draft save
- PGP mail encryption and signing. Signing defaults on with an unlocked browser key; compose labels unsigned mail, and the reader distinguishes encrypted but unsigned mail from a verified signature. Generate or import a key, search for recipient keys on keys.openpgp.org, and check recipient key status before you send. KyPost has two key-protection modes. Read [Where your PGP private key lives](#where-your-pgp-private-key-lives) before you rely on this.
- Contacts address book with groups, dedupe, bulk delete, CSV and vCard import and export, and photo support
- CardDAV server (`/dav`, `/.well-known/carddav`) to sync contacts to phones and desktop apps. An optional CardDAV client syncs against an external address book. Native restore revokes historical CardDAV app passwords and blocks CardDAV while recovery is held.
- Browser PGP writes reject stale snapshots, including same-key edits concurrent with password changes or recovery uploads. Existing complete keyrings support atomic password changes that preserve all history and recovery material.
- PGP recovery copies stored as ciphertext, downloadable backups checked before creation completes, and browser-local recovery drills. Complete-ring export, drills and matching-backup restore preserve historical keys; restoration confirms the stored result before unlocking. Verified complete-ring server copies require saved-secret acknowledgement and confirm the stored result. Conversion and older-backup merging remain gated.
- Multi-factor authentication: TOTP authenticator apps, one-time recovery codes, and push-approval sign-in
- Single Sign-On against any standard OpenID Connect provider — KySignOn (one-click preset; the `kypost.admin` app role is the only thing that makes an administrator, and an SSO session never holds admin without it), Authentik and Keycloak have their admin-group claims mapped. Authorization code + PKCE, ID tokens verified against the issuer's JWKS. Issuance timestamps must be positive and within 30 seconds of future server-clock skew; keep issuer/server clocks synchronized. Accounts are claimed by the provider's `sub` and never by username or email. Admin-configured under Admin > Server > SSO; **requires `SERVER_BASE_URL`**.
- Send-as aliases, each verified before use: a code is mailed as the alias to the alias through your own outgoing server. Typing it back unlocks the From address; the same message looping back DKIM-signed by the alias's domain is the proof that also publishes your key for it over WKD
- Web Key Directory publishing: serve your users' public keys at `/.well-known/openpgpkey/` for verified domains, so correspondents discover them without a keyserver
- CAPTCHA on login, **self-hosted proof-of-work by default** (also Turnstile or Friendly Captcha; `CAPTCHA_PROVIDER=none` turns it off). It works alongside a 3-strikes/15-minute account lockout, a looser per-IP lockout, and an instance-wide login rate limit. Note that proof-of-work needs a secure context in the browser — read the CAPTCHA notes in `.env.example` if you serve over plain HTTP on a LAN.
- Browser push notifications for each user, for all mail or for keyword matches only. KyPost also supports native push pairing for mobile apps. Encrypted-mail setup checks the device’s supported envelope formats before sealing.
- Settings grouped into panels: Appearance, Mail (IMAP/SMTP, send-as, contact sync, filters, mail import and export), Security, Notifications and Status — plus Email Labels for each user's own prompt tuning and classification decisions — and an Admin group for server runtime and diagnostics
- Busnes light/dark defaults follow the OS, with seventeen theme presets and a saved browser-local choice

## Architecture

The container runs these processes:

- API server: `kypost-server --mode server`
- Polling daemon: `kypost-server --mode daemon`
- Ollama service: `ollama serve`
- One-shot startup pull: `ollama pull <configured model>`

Classification flow:

1. Fetch unread messages from IMAP (`INBOX` by default), plus their list/automation headers and any header a filter rule tests.
2. Run filter rules.
3. Pre-sort: a contact's mail gets `Primary` and skips steps 5-8 (and the rate limit); list or automated mail has `Primary` removed from the labels the model may choose. Only accounts whose label set includes `Primary` are affected.
4. Redact sensitive patterns, then embed the redacted sender, subject and body with the on-device sorter. If it is at least `EMBED_MIN_CONFIDENCE` sure, apply its label and skip steps 5-7 (and the rate limit).
5. Build the prompt from sender, subject, body, and tuning context.
6. Call Ollama `/api/generate`.
7. Match the output against the allowed labels.
8. Apply the IMAP keywords, and remember what was applied (as a vector and a hash) so a later relabel by the user can be learned.
9. Save the checkpoint and the decision history.

> **Labels are a hint, not a security boundary.** The classifier reads
> attacker-supplied text, so a sender can write instructions into their message
> and influence which keyword it gets. No small local model resists this
> reliably. Running `backend/cmd/modeleval` against the injection bucket of its
> corpus puts the shipped default at roughly 50–87% resistance depending on
> prompt config, and every model measured let some through. Treat it as a known
> property of the feature rather than a bug with a fix pending.
>
> The embedding sorter follows no instructions, so "file this under Primary"
> is just more words to it (it resisted all 8 of the corpus's injection probes),
> but a sender still chooses the words it reads and can make a message look
> like whatever label they prefer. Its training data is only your own relabels,
> never the LLM's answers or anything a sender controls on its own.
>
> What that buys an attacker is small and bounded: they can steer the label on
> **their own message** — typically into `Primary` instead of `Promotions`. The
> keyword allowlist is enforced in Go after the model answers (step 7), so
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
   > nginx speaks HTTP/1.0 to the upstream by default; set
   > `proxy_http_version 1.1;`. Mail export refuses mbox over HTTP/1.0, where a
   > cut-off download is indistinguishable from a complete one.
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

- **An admin password reset can strand the password-wrapped key.** Before
  you need a reset, use Security → Encryption to create a recovery copy and
  keep its separately displayed secret. The browser tests the encrypted file
  in memory, requests its download and, after you confirm saving the secret, stores a sealed copy on the server.
  After signing in with the reset password, **Use server recovery copy** can
  restore the current identity even if you lost the download. The server never
  receives the recovery secret or plaintext key. Keep an offline file too:
  deleting the identity removes the server copy, and a server loss removes it
  as well. **Run recovery drill** tests your copy and secret without changing
  the key; its date is recorded only in this browser, for the copy tested.
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
  accounts, alongside runtime settings, updates, verified mail domains and native addresses.
  Diagnostics holds the full health view, the system logs and health repair.
  Label rules are a Server tab, since the allowlist is instance-wide.
  Email Labels is entirely per-user — each account's own prompt tuning and
  classification decisions — so it is not admin-only.
- Users connect their own IMAP and SMTP account. They read and label their own
  mail, pair their own devices, set their own notification preferences, and tune
  their own prompt.
- Admins can also do the connecting. **Server > Default Mail Server** publishes
  host and port defaults that prefill every new user's Email Settings form; users
  still supply their own username and password. **Server > Manage Users > Mailbox**
  writes a specific user's IMAP/SMTP and CardDAV-client credentials directly, with
  an optional lock. A locked user still sees the host and username on their
  Settings > Mail tabs, rendered read-only with a "managed by your administrator"
  notice, and the server refuses their own writes. Send-As addresses, Mailbox
  Rules, and the built-in CardDAV Access password are never admin-managed. Every
  admin assignment is logged with `user_id`, `admin_id`, and `managed`.
- Deactivation is a soft delete. The user can no longer sign in. KyPost keeps
  their data on disk until you remove it manually.
- KyPost does not let you deactivate or demote the last active admin.

Per-user data layout:

- `/kypost/config/users/<userID>/`: encrypted IMAP credentials, `carddav-client.json` (encrypted CardDAV-client credentials), tuning prompt (`tuning.md`), notification preferences (`config.yaml`)
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
- `2525`: internal controlled SMTP listener only with `docker-compose.receiving.yml`; the overlay requires an explicit host address and port. See [receiver setup](docs/RECEIVING_SETUP.md).
- `11434`: Ollama API (not exposed by default in `docker-compose.yml`)

Container startup sets config, private-key and state volume roots to owner-only `0700` before bootstrap and services; host inspection or backups require the volume owner or appropriate operator privileges. Existing descendant permissions are retained.

Mail-domain setup adds no environment variables. Its public challenge and issuer are stored owner-only in `$CONFIG_DIR/native-domains.json`; preserve it with `users.json`, `sso-lifecycle.json`, `native-provisioning.json` and mailbox/state data during backup or rollback. Native issuer/source fields remain private in `users.json`. Each container start runs `kypost-server migrate-native` before the services to convert older native storage in place; it is a no-op without native files, and a failure keeps native mail refused while IMAP works. Roll back by restoring the pre-upgrade backup ([native provisioning](docs/NATIVE_PROVISIONING.md#storage-format-migration)).

## Environment Variables

- `KY_LOG_LEVEL`: `info` by default (`debug`, `warn`, `error` supported).
- `KYPOST_BACKUP_DEPOSIT_INTERVAL`: `24h`; `0` disables, otherwise 15 minutes–366 days.
- `KYPOST_BACKUP_DIR`: empty disables local copies; `/kypost/state/backups` or outside the data roots.
- `KYPOST_BACKUP_KEEP`: `7` local copies.
- `KYPOST_BACKUP_ALLOW_PRIVATE_RECOVERY`: `false`; explicit private-network opt-in.
- `KYPOST_BULK_BACKUP_REPOSITORY`: empty keeps mail databases in the capsule; `rest:https://…` (an append-only rest-server, recommended) or an absolute path outside the data roots and backup directory sends them to a restic repository. A local repository is writable by KyPost, so a compromised container could delete its snapshots.
- `KYPOST_RESTIC_BINARY`: `restic`; the restic executable (0.16.0 or newer).
- `KYPOST_BACKUP_SCRATCH_DIR`: empty uses `STATE_DIR/backup-scratch`; an absolute path outside the data roots for backup scratch when STATE_DIR lacks space for a copy of the mail plus a 10%/5 GiB reserve.

Common variables:

- The host-side setup wizard accepts `ENV_FILE` (default repository `.env`) for an owned regular mode-`0600` file. It saves public setup inputs only; provider/account credentials stay in the protected admin UI. This is a wizard input, not a backend setting.

- `KYPOST_NATIVE_MAIL` (default `false`): opt-in KyIdentity native provisioning and local mailbox API/polling. Requires domain proof; preserves existing IMAP accounts. Direct receiving qualification additionally requires `KYPOST_NATIVE_RECEIVING=true`; compose/client-PGP sending from the primary or an administrator-assigned alias requires the configured operator relay; pickup/system sending remains pending. See [native runtime setup and rollback](docs/NATIVE_PROVISIONING.md#opt-in-native-runtime).
- `KYPOST_MAILBOX_QUOTA_BYTES` (default 5 GiB, `5368709120`): every native mailbox's storage quota in bytes, 256 MiB to 1 TiB; other values refuse startup when `KYPOST_NATIVE_MAIL=true` (IMAP-only deployments ignore it). Applied to existing mailboxes by `migrate-native` at the next start; lowering it below a mailbox's usage refuses only that mailbox's new mail. Pair a real quota with `KYPOST_BULK_BACKUP_REPOSITORY`. See [mailbox quotas](docs/NATIVE_PROVISIONING.md#mailbox-quotas).
- `KYPOST_NATIVE_RECEIVING` (default `false`): controlled receiving commands and daemon import; requires native mail, domain proof, prepared users and explicit spool initialization. `receiving config` generates a bounded TLS-only receiver profile; STARTTLS-only reception refuses plaintext senders. `receiving cloudflare route|pickup` supports the separate [one-message hosted pilot](docs/CLOUDFLARE_RECEIVING.md). `receiving quarantine list|release|release-to-current-owner|discard` lists quarantined deliveries (envelope only) and releases one to its frozen mailbox (or, if unresolved, to its address's current owner) or discards it, with the delivery ID repeated after `--confirm`; run it as the state owner (`docker compose exec --user kypost kypost-server kypost-server receiving quarantine list`). Mail waiting for a disabled mailbox or an offboarded or promoted owner is quarantined rather than retried forever ([quarantine release](docs/NATIVE_PROVISIONING.md#quarantine-release)). `receiving blocks list|add|remove` manages manual sender blocks (address or exact domain, optional `--until`, the value repeated after `--confirm`), enforced by both receiving profiles before storage ([sender blocks](docs/NATIVE_PROVISIONING.md#sender-blocks)). No bundled receiver starts. Read [controlled setup and gates](docs/RECEIVING_SETUP.md).
- `KYPOST_RECEIVING_RSPAMD` (default `false`): strict opt-in local spam scanning before new native SMTP acceptance; scanner failure returns a temporary refusal. The Rspamd overlay enables it and Cloudflare pickup requires it; the hosted path uses content/DKIM checks without unavailable peer authentication and retains provider copies on refusal. Existing accepted obligations remain recoverable without rescanning.
- `KYPOST_CLOUDFLARE_RECEIVING_ORIGIN` (default empty, off): the continuous Cloudflare profile's Worker origin, `https://<worker>.<account>.workers.dev`. Requires `KYPOST_NATIVE_RECEIVING=true` and `KYPOST_RECEIVING_RSPAMD=true`, and refuses startup beside the bundled receiver (`KYPOST_NATIVE_RECEIVER=true`). `receiving cloudflare init` creates the credentials and prints the two Worker secrets; `receiving cloudflare rotate`, `takeover --confirm move-receiving-here` and `status` manage them. See [continuous Cloudflare profile](docs/RECEIVING_SETUP.md#continuous-cloudflare-profile).
- `KYPOST_NATIVE_RESTORE_RELEASE` (default `false`): enables `POST /api/admin/native-recovery/release`, which releases a qualified, repaired native restore hold; other values refuse startup. Off, the route answers 404. Enable it only for a deliberate release until the pending qualifications are done ([releasing the hold](docs/RESTORE.md#releasing-the-hold)).
- `KYPOST_NATIVE_RECEIVER` (image default `false`): optional Supervisor receiver startup; requires both native flags above, prepared storage, current proof and operator-owned engine/TLS files. The receiving overlay enables it explicitly.
- Receiver launcher inputs: `KYPOST_RECEIVER_BINARY` (default `/opt/kypost/receiving/maddy`), `KYPOST_RECEIVING_LISTEN` (`0.0.0.0:2525`), required `KYPOST_RECEIVING_HOSTNAME`, `KYPOST_RECEIVING_CERT` (`/opt/kypost/receiving/tls/fullchain.pem`) and `KYPOST_RECEIVING_KEY` (`/opt/kypost/receiving/tls/privkey.pem`). Compose overlay inputs `KYPOST_MADDY_BINARY`, `KYPOST_RECEIVING_TLS_DIR`, `KYPOST_SMTP_BIND` and `KYPOST_SMTP_PORT` are required with no defaults. Follow [setup order and rollback](docs/RECEIVING_SETUP.md#optional-supervised-container-profile).
- `WEB_PORT` (default `5866`)
- `TZ` (default `America/New_York`)
- `SECRET_DIR` (default `/kypost/private`. Every `*_KEY_FILE` / `*_SECRET_FILE` default below is derived from this, so moving it moves all of them together.)
- Domain relay configuration uses `$CONFIG_DIR/native-relay.json` and `$SECRET_DIR/native-relay.key`, with no individual path overrides or environment credentials. Its retained key also derives owner/job-bound outbox encryption keys. Configure through the protected admin API; primary native compose/client-PGP sending uses fresh authority and the durable outbox.
- `OLLAMA_BASE_URL` (default `http://127.0.0.1:11434`)
- `OLLAMA_MODEL` (default `nemotron-3-nano:4b`; see the model note below)
- `CLASSIFIER_ENGINE` (default `hybrid`: the embedding sorter answers when sure, the LLM otherwise; `llm` sends everything to the LLM. Any other value refuses to start.)
- `EMBED_MIN_CONFIDENCE` (default `0.6`; how sure the embedding sorter must be, 0–1, to label without the LLM)
- `EMBED_MODEL_DIR` (default `/opt/kypost/models/potion-base-8M`, installed by the Dockerfile. A missing or unreadable model is logged as an error and the daemon runs LLM-only.)
- `TUNING_FILE` (default `/kypost/config/TUNING.md`)
- `OLLAMA_MODELS_HOST_DIR` (default `./share/ollama/models`)
- `IMAP_CONFIG_FILE` (default `$SECRET_DIR/imap-config.json`)
- `IMAP_CONFIG_KEY_FILE` (default `$SECRET_DIR/imap-config.key`)
- `TOTP_SECRET_KEY_FILE` (default `$SECRET_DIR/totp-secret.key`)
- `SERVER_BASE_URL` (**required for mobile pairing, desktop pairing and Single Sign-On**; recommended always. KyPost embeds this public URL as `srv` in the QR code and uses it to build `reg`, and it is the OIDC `redirect_uri`. Every one of those URLs is where a credential gets sent, so it is never derived from the request's `Host` header — leave it unset and those three features refuse with an error naming it. Pickup links and PGP QR key-exchange URLs fall back to `http://localhost:5866`, which works only on the server itself.)
- `PAIRING_SECRET` (optional. HMAC secret for pickup links, PGP QR key exchange and mobile pairing tokens. Generated automatically on first start and persisted at `PAIRING_SECRET_FILE` — set it only if several replicas must share one secret, and use `openssl rand -base64 32` if you do. A value shorter than 32 bytes is refused and those three features stay disabled, with the reason logged. Bytes, not characters, because the value is used as the HMAC key verbatim; for the ASCII `openssl rand -base64 32` produces they are the same number.)
- `PAIRING_SECRET_FILE` (default `$SECRET_DIR/pairing.key`)
- `REVIEW_PAIRING_USERNAME` (optional, default empty. Enables password-based fast pairing for a disposable Google Play review account at `POST /api/notifications/review-pairing`. A trailing `*`, such as `your-demo-username*`, admits usernames with that prefix; bare `*` is refused. Leave unset on normal servers; MFA and forced-password-change accounts are refused.)
- `PUSH_RELAY_URL` (optional. Base URL of the central push relay Worker that delivers Android native push to FCM. Must be `https://` — the relay key travels on every request — except for loopback.)
- `PUSH_RELAY_KEY` (optional override. Setting `PUSH_RELAY_URL` alone is enough: the server self-registers with the relay on first start and persists the key it is issued at `$SECRET_DIR/push_relay_key`. Set this only to pin a key the operator issued you, or when several servers share one public IP — the relay keeps one active key per address, so the newest registration displaces the previous one.)
- `APNS_RELAY_URL` (optional. Base URL of the central APNs relay Worker that delivers iOS native push. Must be `https://` — the relay key travels on every request — except for loopback.)
- `APNS_RELAY_KEY` (optional override, exactly as `PUSH_RELAY_KEY` above, persisted at `$SECRET_DIR/apns_relay_key`.)
- `ALLOW_INSECURE_SMTP` (optional, default off. KyPost **requires** STARTTLS on SMTP submission and refuses to send if the server does not offer it. Opportunistic STARTTLS is not enough: the capability is advertised by the server, so an on-path attacker strips it from the EHLO response and the session continues in cleartext with the full message and the password. Set this to `true` only for a genuinely plaintext relay on a trusted LAN. There is deliberately no per-request or per-account way to set it — a downgrade has to be a deployment decision, not something a caller or a remote server can trigger.)
- `CAPTCHA_PROVIDER` (optional. Set `pow`, `turnstile`, or `friendly` to require a CAPTCHA solution on login. It works together with the built-in lockout of 3 strikes and 15 minutes.)
  - `pow` is self-hosted proof-of-work: the only provider that makes no third-party network call and adds no third-party origin to the CSP. It requires no account with anyone and no keys to obtain — the signing key is generated on first use at `POW_SECRET_FILE`. **It requires HTTPS**: the browser half uses `crypto.subtle`, which browsers expose only in a secure context, so on a plain-`http://` deployment (anything but `localhost`) the check cannot run and nobody can sign in — put TLS in front of the server, as the note in Quick start says to anyway, or pick another provider. Its difficulty adapts per client IP: an honest first login solves the cheap base challenge in a blink, and each recent failed login from the same address multiplies the next challenge's difficulty, up to a ceiling, decaying after 15 minutes or on a successful login. Each challenge is bound to the address that requested it — the address is signed into the challenge and re-checked when the solution arrives — so the escalation cannot be sidestepped by fetching cheap challenges from a clean address and spending them from an escalated one. (If your own address changes mid-check, say a phone moving from wifi to cellular, the sign-in page tells you to try again and costs you no lockout strike.) Escalation is still counted per address, so an attacker spraying from many addresses gets the base difficulty at each: it prices repetition, not a distributed attacker. An attacker running native code is also one to two orders of magnitude faster than a browser, so this deters casual scripted spraying, not a determined campaign. It does **not** replace the three-strikes lockout, which remains the real brute-force defence. Multi-replica deployments must set `POW_SECRET` so every replica agrees on one signing key — generate it with `openssl rand -base64 32`; anything shorter than 16 characters is refused and the login CAPTCHA then rejects every attempt.
  - `turnstile` and `friendly` verify a token against a third-party siteverify endpoint and need a site key + secret key.
- `CAPTCHA_SITE_KEY` and `CAPTCHA_SECRET_KEY` (required together with `CAPTCHA_PROVIDER=turnstile` or `friendly`; not used by `pow`. The site key is public. The server verifies solutions with the secret key.)
- `POW_MAX_NUMBER`, `POW_SECRET_FILE`, `POW_SECRET` (optional, `CAPTCHA_PROVIDER=pow` only — see `.env.example` for tuning notes)

Less common variables:

- `SMTP_HOST`, `SMTP_PORT` (instance-wide fallbacks used only when an account's
  own IMAP config names no SMTP host or port. Resolution order is: the account's
  saved SMTP settings, then these, then the IMAP host with a leading `imap.` (or
  an embedded `.imap.`) rewritten to `smtp.` — and the IMAP host unchanged if it
  matches neither. The port falls back to `587`.)
- `CLASSIFIER_BASE_URL`, `OLLAMA_API_KEY`, `OLLAMA_GENERATE_PATH` (point the
  classifier at something other than the bundled Ollama — a shared instance, or
  any endpoint that speaks the same generate API. `OLLAMA_BASE_URL` wins if both
  it and `CLASSIFIER_BASE_URL` are set; `OLLAMA_GENERATE_PATH` defaults to
  `/api/generate`; `OLLAMA_API_KEY` is sent as a bearer token when set.
  **A remote classifier receives your mail.** Every message body goes to it after
  redaction, so a non-loopback plaintext endpoint puts that mail — and the API
  key — on the wire in the clear. The server logs an error once per boot when the
  endpoint fails that transport policy, but classification continues, because
  refusing to start a mail server over a variable the operator set deliberately
  is the worse outcome. Use `https://` for anything off-host.)
- `UNHEALTHY_RESTART_SECONDS` (default `300`. How long health may stay red before
  the process exits and lets supervisord and the Docker restart policy bring it
  back.)
- `PGP_PRIVATE_KEY_FILE` (default `$SECRET_DIR/pgp-private-key.key`) and
  `PICKUP_STORE_KEY_FILE` (default `$SECRET_DIR/pickup-store.key`) — the two
  remaining `SECRET_DIR`-derived secret paths.
- `FRONTEND_DIR` (default `/opt/kypost/frontend`. Where the API server reads the
  built SPA from; there is no reason to change it inside the shipped image.)
- `MFA_CLEAR_ALL` (recovery only. Clears two-factor enrollment for **every**
  account on the next boot, then writes a marker so it never runs twice — see
  `.env.example` before using it.)

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
- Required: set `SERVER_BASE_URL` so that QR code payloads point to the correct public backend URL. Use an `https://` URL: pairing tokens, pickup links and QR key-exchange URLs are all built from it, and each carries a bearer credential in the query string. Unset, the pairing panel reports "set SERVER_BASE_URL" and mints no token — the address a credential is sent to is not something a request's `Host` header may choose, and there is no safe guess. It is also what the pairing QR's certificate pin is read from. See the TLS note in Quick Start and [Certificate pinning](#certificate-pinning-in-the-pairing-qr) below.
- Keep all pairing secrets on the server only.

Desktop pairing behavior:

- Security's Devices tab renders a QR code link with `sub`, `hash`, `srv`, `reg`, `pt`, and — when the serving certificate can be read — `pin`.
- Set `SERVER_BASE_URL` in `.env`. Then `srv` and `reg` always point to the deployment address that the mobile app must use. Nobody enters a server URL by hand.
- `pt` is a signed pairing token. It is valid for 90 seconds.
- The UI shows a 4px countdown bar under the QR code. The bar shrinks over 90 seconds and changes from green to red. It is red for the last 15 seconds.
- The mobile app scans the QR code and registers its push token through `reg`. If `reg` is absent, the app uses `srv` plus `/api/notifications/native/register` instead.

### Certificate pinning in the pairing QR

The pairing request is the one call that carries the pairing token, the push
endpoint and the app's WebPush keys. Without a pin the app sends all of it and
only *then* decides whether to trust the certificate it just used. On a network
with a locally trusted CA — an MDM root, a certificate someone installed, a
captive portal — an interceptor reads the token, registers its own device
against your server first, and hands the app back credentials it controls.

So the QR carries `pin`: the SHA-256 of your serving certificate's public key.
The app pins the registration handshake to that one key *before* it sends
anything, and refuses a certificate that does not match.

**Set `SERVER_BASE_URL` to your public `https://` URL and this works with no
further configuration.** At the moment it builds each QR, the server makes a
verified TLS connection to that URL and reads the certificate you are actually
serving — whether that is Caddy, Traefik, nginx-proxy-manager, a Cloudflare
tunnel, or this server's own `TLS_CERT_FILE`. Because it is read fresh every
time, certificate renewal needs no action from you.

Two things worth knowing:

- **Behind a proxy, you are pinned to the proxy.** With Cloudflare in front,
  this closes the hostile-network hole between the phone and Cloudflare. It does
  not make the tunnel end to end; Cloudflare still terminates TLS.
- **A private or self-signed CA gets no pin.** The server will not tell the app
  "trust only this key" on the word of a certificate it could not verify. Use
  `TLS_CERT_FILE`/`TLS_KEY_FILE` to terminate TLS here instead, and the pin is
  read from that certificate directly.

A probe failure — an unreachable URL, a router that will not route your public
hostname back to itself — simply omits `pin`, and pairing proceeds on trust on
first use. It never breaks a pairing; it only declines to protect one.
Already-paired devices are unaffected. A missing `SERVER_BASE_URL` is the one
case that is not merely unpinned: there is then no address to put in the QR at
all, so pairing refuses rather than guessing one from the request.

Native registration behavior:

- `POST /api/notifications/native/register` validates the pairing token. It stores the native device metadata and token in the backend state.
- `GET /api/notifications/native/devices` lists the paired native devices and their reported enrollment envelope versions. Older devices default to v2; webmail refuses setup for devices that require a newer format. V3 delivery and conversion remain gated.
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

Self-hosters set one variable and the server does the rest — it registers itself
with the relay on first start, over its public `/register` endpoint, and persists
the key it is issued under `SECRET_DIR`. No operator involvement, no ticket, no
waiting.

- Android: set `PUSH_RELAY_URL` (Firebase relay)
- iOS: set `APNS_RELAY_URL` (APNs relay)

The server looks for a key in three places, in order: the `PUSH_RELAY_KEY` /
`APNS_RELAY_KEY` environment variable, then the key file from a previous
registration, and only then does it register. So restarts reuse the key on disk
rather than minting a new one.

Two things are worth knowing before you rely on it:

- **The relay keeps one active key per public IP address.** Two self-hosted
  servers behind the same address will take the key from each other, newest
  registration wins, and the displaced server's push silently stops working. If
  that is your setup, ask the operator for keys and pin them with
  `PUSH_RELAY_KEY` / `APNS_RELAY_KEY` instead.
- **Registration can be closed.** The operator can turn `/register` off — for
  abuse, or cost. If it is closed, the server logs the refusal and native push
  stays off; `App Pull` delivery works regardless and needs no relay at all.

Self-hosters need no Firebase account and no Apple Developer account. You never recompile the app.

Relay operators deploy both Workers and can still mint keys by hand. See [`worker/README.md`](worker/README.md) and [`worker-apns/README.md`](worker-apns/README.md) for setup, secrets, and key management.

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
- `/kypost/config/users/<userID>/` (per-user IMAP credentials, CardDAV-client credentials, tuning, notification preferences)
- `/kypost/config/mail-defaults.json` (admin-published instance-wide host and port defaults, no credentials)
- `/kypost/config/sso-lifecycle.json` (accepted SSO logout tokens, directory revision/access fences, verified SCIM desired resources and the native-provisioning initialization fence; temporary replay records expire)
- `/kypost/config/native-provisioning.json` (internal account, mailbox and address ledger, version 2: reservations, preparation status and address generations; keep with lifecycle and mailbox/state data during recovery; provisioning is opt-in via KYPOST_NATIVE_MAIL)
- `/kypost/config/native-domains.json` (verified mail domain set and public challenges); `native-domain.json` is the tombstone of the older single-domain file, and `*.v1-migrated` are the older files kept by the startup migration (not backed up)
- `/kypost/config/TUNING.md` (default tuning for new users)
- `/kypost/config/notifications-vapid-private.pem` (shared web-push signing key)
- `/kypost/private/imap-config.key` (master encryption key for stored IMAP credentials)
- `/kypost/private/totp-secret.key` (master encryption key for stored TOTP secrets)
- `/kypost/state/state.db` (global state: AI-credits flag)
- `/kypost/state/users/<userID>/state.db` (per-user mailbox state, decisions, devices, subscriptions)
- `/kypost/state/mailboxes/<mailboxID>/` (an administrator-created extra native mailbox: `native-mailbox.json`, `mailbox/mailbox.db` and a mail-only `state.db`; devices and subscriptions stay with the owner's primary)
- `/kypost/config/admin.env` (legacy single-admin seed. KyPost imports it once, then stops reading it.)

## Backup and Restore

For sealed capsules, pairing, scheduling and offline recovery, follow [docs/RESTORE.md](docs/RESTORE.md). The manual volume procedure below produces an unencrypted archive and requires secure storage.

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

Shutdown can take up to 36 minutes when both API and daemon are draining work: Supervisor stops their groups sequentially. Compose supplies that budget; give external orchestrators the same allowance. Idle services exit promptly. See [sealed backup shutdown](docs/RESTORE.md).

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

- Admin backup routes: `GET /api/admin/backup/status`; `POST` to `run`, `export-capsule`, `drill`, `pair-remote`, `pin-key`; `DELETE pairing`; `PUT schedule` under `/api/admin/backup/`. Mutations require the current account credential and CSRF protection, or, for a session signed in through KySignOn, a fresh KySignOn confirmation of that exact action.

Auth:

- `POST /api/auth/login`
- `GET /api/auth/login-params` — the per-account salt and work factor a client
  needs to derive its auth secret, so the password is never transmitted. Public,
  and deliberately answers identically for a username that does not exist.
- `GET /api/auth/captcha-config`
- `GET /api/auth/pow-challenge` (`CAPTCHA_PROVIDER=pow` only)
- `GET /api/auth/csrf`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `GET|POST /api/auth/password` (read a private password-change snapshot, then atomically commit credential and optional PGP rewrap; forced resets preserve the previous sealed key for recovery)
- `POST /api/auth/step-up` (re-confirms the password, and a second factor when one is enrolled, before the Security page renders; a session signed in through KySignOn confirms with KySignOn instead, see below)

Single Sign-On (OpenID Connect):

- `GET /api/auth/sso-config` — public `{enabled, issuerUrl, clientId}` that gates the sign-in button and native sign-on. Never returns the client secret.
- `POST /api/auth/native/signon` — body `{idToken}`: a KyIdentity device-grant ID token, refused unless its `origin` claim matches `SERVER_BASE_URL`. Requires SSO plus `PAIRING_SECRET` and `SERVER_BASE_URL`, otherwise 503. Answers the same single-use 90-second pairing deep link as review-pairing.
- `GET /api/auth/oidc/login` (alias `/auth/sso/login`) — starts the authorization-code flow for signing in.
- `POST /api/settings/sso/link` — links the provider identity to the *caller's own* account. Requires the account password (and the two-factor code, when one is enrolled) re-entered now, because a linked identity is a way to sign in.
- `GET /api/auth/oidc/callback` (alias `/auth/sso/callback`) — verifies the ID token, including a positive issuance timestamp no more than 30 seconds ahead of the server, then signs in, auto-provisions, or links by `sub`. Keep issuer/server clocks synchronized. The session remembers the provider's `sid`, so the provider can end it.
- `POST /api/auth/oidc/step-up`, `GET|DELETE /api/auth/oidc/step-up/{id}` — action-bound re-authentication for a session signed in through KySignOn. A sensitive request (the Security page gate, backup actions) answers `403 {"error":"sso_step_up_required","challenge":…}`; the browser opens a KySignOn sign-in popup for that one action (`prompt=login`), and repeats the request with `X-Kypost-Step-Up: <challenge>` once it is verified. The grant is spent once, for that request only.
- `POST /api/auth/oidc/backchannel-logout` — OpenID Connect back-channel logout receiver. Register it at the provider (KySignOn: the client's *back-channel logout URI*). The `logout_token` is verified against the issuer's JWKS, admitted once durably, and ends the session it names, or every session of the subject when it names none. Needs an `https` issuer.
- `POST /api/settings/sso/unlink`
- `GET|PUT /api/admin/sso` (admin only. The provider configuration.)
- `POST /api/sync/webhook` — KySignOn directory push. Pair KyPost in KySignOn as a webhook system with this URL and either the pairing secret or the SSO client secret as the sync secret. Each event is a signed, versioned SCIM User; stale or reordered deliveries are refused, a disabled or deleted user keeps their mailbox and loses access, and a rehire brings the same account back. Supported SCIM fields are retained durably alongside the revision fence for later repair; acknowledgment does not mean a domain mailbox or receiver route is ready.

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
- `GET|PUT|DELETE /api/users/{id}/imap-config` (assign a user's IMAP/SMTP credentials; `managed: true` locks the user's own route)
- `GET|PUT|DELETE /api/users/{id}/carddav-client` (same for the outbound CardDAV client)

Runtime:

- `GET /api/status`
- `GET /api/health`
- `GET /healthz` (public `ky.health/1` status for KyPulse: 200 `ok` or 503 `down`; one cached `service` check covers the API and daemon without exposing mailbox, version, or failure details. `/api/health` keeps its existing detailed response.)
- `POST /api/health/repair` (admin only)
- `POST /api/admin/mail/poll-now` (admin only. Starts an immediate poll.)
- `GET /api/setup` (reports whether the initial admin setup completed)
- `GET /api/server/version` (the running version and whether a newer release exists)
- `GET /api/ollama/version` (the classifier runtime's version)
- `GET /pickup/{id}?t=<token>` (single-use mobile pickup link), plus `POST /pickup/{id}/open` and `POST /pickup/{id}/blob` for a client-sealed pickup

Config and data:

- `GET /api/mail/outbox/{id}` — session/device-authenticated native delivery state for the acting owner, with attempts/retry timing and Sent status; no MIME or credentials. Native send replies add `outboxId`; success still requires confirmed primary SMTP acceptance. Inspect uncertain jobs before resubmitting. See [outbox contract](docs/NATIVE_OUTBOX.md).
- `GET|PUT /api/admin/mail-relay` — admin-only encrypted domain relay settings. PUT accepts `{host,port,smtpUsername,smtpPassword,domains?,password}` (or `authSecret` for account confirmation), requires CSRF/request-bound step-up and fresh issuer-bound DNS proof of every newly added relay domain and of at least one domain overall, and defaults port to 465. Omitted `domains` keeps the saved set (the founding domain for a new relay); a body with only `domains` changes the set and keeps the generation; removing a domain with queued or retryable jobs is refused and moves it to `retiredDomains`. Responses redact both relay credentials and report configured native capability in `sendingEnabled` (not provider readiness); this native profile requires verified implicit TLS and AUTH. See [relay contract](docs/DOMAIN_RELAY.md).
- `POST /api/admin/mail-relay/test` — admin-confirmed no-mail check of the saved `expectedGeneration`, using the same strict TLS/AUTH policy as delivery. Fresh domain/issuer and restore gates run before and after connection; one check per instance per 30 seconds. No MAIL/RCPT/DATA or outbox writes; success reports `deliveryTested:false` and proves neither From authorization nor inbox placement. See [check contract](docs/DOMAIN_RELAY.md#check-the-saved-relay-without-sending-mail).

- `GET|PUT /api/config` (GET omits `redaction.patterns` for non-admins; PUT is admin only)
- `GET /api/labels`
- `GET|PUT /api/labels/preferences` (the caller's own label list, auto-apply preference and optional label descriptions for the embedding sorter. `PUT` replaces the whole block.)
- `GET /api/decisions` (the caller's own decisions)
- `GET|PUT /api/tuning` (the caller's own tuning prompt)
- `GET /api/mail-defaults` (any user) / `PUT /api/mail-defaults` (admin): instance-wide host and port defaults, no credentials

IMAP and inbox:

- `GET|POST|DELETE /api/imap/config`, returns 403 while `managed`
- `POST /api/imap/test`
- `GET /api/inbox?limit=500&mailbox=<name>`. Add `bodies=0` to get the list without message bodies — 13.3 MiB against 3.1 KiB for a 500-message window, since the rows render no body. The web UI then preloads the current 20-message page one body at a time from `GET /api/mail/body`, so the list renders first and opening a displayed message normally needs no wait. See [docs/INBOX_PAYLOAD_HANDOFF.md](docs/INBOX_PAYLOAD_HANDOFF.md). Add `before=<messageId>` for the next page of older mail (metadata only, with `hasMore`/`nextBefore`); see [docs/PLATFORM_BASELINE.md](docs/PLATFORM_BASELINE.md) §7.
- `POST /api/admin/native-recovery/challenge` and `/api/admin/native-recovery/evidence` — administrator CSRF and exact-action confirmation bind one signed KyIdentity export to a usable restore epoch and complete retained subjects. Import preserves the hold and account state while installing durable revision barriers only for unpublished native reservations; published accounts retain ordinary offboarding/demotion. It grants no recovery readiness. See [protected recovery procedure](docs/NATIVE_RESTORE_AUTHORITY.md#protected-consumer-procedure).
- `GET /api/admin/native-recovery/status` — administrator, read-only: each native restore hold release precondition with its reasons, the `KYPOST_NATIVE_RESTORE_RELEASE` flag, Cloudflare fence state and ordered next steps; never evidence contents. `kypost-server restore status`, run as the `STATE_DIR` owner, prints the same. See [reading release status](docs/RESTORE.md#reading-release-status).
- `POST /api/admin/native-recovery/repair` — separately confirmed administrator repair using the current stored signed evidence. Reconciles existing native activity/roles, persists replay barriers before account writes, and revokes sessions, device/push, pairing and CardDAV credentials before recording completion. Legacy accounts and retained mail/PGP data are preserved. Partial failures keep the restore held and require fresh evidence; success also preserves the hold. See [protected recovery procedure](docs/NATIVE_RESTORE_AUTHORITY.md#protected-consumer-procedure).
- `POST /api/admin/native-recovery/release` — off unless `KYPOST_NATIVE_RESTORE_RELEASE=true`. An unlinked local administrator on a password session confirms the credential; the server rechecks every release precondition under its fences and a fresh DNS proof, and on the bundled-receiver profile requires `"confirm": "original-host-decommissioned"`. It deactivates non-native accounts the evidence shows inactive, demotes non-native administrators it shows without the administrator role, writes release floors and ID-token fences, then renames the hold to `native-restore-released.json`. A repeat answers `alreadyReleased`. See [releasing the hold](docs/RESTORE.md#releasing-the-hold).
- `GET|PUT /api/admin/mail-domain` and `POST /api/admin/mail-domain/verify` — admin-only mail-domain diagnostics/setup. Writes require CSRF and the current account credential (KySignOn uses request-bound step-up). Configure `{domain,password}` or `{domain,authSecret}` after KyIdentity pairing, publish the returned exact TXT record, then verify with the same credential fields. These routes serve the founding domain. DNS proof binds one immutable domain/issuer, initial verification expires after 24 hours, and configuring again rotates the challenge. Once established, the same TXT record is rechecked automatically without daily DNS changes. System DNS is not DNSSEC; every allocation rechecks it. Explicit KYPOST_NATIVE_MAIL=true enables provisioning and local mailbox access after verified directory assignment; verification alone enables no reception or sending. See [setup and failure responses](docs/NATIVE_PROVISIONING.md).
- `GET|POST /api/admin/mail-domains`, `POST /api/admin/mail-domains/{domain}/verify` and `DELETE /api/admin/mail-domains/{domain}` — admin-only domain set: list per-domain status (`configured`, `retired`, `recordName`, `recordValue`, `established`, `expiresAt`, `verifiedUntil`), add a domain or rotate its challenge with `{domain}`, verify one domain, and retire one (409 while an address on it is active, a queued/retryable outbox job sends from it, accepted (pending) incoming mail is bound to it or the relay still sends for it; address records are kept; re-adding a retired domain configures it afresh, and its addresses resume for their recorded mailboxes once it verifies again). Same CSRF, credential and step-up rules as the single-domain routes; each proof fences only its own domain. See [several domains](docs/NATIVE_PROVISIONING.md#several-domains).
- `GET|POST /api/admin/mail-addresses`, `DELETE /api/admin/mail-addresses/{address}` and `POST /api/admin/mail-addresses/{address}/reassign` — admin-only native aliases: list mailboxes and their addresses (`address`, `kind`, `state`, `generation`; `?user=<id>` filters) with each mailbox's `usedBytes`/`quotaBytes` and a `storage` summary of quotas against the drive (`overcommitted` above 80%), add an alias with `{mailbox,address}` to an everyday identity's mailbox on a configured domain, release one (kept as `reserved`, never deleted) and reassign a reserved one with `{mailbox}`. Each change of owner or state moves the address to a new generation, so mail or outbox jobs frozen against an older one are quarantined, never delivered; ordinary KyIdentity edits change no generation. 400 malformed, 404 unknown, 409 taken/reserved/primary/a KyIdentity primary/administrator owner/unconfigured domain/restore hold; a committed change whose receiving-route update is still pending answers 200 with a `warning`. Same CSRF, credential and step-up rules as the domain routes. Users send from an active alias by naming it in `from`. See [addresses](docs/NATIVE_PROVISIONING.md#addresses-aliases-and-generations).
- `GET|POST /api/admin/mailboxes`, `POST /api/admin/mailboxes/{id}/disable` and `POST /api/admin/mailboxes/{id}/enable` — admin-only extra native mailboxes: list mailboxes with `kind` and `state` (`?user=<id>` filters), create one for an everyday identity with `{user,address}` (its primary address on an established domain, unique and not any KyIdentity primary; stored under `$STATE_DIR/mailboxes/`), and disable or re-enable it (mail is kept; its addresses stop routing and sending; jobs still queued in its outbox are quarantined). Listings carry `prepared`. Creation is 409 while the owner has incoming encryption on, and enabling incoming encryption is 409 while the user has an extra mailbox: it covers the primary only. Same gates and error mapping as the alias routes. See [extra mailboxes](docs/NATIVE_PROVISIONING.md#extra-mailboxes).
- `GET /api/admin/receiving/cloudflare` — admin-only continuous Cloudflare receiving status: `running`, `fenced`, `error`, `uninitialized` or `not-started`, last published revision, last publish and pickup times, oldest waiting capture and its one-hour warning, waiting and ledger counts. Never addresses, envelopes or credentials.
- `GET /api/admin/receiving/quarantine[?after=<sequence>]`, `POST /api/admin/receiving/quarantine/{gateway}/{id}/release` and `POST /api/admin/receiving/quarantine/{gateway}/{id}/discard` — admin-only quarantined native deliveries: list up to 100 envelopes (gateway, ID, received time, envelope sender, size, and per recipient the address, frozen mailbox, owning user and generation; never body, subject or headers), release one to the mailboxes it was frozen to (refused with 409 and the reason when a frozen mailbox was deleted or disabled, changed owner or is no longer admitted; never to an address's current owner), or discard it (bytes removed, a tombstone blocks redelivery; `partially_released` when an interrupted release may already have reached some mailboxes). Release refusals say whether the cause is durable (discard remains) or transient (resync and retry). An `unresolved` delivery (continuous Cloudflare mail captured under a routing table this server does not know, typically after a restore) lists its address's owner today (`currentMailbox`, `currentUser`) and is released only with `{"toCurrentOwner": true, "currentMailbox": "<as listed>"}` to that owner (refused if the address moved since it was listed), not proven to be the original, while the address is active; that action is audited separately. POSTs need CSRF and the account credential or KySignOn step-up; every action is audited without content. See [quarantine release](docs/NATIVE_PROVISIONING.md#quarantine-release).
- `GET|POST /api/admin/receiving/blocks` and `DELETE /api/admin/receiving/blocks/{id}` — admin-only sender blocks for both receiving profiles: list blocks in force (`id`, `kind`, `value`, `until` in Unix ms or null, `source` `manual` or `automatic`, `level`, `createdAt`, `actor`, `reason`) plus automatic-block `evidence` status (`damaged`, `resetAt`, `domainBlocksFrom`, `goodFull`, `automaticFull`), block an `address` or `domain` with `{kind,value,until?,reason?}` (reason `spam`, `phishing`, `abuse` or `other`; any sender either profile accepts, A-Z lowercased and non-ASCII compared exactly, A-labels for internationalized domains; domains match exactly, not subdomains; your own mail domains and addresses on them are refused with 409, and adding a mail domain a block matches is refused until you unblock it; at most 5000), or unblock one by its listed `id` (so proxy logs never record a blocked address; this also stops automatic re-blocking of it for 30 days; if that cannot be recorded the block is still removed and the answer carries a `warning`). Maddy answers blocked senders `550 5.7.1` at RCPT; the Cloudflare Worker rejects them from the signed table, republished within seconds. Already accepted mail is unaffected and the null sender is never blocked. POST and DELETE need CSRF and the account credential or KySignOn step-up; audited with the block ID, never the address. See [sender blocks](docs/NATIVE_PROVISIONING.md#sender-blocks).
- `GET /api/mailboxes` — the caller's accessible native mailboxes (primary first) and their active addresses, with `usedBytes` (absent when unreadable) and `quotaBytes`; disabled ones are omitted. Mail routes accept an optional `X-KyPost-Mailbox` header naming one of them (absent means the primary, so older clients are unchanged); unknown, foreign and disabled mailboxes all answer the same 404. Per-user routes ignore the header, and native notifications carry the mailbox ID. See [mailbox selection](docs/PLATFORM_BASELINE.md#native-mailbox-selection-additive).
- `GET /api/export/folders`, `POST /api/export` and `GET /api/export/{token}` — self-service export of the caller's own native mailbox or one folder as mboxrd or a zip of EML files, exact stored bytes (encrypted mail stays encrypted). The POST needs a browser session, CSRF and account or KySignOn confirmation and returns a single-use download link valid for five minutes, bound to that session, with the message count; the GET streams it as an attachment, or redirects back to Security → Export Mail with a reason. mbox needs HTTP/1.1 to the server. External IMAP accounts get 409. See [mail export](docs/NATIVE_PROVISIONING.md#mail-export)
- `POST /api/import`, `POST /api/import/{token}`, `GET /api/import` and `POST /api/import/cancel` — self-service import of mbox, EML or a zip of EML files into the caller's own native mailbox. The first POST needs a browser session, CSRF and account or KySignOn confirmation, creates the target folder (default `Imported`) and returns a single-use upload link valid for five minutes in that session; the upload streams the raw file (at most the mailbox's storage quota) to a temp file and starts a background job answering 202. `GET` reports `{state, imported, duplicates, skipped, bytes, error}` and the size limits. One import per user and two per server; 409 for external IMAP accounts and while incoming encryption is on. See [mail import](docs/NATIVE_PROVISIONING.md#mail-import)
- `POST /api/import/imap`, `POST /api/import/imap/{token}/folders` and `POST /api/import/imap/{token}/start` — self-service import from another mail account over IMAP into the caller's own native mailbox. The first POST takes `{mailbox, host, port, security, username}` plus the account or KySignOn confirmation (never the provider password) and mints a 10-minute grant for that session; `.../folders` takes `{password}`, signs in (TLS on 993 or STARTTLS on 143, certificate always verified; private, loopback, link-local and CGNAT addresses refused) and lists the folders; `.../start` takes `{folders, target}` (default `Imported/<host>`) and answers 202. Read-only on the provider (EXAMINE, BODY.PEEK); the password is held in memory only until the job signs in. Failed sign-ins are limited per user (six an hour, then 429), at most four listings connect at once (503), and a job's connection reads at most twice the mailbox's storage. Status and cancel are `GET /api/import` and `POST /api/import/cancel`. See [import from another mail account](docs/NATIVE_PROVISIONING.md#import-from-another-mail-account)
- Internal native provisioning records durable reservations and pending/applied/failed preparation status from verified directory state. Admin domain challenge/verification routes are available; KYPOST_NATIVE_MAIL=true enables new-account allocation, retained-work retries and API/daemon local mailbox selection. Direct receiving commands/import and TLS-only profile generation additionally require KYPOST_NATIVE_RECEIVING=true; mandatory STARTTLS refuses plaintext senders and no bundled public receiver starts. See [controlled receiver setup](docs/RECEIVING_SETUP.md). Native sending (primary or an owned active alias) additionally requires the configured relay; pickup/system sending remains pending and restore-hold release is off by default (`KYPOST_NATIVE_RESTORE_RELEASE`). See [provisioning contract](docs/NATIVE_PROVISIONING.md).
- Mail state/configuration failures return an explicit error instead of an empty inbox. Internal native-mailbox qualification rejects source mismatches with 409; switching remains disabled, and native inbox responses are full snapshots (`delta:false`, `cursor:0`). External IMAP remains the default; native runtime is opt-in.
- `POST /api/inbox/actions`
- `GET|POST|PUT|DELETE /api/inbox/folders`
- `GET /api/mail/search`

Mail:

- `POST /api/mail/send`. Optional `attachments: [{name, mimeType, dataBase64}]`, 25 MB in total. Optional `encrypt` and `sign`. If `encrypt` is true and a recipient has no usable key, the call fails with 409. To allow the pickup-link fallback instead, set `allowPickupFallback`. See [Where your PGP private key lives](#where-your-pgp-private-key-lives). Optional `calendarReply: {ics}` sends a calendar RSVP (iTIP REPLY) alongside the body.
- `POST /api/mail/draft` (the same optional `attachments` shape)
- `GET /api/mail/body?mailbox=&messageId=` (one message's body and its `bodyMode`, for clients that list with `bodies=0`; 422 if an adapter reports malformed MIME, preserving original mail)
- `GET /api/mail/attachments?mailbox=&messageId=` (lists the attachment metadata of a message; a calendar invite sent as a message body part appears as `invite.ics` with `calendarMethod`)
- `GET /api/mail/attachment?mailbox=&messageId=&index=` (downloads one attachment)
- `GET|POST /api/mail/send-as`, `POST /api/mail/send-as/{id}/confirm` and `DELETE /api/mail/send-as/{id}` (alias addresses. A new alias is unusable until the user confirms the mailed code or a DKIM-signed copy from its own domain reaches the inbox; only the DKIM proof makes it publishable. The list never returns the code.)

Filter Rules (the caller's own rules):

- `GET|POST /api/rules`
- `PUT|DELETE /api/rules/{id}`
- `POST /api/rules/reorder`
- `GET|PUT /api/rules/{id}/sieve` (view and edit the raw Sieve script)
- `POST /api/rules/run` (runs the rules on demand)

PGP:

- PGP snapshots expose `pgpRevision`; identity, envelope and password writes accept optional `expectedRevision` and reject stale updates with 409. Clients must use the revision from the snapshot that produced their ciphertext. The browser requires revision support for these writes; older clients may still omit it on unconverted accounts. Versioned keyring snapshots and internal atomic storage are prepared; converted records reject legacy single-key writes. Multi-key conversion is not enabled. See [the revision contract](docs/E2E_PGP.md#pgp-revision-preconditions).

- `POST /api/pgp/identity/generate` and `POST /api/pgp/identity/import`
- `GET|DELETE /api/pgp/identity`
- `POST /api/pgp/identity/client` (store a client-protected identity — the server never sees the private key)
- `GET /api/pgp/identity/wrapped` and `POST /api/pgp/identity/rewrap` (fetch and repair the account-password-wrapped envelope; optional `expectedFingerprint` refuses a changed identity with 409)
- `GET|PUT|DELETE /api/pgp/identity/envelope/{slot}` (session-only wrapped recovery/device copies; PUT and DELETE require the current account credential. PUT accepts `expectedFingerprint`; GET includes the identity fingerprint and public key from the same snapshot.)
- `POST /api/pgp/identity/export-legacy` (one-time export of a server-held key, so it can be migrated or backed up)
- `GET|PUT|DELETE /api/pgp/identity/envelope/{slot}` (per-slot key envelopes)
- `GET /api/pgp/bootstrap` (everything the browser needs to unlock a client-protected identity in one call)
- `GET /api/pgp/keyserver/lookup` (queries keys.openpgp.org)
- `POST /api/pgp/recipients/check` (key status for a set of recipients before you send)
- `POST /api/pgp/recipients/resolve` (resolves the key actually used for each recipient)
- `GET /api/pgp/qr/token` and `GET /api/pgp/qr/key` (public key exchange through a QR code)
- `POST /api/pgp/pickup` (creates a sealed pickup for a recipient with no usable key, so a client-protected sender can still use the secure-link fallback)
- `GET /api/mail/pgp-payload` and `POST /api/mail/send-pgp` (fetch a ciphertext for local decryption; submit a locally encrypted message. On a converted account the send carries `materialGeneration` and is refused with 409 when it is stale, and a paired device must be enrolled at that generation)

PGP key discovery and device enrollment:

- `GET|PUT /api/pgp/incoming` — caller-only incoming-encryption preference; PUT requires fresh account confirmation and enabling requires backup acknowledgment and current `expectedRevision`.
- `GET|PUT /api/pgp/discovery/settings`
- `GET /api/pgp/discovery/suppressions` and `DELETE /api/pgp/discovery/suppressions/{email}`
- `POST /api/pgp/discovery/suppress-contact`
- `GET /api/pgp/device/envelope` (a paired device fetches the envelope sealed to its own secure-element key), `POST /api/pgp/device/enrollment-key` (a device publishes its public sealing key and optional `envelopeVersions` under its pairing credential), `POST /api/pgp/device/enrollment-state` (a device reports whether it can actually read the identity and, on a converted account, which envelope version, material generation and fingerprint it holds; a stale or bare report is refused with 409). A browser delivers a sealing with `PUT /api/pgp/identity/envelope/device:<id>`, bound to the device's published key, the snapshot revision and the material generation; v3 for a converted account, v2 for a legacy one

Web Key Directory (admin only, plus the public serving path):

- `GET|POST /api/pgp/wkd/domains` and `DELETE /api/pgp/wkd/domains/{domain}`
- `POST /api/pgp/wkd/domains/{domain}/verify`
- `GET /.well-known/openpgpkey/...` (public. Serves verified users' keys — see [docs/WKD_Publishing.md](docs/WKD_Publishing.md).)

Contacts:

- `GET|POST /api/contacts`
- `GET|PUT|DELETE /api/contacts/{id}`
- `POST /api/contacts/dedupe`
- `GET /api/contacts/search`
- `POST /api/contacts/bulk-delete`
- `GET /api/contacts/export` and `POST /api/contacts/import`
- `GET|POST|DELETE /api/contacts/dav-password` (app-specific CardDAV password)
- `GET|POST|DELETE /api/contacts/carddav-client/config` and `POST /api/contacts/carddav-client/sync` (sync from an external CardDAV server), returns 403 while `managed`
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
- `POST /api/notifications/native/register` and `POST /api/notifications/native/deregister`
- `GET|DELETE /api/notifications/native/devices`
- `PUT /api/notifications/native/mode` (relay push vs. app pull)
- `PUT /api/notifications/native/devices/{deviceId}/mfa` (allow a device to approve sign-ins)
- `GET /api/notifications/native/pull` (every notification is queued here in both modes, addressed to the devices it was sent to, so a device that stops hearing from the relay can poll and catch up)
- `POST /api/notifications/native/unpair`

Logs (admin only):

- `GET /api/logs?file=<name>.log&lines=<n>`
- `GET /api/logs/list`

## Build and Dev Checks

These are the same gates CI runs. All of them must pass before a PR merges —
see [CONTRIBUTING.md](CONTRIBUTING.md) for the full contract.

Backend:

```bash
cd backend
go build -buildvcs=false ./...
gofmt -l .            # must print nothing
go vet ./...
go test -race -count=1 -timeout=20m ./...
```

The `-timeout` is not optional. `internal/api` alone exceeds Go's default 600s
under `-race`, which is why CI splits it into its own job.

Frontend:

```bash
cd frontend
npm ci
npx tsc --noEmit
npm test -- --run
npm run build
```

Push relays (only if you touch `worker/`, `worker-apns/` or `push-relay-shared/`):

```bash
(cd worker && npm ci && npm run typecheck)
(cd worker-apns && npm ci && npm run typecheck)
./scripts/test-relays.sh
```

Install and update scripts:

```bash
for f in scripts/*.sh; do bash -n "$f"; done
scripts/update-host.test.sh
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
release instead, set `KYPOST_VERSION=0.3.0` in `.env` before running it.

### Moving a locally built install onto published images

**Every install created before 2026-08-25 needs this once.** There were no
published images before then, so any install older than that is running one it
built itself.

`update-host.sh` refuses a locally built image: it has no published immutable
digest, so there is no rollback target to preserve, and the updater will not
guess at one. Rebuilding from source with `docker compose up --build -d` keeps
you on a local build and hits the same refusal next time. The one-time move onto
published images is:

```bash
git pull --ff-only     # pick up the current compose file
docker compose pull    # fetch the published image over the locally built tag
docker compose up -d   # recreate the container against it
```

Confirm it took — this is the exact property `update-host.sh` tests:

```bash
docker image inspect ghcr.io/busnes-app/kypost-server:stable \
  --format '{{range .RepoDigests}}{{println .}}{{end}}'
```

One `ghcr.io/busnes-app/kypost-server@sha256:...` line means the migration
worked and `./scripts/update-host.sh` will run from now on. No output means the
image is still locally built.

Your data is untouched by this: config, state and private keys live in the four
named volumes, not in the image. Take a backup first anyway — see
[Backup and Restore](#backup-and-restore).

To keep building from source instead, that is still supported — `docker-compose.yml`
retains its `build:` stanza. You update with `git pull --ff-only && docker compose
up --build -d` and simply do not use `update-host.sh`.

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
- `ollama-model.log` in `/kypost/logs` holds the model installer's own output,
  including its pull retries; `ollama.log` holds the Ollama runtime's.
- If necessary, restart with `docker compose restart`.

### IMAP connection issues

- Verify the host, port, username, password, and mailbox in Config.
- Run IMAP Test in Config.
- Check `daemon.err.log` and `api.err.log` for authentication, TLS, and keyword failures.

### SMTP send issues

- Verify the SMTP host and port in Config.
- Port 465 requires implicit TLS. KyPost supports it.
- If your provider requires app passwords, use them.
- `smtp submission refused: server did not offer STARTTLS` means exactly that —
  the server advertised no STARTTLS, so KyPost refused rather than sending your
  message and password in the clear. Fix the relay, or, for a plaintext relay on
  a network you trust, set `ALLOW_INSECURE_SMTP=true` and understand what you
  are giving up.
- Check `api.err.log` for `mail send failed` details.
- `smtp: acceptance uncertain` means the final DATA acknowledgment was lost or
  invalid. The relay may already have accepted the message; check its logs and
  the recipient before retrying to avoid duplicate mail. A pickup notification
  with this result keeps its encrypted message until it is opened or expires.

### KyPost does not apply labels

- Confirm that the labels exist in the allowlist and the tuning file.
- Confirm that the unread inbox holds eligible messages.
- Check the Decisions page and the poller logs.

### PWA installation on Firefox

- The install button lives on the **Get the apps** page (sidebar, under Settings), alongside links to the native clients.
- Firefox can omit the install prompt event that Chromium browsers emit.
- KyPost still provides a service worker and a manifest. The installation flow differs by browser.

## Project Structure

- `docker-compose.rspamd.yml`: optional pinned private scanner sidecar; fixed configuration in `scripts/rspamd/rspamd.conf`.
- `docker-compose.receiving.yml`: optional controlled receiver supervision and explicit SMTP publish with operator-supplied read-only engine/TLS mounts.

- `backend/internal/mailmsg/`: shared MIME/SMTP helpers and encrypted domain relay profile. Strict native implicit-TLS transport is internally qualified; native primary sending uses fresh admission and the durable outbox; provider readiness and pickup/system paths remain pending.

- `backend/internal/sso/`: signed directory lifecycle, admin mail-domain DNS proof, native reservations, opt-in prepare-before-publication account allocation and shared native outbound admission/recovery. See [provisioning contract](docs/NATIVE_PROVISIONING.md).

- `backend/internal/cfreceiving/`: KyPost side of the continuous Cloudflare wire contract: pickup credentials, signed routing tables and rotations, the bounded Worker client and local pickup state. See [continuous receiving](docs/CLOUDFLARE_CONTINUOUS_RECEIVING.md#kypost-side).
- `backend/internal/ingress/`: durable receiving-buffer core and receipt bridge, selected by opt-in local receiving commands and daemon import; public receiver packaging remains gated. See [receiving qualification](docs/RECEIVING_GATEWAY_ASSESSMENT.md).
- `backend/internal/mailbox/`: internal permanent per-owner SQLite mail, metadata, receipt and change storage, with a complete internal mail Client and transactional incoming-encryption recovery. The internal importer commits these receipts before releasing receiving-buffer payloads. Source guards refuse switching or reusing references against another native database. Native API qualification uses fresh full snapshots; efficient scoped deltas remain pending; `KYPOST_NATIVE_MAIL=true` selects prepared local mailboxes. The internal directory reconciler retains primary-address/account reservations and preparation status; provisioning retries retained signed directory subjects when native mode is enabled. Internal new-account preparation atomically publishes an empty mailbox plus prebound state and refuses legacy/incomplete directories; matching preparations are validated on retry. See [implementation evidence](docs/TURNKEY_MAIL_PHASE1.md#durable-directory-desired-state-and-native-account-preparation). Encrypted outbox claims and independent Sent receipts back admitted primary compose/client-PGP sending and API/daemon recovery; pickup/alias/system paths remain pending.

- `backend/internal/backup/`: KyRecovery adapter, collection and drill checks for state, native mailbox and receiving SQLite snapshots.
- `docs/RESTORE.md`: operator backup and offline restore procedure.

- `backend/`: Go API, poller, adapters, config, state, health, and the on-device embedding sorter (`internal/sorter`)
- `frontend/`: React and Vite UI
- `scripts/`: container entrypoint, supervisord orchestration, Ollama model management, host-side update helpers and the controlled native-domain setup wizard
- `push-relay-shared/`: shared Cloudflare Worker logic for the push relays — API-key issuance, rate limiting, device-token ownership, and the `RelayCoordinator` Durable Object
- `worker/`, `worker-apns/`: the FCM and APNs deployments of that relay. Each holds only its provider's `handleSend` plus its wrangler config; everything else is imported from `push-relay-shared/`
- `receiving-worker/`: independent Email Workers with private R2 retention and authenticated pickup: the one-message pilot (`docs/CLOUDFLARE_RECEIVING.md`) and the continuous protocol Worker, whose KyPost side is `backend/internal/cfreceiving/` (`docs/CLOUDFLARE_CONTINUOUS_RECEIVING.md`); built-in Node tests
- `docs/`: the contracts the client repos implement against — [PLATFORM_BASELINE.md](docs/PLATFORM_BASELINE.md) (what a client must implement to call itself a KyPost client), [E2E_PGP.md](docs/E2E_PGP.md), [WKD_Publishing.md](docs/WKD_Publishing.md), [WEBMAIL_HANDOFF.md](docs/WEBMAIL_HANDOFF.md), [INBOX_PAYLOAD_HANDOFF.md](docs/INBOX_PAYLOAD_HANDOFF.md) — plus the operator guide [Reverse_Proxy_Networking.md](docs/Reverse_Proxy_Networking.md)
- `share/`: host-side Ollama model blob cache, bind-mounted into the container. Never committed
- `testdata/`, `fonts/`: test fixtures and the bundled webfonts
- `Dockerfile`: single image build (backend, frontend, Ollama runtime, pinned embedding model)
- `docker-compose.yml`: local orchestration
- `supervisord.conf`: in-container process supervision
- `AGENTS.md`: the contribution contract for automated agents. Every subtree with its own rules carries one

## Licence

KyPost is released under the [MIT License](LICENSE.txt).

[![OctoCounts](https://api.octocounts.com/badge/Busnes-app/KyPost-Server/branch/main)](https://octocounts.com/github/Busnes-app/KyPost-Server/tree/main)

## Upgrading after the Busnes-app owner move

The GitHub organisation was renamed on 2026-09-16 and the image now lives at `ghcr.io/busnes-app/kypost-server`. The project no longer controls `ghcr.io/busness-app`; GHCR does not redirect it, and anything served under that name must be treated as untrusted. If `KYPOST_IMAGE` in `.env` still names the old namespace, re-pinning is required, not optional: first inspect `git remote -v` and replace a retired-owner remote with `https://github.com/Busnes-app/KyPost-Server.git` (prefer a fresh clone plus a known commit). A first `scripts/update-host.sh` run on a container pulled from the retired namespace is expected to refuse because its rollback digest has the old repository prefix; follow [Moving a locally built install onto published images](#moving-a-locally-built-install-onto-published-images), but verify the newly selected digest with `gh attestation verify` before `docker compose up -d`. Once the running image has the official digest, run [`scripts/update-host.sh`](scripts/update-host.sh), which resolves `stable` to a digest and verifies its GitHub build attestation before updating the service. See [Updating KyPost](#updating-kypost) for the procedure.
