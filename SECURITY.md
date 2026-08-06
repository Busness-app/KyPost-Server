# Security Policy

KyPost is a self-hosted IMAP web client with end-to-end encryption support. This document describes security practices, known limitations, responsible disclosure, and deployment security considerations.

## Reporting Security Vulnerabilities

If you discover a security vulnerability in KyPost, please report it responsibly via GitHub Security Advisories rather than opening a public issue.

### How to Report

1. Go to the [Security Advisories](https://github.com/Yoshiofthewire/kypost-server/security/advisories) page
2. Click "Report a vulnerability"
3. Provide a detailed description, affected versions, and reproduction steps if applicable
4. Do not disclose the vulnerability publicly until a patch is available

### Disclosure Timeline

The timeline for public disclosure depends on severity:

- **Critical** (e.g., unauthenticated data access, authentication bypass, remote code execution): 30 days
- **High** (e.g., privilege escalation, cryptographic weakness): 60 days
- **Moderate** (e.g., denial of service, information disclosure): 90 days

We will:
- Acknowledge receipt of your report within 2 business days
- Provide a timeline and severity assessment
- Develop and test a patch
- Coordinate a release that includes the fix before the deadline
- Credit you in the patch release notes (unless you prefer anonymity)

This timeline assumes good-faith coordination. Patches are publicly available before any advisory is published.

### Security Advisory Credits

We acknowledge security researchers and community members who help us improve. If you'd like credit in our release notes, please let us know your preferred name or handle when reporting.

## Known Limitations & Trust Boundaries

KyPost is honest about what it does and does not protect. Read these carefully before deploying or relying on specific features.

### PGP Key Custody

KyPost has two key protection modes. **Choose deliberately, not by accident.** See [Where your PGP private key lives](README.md#where-your-pgp-private-key-lives) for a complete explanation.

**Client-Protected (End-to-End):** Your browser generates or wraps the key under a password-derived key. The server cannot open it. Costs: you must unlock it each browser session, and admin operations cannot access your encrypted mail. Security can create an encrypted offline recovery backup in the browser; restoring it requires both the downloaded file and its separately displayed random secret. Neither the plaintext key nor the secret is sent to or stored by the server.

**Server-Protected:** The server holds a master key and unwraps your PGP key on demand. Convenience: automatic decryption, password resets work, background polling works. Cost: this is **not** end-to-end encryption. The server, and anyone with access to its disk (root, backup operators, disk seizure), can decrypt everything you receive. If you self-host, this may be acceptable. If someone else runs it, you are trusting them with plaintext mail.

### Automatic Label Classification

Labels (keywords) assigned by the classifier are **a sorting hint, not a security boundary.** The classifier reads sender-controlled email, so a sender can write instructions into their message and influence which label it receives. Testing shows roughly 50-87% resistance to prompt injection depending on configuration, but every model tested let some through.

What an attacker can achieve: steer the label on **their own message** into a different folder (e.g., `Primary` instead of `Promotions`). The keyword allowlist is enforced in Go after the model answers, so output outside that list is discarded. A message cannot be deleted, moved, marked read, or cause any other message to be affected.

**Do not build security controls on labels.** Never create a filter rule that grants trust based on a label, and never auto-archive anything by label alone. This is not a fixable limitation—it is a known property of using local LLMs to classify sender-controlled text. All decisions are recorded on the Decisions page so you can audit what actually happened.

**Encrypted mail is not classified, and is never labelled as encrypted.** A PGP-encrypted message has no readable body, so it skips the classifier and is tagged with your account's default label instead. It is deliberately *not* given an `Encrypted` keyword. IMAP keywords are stored on the mail server in the clear, so such a keyword would hand whoever runs that server a precise index of which of your messages are worth attacking—the exact adversary client-protected custody exists to defend against—while looking to you like a security feature. It would break the rule above in both directions at once: not trustworthy enough to rely on, and harmful merely by existing. The padlock you see in the reader is derived from the message itself each time it is displayed and is never written anywhere.

**Encrypted mail also stays out of mobile push payloads.** Native push travels to the relay Worker and on to FCM/APNs in cleartext at every hop. For an encrypted message the sender and subject are withheld from that payload regardless of your Content Preview setting, because a third-party PGP/MIME message that does not use protected headers carries its real subject in the clear. Web push is unaffected—those payloads are encrypted to your browser's own subscription keys (RFC 8291), so Content Preview remains your choice there.

See [Classification flow](README.md#classification-flow) for details.

### Email HTML Rendering

KyPost renders email HTML in a sandboxed iframe with DOMPurify sanitization. The sandbox blocks most attacks (no script execution in the frame itself), but:

- **Remote content loads on opt-in.** Images, stylesheets, and other remote resources are not loaded by default. Users can opt in per message.
- **Links open in new windows** (via `<base target="_blank">`). The link destination is not constrained by KyPost; it goes wherever the sender directed.
- **Sender HTML survival.** DOMPurify removes most dangerous elements, but sanitization is a defense layer, not a boundary. Treat all email HTML as potentially hostile, and do not trust email to be what it claims.

### Session Security

See [Session Behavior](README.md#session-behavior) for full details. Key points:

- Sessions expire after 24 hours without activity (sliding window).
- Sessions have a hard cap: 7 days from issue, regardless of activity. Stolen cookies cannot be kept alive indefinitely.
- Sessions are swept every hour; expiry does not wait for the cookie to be presented again.

### CardDAV & External Services

- CardDAV clients (phones, desktop apps) authenticate with a per-user app-specific password separate from your login password.
- CardDAV clients that sync from external servers should use HTTPS-only connections.
- KyPost does not validate external CardDAV server certificates beyond the OS default. Use a trusted network or a known server.

### Mobile Pairing

- Pairing tokens are valid for 90 seconds and signed with a per-instance secret.
- All pairing payloads (QR codes, pickup links, key exchange URLs) carry bearer credentials in the query string.
- Set `SERVER_BASE_URL` to an HTTPS URL so credentials travel over TLS.
- Pairing secrets must remain on the server only. Multi-replica deployments share one secret via `PAIRING_SECRET`.

## Deployment Security

Your deployment choices determine the actual security of KyPost. This section covers the configuration decisions that matter most.

### TLS & Network Binding

**This is the most important decision you make.** KyPost serves plain HTTP by default. Session cookies are marked `Secure` only when the request provably arrived over TLS.

**Before exposing KyPost to a network, get TLS in front of it.** On bare `http://`, cookies are sent in the clear on every request.

Three ways to get TLS:

**1. Terminate TLS in KyPost (recommended if you control the host)**
- Set `TLS_CERT_FILE` and `TLS_KEY_FILE` to mounted certificate paths.
- KyPost will reload certificates without a restart (important: restarting logs everyone out).
- Setting only one path is a startup error; it will not fall back to cleartext.
- This is the only option where "did this arrive over TLS?" is answered by the connection itself, not by a header. `TRUSTED_PROXY_CIDRS` does not apply.
- Certificates are never baked into the image.
- See `.env.example` and the commented volume in `docker-compose.yml`.

**2. Cloudflare Tunnel**
- cloudflared gives the browser a real HTTPS origin (needed for proof-of-work CAPTCHA).
- No TLS configuration of your own.
- Set `TRUSTED_PROXY_CIDRS` to the proxy's address.

**3. Reverse proxy you operate** (nginx, Caddy, etc.)
- Set `TRUSTED_PROXY_CIDRS` to the proxy's address.
- Proxy must use HTTPS when reaching KyPost if the hop carries session cookies across a real network.

### KYPOST_BIND: Which Interface to Publish

`KYPOST_BIND` controls which interface publishes port 5866. It has no default—compose refuses to start without it.

- **`127.0.0.1`**: loopback only. Use when your reverse proxy runs on this same host.
- **Your LAN IP** (e.g., `192.168.1.10`): publish to the LAN. Use when a proxy on another machine reaches this host.
- **`0.0.0.0`**: publish everywhere. Use only when you deliberately want KyPost reachable on all interfaces. **This is usually wrong unless you also set `ALLOW_INSECURE_HTTP=true` and understand the consequences.**

**Check where your proxy actually reaches this container from** before choosing. Loopback publishing severs a proxy that arrives by the host's LAN address, which is the typical shape for cloudflared or an nginx on another machine.

**Better practice:** Run the proxy as a container on `kypost-net` (the network the compose file defines) and point it at `http://KyPost-Server:5866`. That network has DNS, nothing needs publishing, and the path ignores source NAT entirely—the server sees the real client IP. See [Reverse_Proxy_Networking.md](docs/Reverse_Proxy_Networking.md) for setup and Docker error recovery.

### TRUSTED_PROXY_CIDRS: Client IP Trust

When a reverse proxy sits in front of KyPost, the server sees the proxy's address as the client IP. This address is used as the key for:

- Login rate limiting (3 strikes, 15-minute lockout)
- Per-IP account lockout (looser, across all accounts)
- Instance-wide login rate limit
- MFA push approval notifications (the push names the address)

**If `TRUSTED_PROXY_CIDRS` is empty, forwarded headers are discarded entirely.** Every caller is keyed as the proxy, so all users share one lockout bucket and push notifications show the gateway address instead of the user signing in.

**If `TRUSTED_PROXY_CIDRS` is set, KyPost trusts `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-For` from that CIDR.** This marks cookies `Secure` and keys lockouts off the real caller. Cloudflare Tunnel also reads `CF-Connecting-IP` in preference to `X-Forwarded-For` (the edge appends your IP to XFF, but cloudflared may append its own hop after it).

**Name the proxy's address specifically, not a wide range.** Any peer inside the range you name can forge their own client IP and bypass every rate limit and lockout. Example:

- Proxy on same host: `TRUSTED_PROXY_CIDRS=127.0.0.1/32`
- Proxy pinned on `kypost-net`: `TRUSTED_PROXY_CIDRS=10.89.0.10/32` (replace with your proxy's actual Docker network IP)
- Cloudflare Tunnel: `TRUSTED_PROXY_CIDRS=0.0.0.0/0` is unavoidable; Tunnel is the proxy and only Cloudflare can reach it

This replaces the old `TRUST_PROXY_HEADERS=true`, which trusted forwarded headers on *every* connection from any peer and was only ever safe when nothing but the proxy could reach the port.

### Verification: Confirm Your Setup

**Verify rather than assume.** Sign in and fetch `GET /api/status`. Check two fields:

- `clientIp`: must be your own public address (or `127.0.0.1` if TLS-terminating in KyPost)
- `proxyHeadersTrusted`: must be `true` (if using a reverse proxy) or `false` (if TLS-terminating in KyPost)

If `clientIp` is a loopback or bridge address (e.g., `172.17.0.1`), every user shares one lockout bucket and the session cookie is not being marked `Secure`.

### Secret Handling

- **Bootstrap password:** On first start, KyPost writes the generated admin password to `first-run-password.txt` (mode `600`) in the config volume. Read it and delete it immediately. Logs are unrotated by default and readable by anything with Docker socket access—the password is never logged. This holds for both bootstrap paths: the container's `--mode bootstrap-admin` step and a server started directly against an empty config directory. If the file cannot be written, startup fails rather than falling back to printing the password.
- **IMAP credentials:** Stored encrypted at `/kypost/private/imap-config.key` (master key) and per-user encrypted payloads. The key does not rotate; compromise of the key compromises all encrypted credentials.
- **TOTP secrets:** Master key at `/kypost/private/totp-secret.key`. Same rotation caveat.
- **Pairing secret:** `/kypost/private/pairing.key` (generated on first start). Must be identical across replicas if you run multiple.
- **PGP server keys:** Master key at `/kypost/private/pgp-server-key` (only if using server-protected PGP mode).

All of these live in `/kypost/private`. **Back up this volume separately and store it securely.** Compromise of this directory compromises all user data.

### First Run & Bootstrap

- Bootstrap credentials are written to a file on first run, not logged. Running the binary directly (systemd, CI, a bare host) takes the same path as the container: the password goes to `first-run-password.txt`, and only its *path* is printed.
- You can pass `BOOTSTRAP_ADMIN_PASS` on the first run to avoid the file write (you already have the password).
- You can also pass `BOOTSTRAP_ADMIN_USER` to name the initial admin (default: `admin`).
- The bootstrap account starts on the password-change screen and cannot access anything else until you change it.
- **Change the password immediately after first login.**

## Authentication & Authorization

### Login Flow

- Username + password, with per-account salt and work factor.
- Password never reaches the server. The browser derives an authentication half (what gets sent) and a key-wrapping half (for PGP key encryption, stays in the browser).
- CAPTCHA challenge on login (optional, configurable: `pow`, `turnstile`, `friendly`, or `none`).
- Proof-of-work CAPTCHA (`pow`) uses `crypto.subtle` and requires HTTPS (except localhost). Difficulty adapts per address; escalation is counted per IP and decays after 15 minutes or on successful login.
- 3-strikes account lockout (15 minutes).
- Per-IP lockout (looser, across all accounts).
- Instance-wide login rate limit.

### Multi-Factor Authentication

- **TOTP:** Time-based one-time passwords from an authenticator app.
- **Recovery codes:** One-time codes for account recovery if you lose your authenticator.
- **Push approval:** A pairing device receives a push notification and approves or denies the sign-in. Set up on Security's Devices tab.

Recovery codes are the only way to regain access if you lose your authenticator and have no paired push device. **Export and store them securely.**

### Roles & Authorization

- **Admin:** Create users, reset passwords, deactivate accounts, view system logs, edit global settings, start health repair.
- **User:** Connect their own IMAP/SMTP, read mail, manage their own rules and filters, set notification preferences, tune their own prompt.

Authorization is checked on every request. Deactivation or role changes take effect on the user's next request, not at the next login.

### Session Revocation

- Logout invalidates the server-side session and clears the cookie.
- Deactivation or demotion takes effect on the user's next authenticated request.
- KyPost will not let you deactivate or demote the last active admin.

## Data Protection

### Encryption at Rest

User data is stored in `/kypost/config/users/<userID>/` and `/kypost/state/users/<userID>/`. What is encrypted:

- **IMAP credentials:** AES encryption with a master key (`imap-config.key`).
- **TOTP secrets:** AES encryption with a master key (`totp-secret.key`).
- **PGP keys (server-protected mode):** Encryption with a master key (`pgp-server-key`).
- **PGP keys (client-protected mode):** Wrapped in the browser under a password-derived key; the server stores only the wrapped blob.
- **Client recovery backups:** The downloaded backup contains a second browser-created AES-GCM envelope. Its recovery secret is shown once and is not stored by KyPost.

Unencrypted:

- **User account metadata:** Username, role, hashed auth secret, account status.
- **Mailbox state:** IMAP checkpoint, processed message IDs, decision history (which labels were assigned to which messages).
- **Configuration:** Tuning prompts, notification preferences, rules, contacts.

**If the `/kypost/private` volume is compromised, all encrypted data is compromised.** This includes all IMAP credentials, TOTP secrets, and server-protected PGP keys.

### Encryption in Transit

- **Sessions:** Cookies marked `Secure` only on HTTPS (when `TRUSTED_PROXY_CIDRS` is set or TLS terminates in KyPost).
- **API calls:** All backend endpoints expect HTTPS (enforced by cookie marking and browser same-origin policy).
- **CardDAV:** Sync clients should use HTTPS-only servers.
- **Mobile pairing:** QR codes and pickup links carry bearer tokens in the query string. Use HTTPS for `SERVER_BASE_URL`.
- **External services:** Push relay APIs use HTTPS only (`PUSH_RELAY_URL` and `APNS_RELAY_URL` must be HTTPS).

### Sensitive Data in Logs

- Passwords are never logged.
- IMAP credentials are never logged in full; auth errors mention only the server and username.
- CAPTCHA solutions are not logged.
- Mail content (subject, body) is not logged except for decision history (which labels were assigned).

Check `/kypost/logs` regularly and configure your log aggregator appropriately if you have one.

## Security Headers & Defense-in-Depth

KyPost applies multiple defense layers to protect against common web attacks.

### Content Security Policy

CSP is configured per CAPTCHA provider to block script injection and limit the capabilities an attacker can use if HTML sanitization fails. Directives:

- **script-src:** `'self'` plus provider-specific origins only (e.g., `challenges.cloudflare.com` for Turnstile, `cdn.jsdelivr.net` for Friendly Captcha). **Never `'unsafe-inline'` or `'unsafe-eval'`.**
- **style-src:** `'self'` and `'unsafe-inline'` (for the Quill editor's inline styles). No third-party origin.
- **font-src:** `'self'` and `data:`. The webfonts are served from this origin out of the app bundle, not from Google Fonts — an install with no CAPTCHA configured, or on the self-hosted `pow` provider, makes no cross-origin request at all.
- **img-src/media-src:** Allows remote content (shown after user opt-in per message) and data URIs.
- **object-src:** `'none'` (blocks Flash, PDF plugins, etc.).
- **frame-ancestors:** `'none'` (prevents clickjacking).
- **base-uri:** `'self'` (prevents injection of a malicious `<base>` tag).
- **form-action:** `'self'` (all forms submit to this origin).

### Other Security Headers

- **X-Content-Type-Options:** `nosniff` (prevents MIME sniffing).
- **X-Frame-Options:** `DENY` (prevents framing).
- **Referrer-Policy:** `strict-origin-when-cross-origin` (limits referrer information).
- **Permissions-Policy:** Blocks powerful features (camera, microphone, geolocation, payment, etc.) that KyPost never needs.
- **Cross-Origin-Opener-Policy:** `same-origin` (severs `window.opener` for client-protected PGP keys).
- **Strict-Transport-Security:** `max-age=31536000; includeSubDomains` (on HTTPS only).

### Email HTML Sanitization

Email HTML is sanitized with DOMPurify before rendering in a sandboxed iframe. The sandbox blocks script execution in the frame itself, but **DOMPurify is a defense layer, not a boundary.** Treat all email HTML as potentially hostile.

### CAPTCHA & Rate Limiting

- **CAPTCHA:** Optional on login. Proof-of-work (`pow`) is self-hosted and requires HTTPS. Turnstile and Friendly Captcha use third-party verification.
- **Account lockout:** 3 failed login attempts = 15-minute lockout per account.
- **Per-IP lockout:** Looser, across all accounts.
- **Instance-wide limit:** Meters login attempts across the instance.
- **Proof-of-work escalation:** Difficulty increases with each recent failed login from the same IP (up to a ceiling), decaying after 15 minutes or on success.

None of these replace the others; they work together.

## Development & Security Testing

Security-sensitive code should meet these expectations:

### Testing

- **Authentication changes:** Tests for bypass scenarios (missing credentials, modified tokens, expired sessions).
- **Authorization changes:** Tests for privilege escalation (users accessing admin endpoints, admins accessing user-scoped data).
- **Cryptographic operations:** Tests for correct key derivation, encryption, and decryption.
- **Input validation:** Tests for injection attacks (SQL if applicable, command injection, XSS via sanitized HTML).

See `backend/internal/api/*_security_fixes_test.go` for patterns.

### Code Review

Security-sensitive PRs should include:

- A description of the trust boundary or attack surface.
- Explanation of why the approach is secure (or why a known limitation is acceptable).
- Test coverage for both the happy path and attack scenarios.
- Any assumptions about the deployment (e.g., "assumes TLS termination in KyPost").

### Examples of Security-Sensitive Code

- Authentication and session management (`backend/internal/api/auth.go`)
- Authorization checks (role-based access)
- Cryptographic operations (key derivation, encryption, decryption)
- Input validation and sanitization (HTML email, filter rules, etc.)
- Rate limiting and lockout logic
- Trust boundary validation (client IP from forwarded headers, etc.)

## Security Contacts

- **Vulnerability reports:** [GitHub Security Advisories](https://github.com/Yoshiofthewire/kypost-server/security/advisories)
- **Maintainer:** [Yoshiofthewire](https://github.com/Yoshiofthewire)

## Additional Resources

- [README Security Section](README.md#where-your-pgp-private-key-lives) — PGP key custody, session behavior, users and roles
- [Reverse Proxy Networking](docs/Reverse_Proxy_Networking.md) — Setting up a proxy on `kypost-net`
- [Quick Start TLS Notes](README.md#quick-start) — TLS termination and proxy configuration
- OWASP guidelines on secure development practices
