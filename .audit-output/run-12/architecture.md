# KyPost Server — Architecture Summary (run-12)

**Target:** `/home/yoshi/git/kypost-server`  
**HEAD:** `95c8c0f` (`fixes-101-102`)  
**Prior coverage:** audit artifacts through run-11 exist. Runs 1–10 reported many findings across auth, lockouts, CardDAV, PGP/MIME, push relay, rules, contacts, and frontend rendering. Run-11 rejected its rechecked findings as fixed on the then-current branch.

## Application and deployment

KyPost is a self-hosted, multi-user IMAP webmail client with SMTP, CardDAV, Sieve-style rules, PGP in server- and client-custody modes, local Ollama classification, MFA, browser/native push, and Cloudflare FCM/APNs relay deployments. The backend is Go 1.26.5 using `net/http`, SQLite, JSON/YAML stores, IMAP, MIME/OpenPGP, CardDAV, and SMTP libraries. The frontend is React 19/TypeScript with DOMPurify, Quill, OpenPGP, and a sandboxed email-body iframe.

The standard container runs separate API and daemon Go processes under supervisord, plus Ollama. Persistent state is under `/kypost`; the application runs as `kypost` after startup ownership setup. The API is published on a caller-selected bind address and can use TLS directly or an operator-controlled proxy.

Key entry points are `backend/cmd/main.go`, `backend/internal/app/app.go`, `backend/internal/api/server.go`, `frontend/src/App.tsx`, `push-relay-shared/push-relay-common.ts`, `worker/src/index.ts`, `worker-apns/src/index.ts`, `Dockerfile`, and the GitHub Actions workflows.

## Trust model and boundaries

- Web sessions use an in-memory cookie session, live user/role/activity checks, CSRF for cookie-authenticated writes, and password-change confinement.
- Native devices use `X-Kypost-Device-Id` plus a hashed secret. Current code reloads the live device and user state, checks account activity/password-change state, and applies lockout/metering.
- CardDAV uses a separate per-account app password with live account checks, bounded verification caching, generation invalidation, and user-scoped paths.
- Pairing, QR, pickup, and relay credentials are signed or opaque token boundaries with purpose/expiry checks; relay token ownership and claims are coordinated by a Durable Object.
- Native pairing-token revocation is not one transaction: registration resolves the subscriber owner before commit, while admin credential purge deletes devices and rotates the subscriber in later independent operations. This is the current audit finding and must be treated as a trust-boundary race.
- Untrusted inputs enter through HTTP/API/WebDAV, IMAP mail and MIME/PGP bytes, vCards/XML/JSON/YAML, environment/configuration, and external service responses. Outbound sinks include IMAP/SMTP, CardDAV, UnifiedPush, classifier/Ollama, WKD/key discovery, CAPTCHA providers, and push relays.
- Email HTML is sanitized before browser rendering; the read view uses a sandboxed iframe without scripts. Attachment response types are allowlisted. SQL uses parameterized queries and application request paths do not invoke shell execution.

## Current-delta surfaces

Since run-11, the meaningful audit surfaces are:

- PGP/MIME pass-through and bodyless client-protected messages (`backend/internal/api/pgp_receive.go`, `server_inbox.go`, `pgp_client_read.go`, `backend/internal/adapters/imap/client.go`).
- Browser MIME decoding, read/draft handoff, and stale inbox-load handling (`frontend/src/lib/mimeContent.ts`, `ReadPage.tsx`, `EmailBodyFrame.tsx`).
- Image publication/release workflows and supply-chain inputs (`.github/workflows/publish-main.yml`, `release-image.yml`, pinned Docker/Ollama inputs).
- CAPTCHA proof-of-work defaults and secure-context deployment assumptions (`.env.example`, CAPTCHA backend/frontend paths).

## Baseline comparable

The closest baselines are Roundcube/SnappyMail for webmail, SOGo/Nextcloud for CardDAV, Mailvelope/Proton-style browser PGP, and Signal-style linked devices. KyPost’s documented tradeoffs are self-hosting, operator-managed TLS and upstream credentials, server-served browser code for client-custody PGP, and a central push relay. These are design choices, not findings without a concrete boundary failure.
