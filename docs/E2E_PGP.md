# End-to-end PGP: design, status, and the mobile plan

## Why this exists

KyPost advertised "PGP end-to-end mail encryption" while storing every user's
private key on the server, unlocked, sealed with a master key sitting on the
same volume. Anyone with the disk, a backup, a container shell, or a
path-traversal bug could decrypt every message every user had ever received,
retroactively. That is server-side encryption, not end-to-end, and the gap
between the claim and the design is the thing this work closes.

## The model

Two protection modes, recorded per user in `users.json` as
`pgpKeyProtection`:

| | `server` (legacy) | `client` (end-to-end) |
|---|---|---|
| Private key stored as | `pgpPrivateKeyEnc` — AES-GCM under `SECRET_DIR/pgp-private-key.key` | `pgpPrivateKeyWrapped` — AES-GCM under a key derived from the user's password |
| Server can decrypt mail | Yes | No |
| Decryption happens | Server (`api/pgp_receive.go`) | Browser (`lib/pgpClient.ts`) |
| Signing happens | Server (`handleMailSend`) | Browser, delivered via `POST /api/mail/send-pgp` |
| Send-as User ID reconcile | Daemon, automatically | Browser, when the vault is unlocked |

`users.User.PGPProtection()` is the single source of truth; every server-side
PGP path calls `HasServerReadableKey()` and refuses rather than assuming.

### Key wrapping

`frontend/src/lib/keyVault.ts`:

- PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP figure for this
  construction), 16-byte random salt.
- AES-256-GCM, 12-byte random IV.
- Envelope records `kdf` and `iterations`, so a later move to Argon2id is a
  format addition, not a migration — unwrap dispatches on what the stored
  envelope says.

Argon2id would resist GPU attack better and is the eventual target. It is not
in WebCrypto, so today it would mean a WASM bundle on the critical path of
every login. The envelope is versioned specifically so that trade can be
revisited without touching stored data.

### Why the server can't cheat

The server holds a scrypt hash of the password, never the password. It
therefore cannot derive the wrapping key, and there is no code path that
tries. `cryptutil.OpenString` uses `LoadKey`, not `LoadOrCreateKey`, so a
missing master key is a loud error rather than a silently-minted new one.

### Session handling

The unwrapped key lives in module memory for the life of the page and is
never written to `localStorage` or `sessionStorage` — both survive a tab
close and are readable by any script that achieves XSS, which is exactly what
this protects against. A reload means re-entering the password. There is a
test asserting nothing lands in either store.

## What this costs, honestly

- **Admin password reset destroys the key.** The wrapping key comes from the
  password; an admin cannot rewrap a key they cannot open. Users must keep an
  exported backup. This is inherent to the model, not an implementation gap.
- **Password change requires the browser.** It unwraps with the old password
  and rewraps with the new one (`POST /api/pgp/identity/rewrap`). If that
  second call is lost, the stored envelope is still wrapped under the old
  password — recoverable by entering the previous password once, which beats
  the alternative of the server holding the key so it can rewrap unattended.
- **The pickup-link fallback is weaker than PGP.** See "Sealed pickup links"
  below for exactly how much weaker.
- **Subject headers are still cleartext** outside the encrypted part, as with
  any PGP/MIME mail.


## Sealed pickup links

A recipient with no PGP key has nothing to encrypt to, so KyPost falls back to
emailing them a one-time link. Originally the server stored that message's
plaintext (sealed with its own key, which it holds) for seven days — the exact
property client-side protection exists to remove.

For client-protected accounts the message is now sealed in the sender's
browser instead:

1. The browser picks a random AES-256-GCM key and encrypts subject and body.
2. It uploads **only ciphertext** to `POST /api/pgp/pickup`.
3. The link is `…/pickup/<id>?t=<token>#<key>`. Browsers never transmit a URL
   fragment, so the key does not reach the server on the fetch.
4. The recipient's page (`/pickup-decrypt.js`) reads `location.hash` and
   decrypts locally, then strips the key from the address bar.

`?t=` still authenticates the fetch, as before. The key is separate and rides
only in the fragment.

### What this actually protects against

**Protects:** the server's disk, its backups, snapshots, a compromise after
the fact, and an operator reading files. The stored blob is ciphertext and the
key was never written anywhere.

**Does not protect:**

- **Anyone who can read the recipient's mailbox has the key**, because the key
  is in the email. Their provider, an attacker with mailbox access, an
  unencrypted hop. This defends against *your* server, not their mail path.
- **The server sees the key once, in flight**, when it relays the notification
  email over SMTP. Unavoidable while it holds the SMTP credentials. So a
  server compromised *at the moment of sending* still sees it; one compromised
  later does not.

Net: a seven-day plaintext-at-rest exposure becomes a momentary in-flight one.
That is a real improvement and it is not the same guarantee the PGP path
gives. The compose checkbox is off by default and says so.

### Operational hazard: link rewriting

Corporate mail security products (Outlook Safe Links, Proofpoint, Mimecast)
rewrite inbound URLs. HTTP redirects preserve fragments, but a rewriter that
*constructs* a new URL can drop everything after `#` — and then the message is
permanently unreadable. This is the most likely real-world failure, and it is
why the page checks for an absent fragment first and names that cause
specifically rather than reporting a generic decryption failure.

### Other notes

- The subject is inside the sealed blob, not stored alongside it. A subject in
  the clear gives away most of what the encryption was for.
- The page renders the decrypted body as **text**, never as HTML: it has no
  sanitizer available, and the content is written by the sender.
- Consumption happens on the blob fetch, not the page load, so a link-preview
  bot fetching the HTML does not burn the message.
- Server-protected accounts keep the original server-sealed path. The server
  can already read their mailbox, so client-sealing there adds machinery
  without changing what it can see.

## Status

### Corrections to an earlier version of this document

The first version of this file claimed "Read path passes ciphertext through
untouched for client-protected accounts." That was true of the Go struct and
false end to end. `decryptPGPMessageContent` does leave
`PGPEncryptedPayload` populated, but `inboxEmail` has no field for it and
`mailcache.Entry` does not persist it, so the ciphertext was dropped at JSON
serialization and never reached any client. No client-protected account
could read encrypted mail, on web or anywhere else. Fixed by
`GET /api/mail/pgp-payload`.

It also listed the key endpoints as implemented without noting they were all
`withAuth` (session cookie only), which locked out every paired mobile
device — the clients this mode was designed for. All but `export-legacy` are
now `withMailAuth`.

Both defects came from verifying at the Go boundary and never at the HTTP
boundary. There are now HTTP-level tests
(`api/pgp_client_e2e_test.go`) for exactly that gap.

Implemented:

- Storage model, `PGPProtection()`, and refusal of every server-side PGP
  operation on a client-protected key (`users`, `api/pgp_receive.go`,
  `handleMailSend`, `processor/sendas_check.go`).
- Endpoints, all `withMailAuth` (device or session) unless noted:
  `GET /api/pgp/bootstrap`, `GET /api/pgp/identity/wrapped`,
  `POST /api/pgp/identity/client`, `POST /api/pgp/identity/rewrap`,
  `POST /api/mail/send-pgp`, `GET /api/mail/pgp-payload`.
  `POST /api/pgp/identity/export-legacy` is **session-only** on purpose: it
  is the one endpoint that returns a private key, and it re-verifies the
  account password, which a device secret is not.
- The server derives fingerprint and key ID from the uploaded public key
  rather than trusting the client's claim — otherwise a client could get its
  own key published under someone else's identity through WKD or Autocrypt.
- Browser crypto: `lib/keyVault.ts` (wrap/unwrap/lock, 12 tests) and
  `lib/pgpClient.ts` (generate, import, decrypt, encrypt, RFC 3156 wrapping
  with a full RFC 5322 envelope and protected Subject).
- Client-protected accounts fetch ciphertext per message from
  `/api/mail/pgp-payload` and decrypt locally.

### Cold start

A client cannot keep the unwrapped private key across restarts — the web
vault holds it in page memory only, and the mobile apps are told not to put
it in the Keystore/Keychain, since anything recoverable without the password
defeats the model. Every launch is therefore a full reload.

`GET /api/pgp/bootstrap` is the single call that makes a client operational
from nothing:

| field | meaning |
|---|---|
| `hasIdentity` | whether this account has a key at all |
| `protection` | `client`, `server`, or `""` |
| `wrappedPrivateKey` | the self-describing envelope to unwrap (client mode) |
| `unlockRequired` | prompt for the password before reading mail |
| `canDecryptServerSide` | true only for legacy accounts |
| `migrationAvailable` | offer the one-time migration |
| `publicKey`, `fingerprint`, `keyId` | the identity itself |
| `signerPublicKeys` | contact public keys, so signatures verify without waiting on a contacts sync |
| `payloadEndpoint` | where to fetch ciphertext; absent on older servers |

Doing this as separate calls gives four chances to render a
half-initialized UI — showing "no PGP identity" to someone who has one, or
treating mail as unreadable because the wrapped-key call was the one that
failed. The envelope carries its own `kdf`/`iterations`/`salt`/`iv`, so
clients must derive from the blob rather than hardcoding parameters; that is
what lets the KDF change later without stranding them.

Web UI (wired):

- **Cold start** in `App.tsx`: every authenticated page load fetches
  `/api/pgp/bootstrap` into `lib/pgpSession`. Nothing unlocks at login — the
  prompt appears the first time something needs the key, so a user who never
  opens encrypted mail is never asked. Logout clears the vault.
- **Security page**: browser-side generate and import, protection-mode
  status, unlock/lock, and the one-time migration for legacy keys. Both
  creation paths warn that an admin password reset destroys the key.
- **Read page**: fetches ciphertext from `/api/mail/pgp-payload` and decrypts
  locally; the signature verdict comes from that decrypt, not the server.
- **Compose**: resolves recipient keys via
  `/api/pgp/recipients/resolve`, encrypts per delivery group (BCC each in its
  own), posts to `/api/mail/send-pgp`. **Refuses** when a recipient has no
  usable key rather than downgrading — the pickup-link fallback stores
  plaintext on the server, which is what this mode prevents.
- **Password change**: rewraps the key, unwrapping before the password write
  so a failure leaves nothing half-applied.

Still open:

- Browser-side send-as User ID reconcile. The daemon skips client-protected
  keys (adding a User ID re-signs the key and needs the private half), so an
  alias verified after key creation is not yet added to the key. Until that
  lands, regenerate the key after verifying a new alias if you need WKD or
  Autocrypt to serve it for that address.
- **Nothing here has been exercised against a real IMAP server or a real
  recipient.** The unit and HTTP-level tests pass; an end-to-end manual run
  is still required before relying on this.

Because the default is unchanged, this is safe to ship incrementally: existing
installs keep working exactly as before, and nothing silently downgrades.

## Mobile plan

Both apps need the same three capabilities. Neither can keep using the
server-side decrypt path once its user migrates, because there will be
nothing on the server to decrypt with.

### Shared contract

1. `GET /api/pgp/bootstrap` on every launch — see Cold start above. This
   replaces the older advice to call `/api/pgp/identity/wrapped` directly;
   that endpoint still exists for a re-unlock after an explicit lock, where
   pulling the whole address book again would be wasteful.
2. If `protection == "client"`, unwrap locally with the account password:
   PBKDF2-HMAC-SHA256, iterations and salt from the envelope, AES-256-GCM.
   The envelope is self-describing; do not hardcode 600,000.
3. Messages arrive with `pgpEncrypted: true` and an empty `pgpDecryptError`.
   The ciphertext is **not** inlined in the inbox row — fetch it per message
   from `GET /api/mail/pgp-payload?mailbox=&messageId=<uid>`, which also
   returns `signerPublicKeys` for verification. An earlier version of this
   document said the payload arrived inline; it never did.
4. Sending encrypted: build the ciphertext on device and POST to
   `/api/mail/send-pgp` with one delivery per recipient group, BCC recipients
   each in their own. Each delivery must be a **complete RFC 5322 message** —
   From, To, Subject, Date, MIME-Version, Content-Type — because the server
   relays the bytes verbatim and synthesizes nothing. It now rejects a
   delivery missing any of those rather than sending malformed mail. Put the
   real subject inside the encrypted part as a protected header and use the
   placeholder `[Encrypted] Email Sent by KyPost` outside, matching both
   other send paths.

### kypost-android

- **KDF/AEAD:** `javax.crypto.SecretKeyFactory` with
  `PBKDF2WithHmacSHA256`, then `Cipher.getInstance("AES/GCM/NoPadding")`.
  Both are in the platform; no new dependency.
- **OpenPGP:** Bouncy Castle (`org.bouncycastle:bcpg-jdk18on`), which the
  Android ecosystem already uses widely. Do not attempt to reuse OpenKeychain
  via intents — that puts the key in another app's custody and reintroduces
  the same "who actually holds it" question.
- **Key storage at rest:** keep the wrapped envelope in app-private storage.
  The unwrapped key should live in memory only, cleared in `onTrimMemory`
  and on logout. Do *not* put the unwrapped key in the Android Keystore
  "for convenience" — that makes it recoverable without the password, which
  is the property being removed.
- **Unlock UX:** prompt at first PGP operation after app start, not at
  launch, so users who never touch encrypted mail never see it. Optionally
  gate a short-lived in-memory cache behind `BiometricPrompt`.
- **Push:** already generic by default; nothing to change. The notification
  carries only `messageId`, so tapping it syncs and then decrypts on device —
  which is the correct flow anyway.
- **Order of work:** wrapped-key fetch and unwrap → decrypt on read →
  encrypt on send → migration prompt.

### kypost-Linux / kypost-for-Mac (Qt)

- **KDF/AEAD:** Qt has no PBKDF2 primitive worth using here; link OpenSSL
  directly (`PKCS5_PBKDF2_HMAC` with `EVP_sha256`, then
  `EVP_aes_256_gcm`). Both desktop targets already ship against OpenSSL for
  TLS.
- **OpenPGP:** GPGME via `gpgme++`, or Sequoia's C API. GPGME is the lower
  friction path on Linux; on macOS it means bundling GnuPG, so Sequoia may
  be the better single choice for both.
- **Key storage:** the wrapped envelope goes in the app config dir. Do not
  put the *unwrapped* key in the platform keychain (Secret Service /
  Keychain Access) — same reasoning as the Android Keystore note.
- **Unlock UX:** a modal on first PGP operation, with an explicit "this
  is your account password, not a separate PGP passphrase" line, because
  users who imported a passphrase-protected key will expect the old one.
- **Order of work:** identical to Android.

### Migration for existing mobile users

A user who migrates on the web will find their phone unable to read encrypted
mail until the app is updated. The apps should detect `protection == "client"`
with no local unwrap support and show a clear message ("this account's key is
end-to-end protected; update the app to read encrypted mail here") rather
than surfacing a generic decryption failure. Add that check first, ahead of
the crypto work, so an old app fails legibly.
