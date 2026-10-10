# KyPost platform baseline

What a client must implement to call itself a KyPost client.

This exists because there are three independent client implementations —
browser, Android, and Qt/Linux — against one server, and until now nothing
stated what they owed each other. A user cannot tell which combinations work,
and neither could we.

**Scope.** This describes the contract, not the version numbers. Platforms are
aligned to 0.4.0 once, at launch, and are then free to drift against the
compatibility matrix at the end of this document. There is no permanent
lockstep: coupling the numbers forever means a one-line Linux fix cannot ship
without bumping the server and Android too.

Every line below is a claim about code in this repository, cited so it can be
checked rather than believed. Where a section is marked **NORMATIVE**, the bytes
are part of a wire format shared across implementations, and changing them is a
compatibility break that must move a version tag with it.

---

## 1. Pairing

Native sign-on through `POST /api/auth/native/signon` accepts a provider-issued ID token with positive `iat`, at most 30 seconds ahead of the server and at most five minutes old, in addition to signature/issuer/audience/origin checks. Keep provider/server clocks synchronized; refusal is HTTP 403 without a pairing grant. Clients obtain the signed token from the provider rather than constructing timestamps.

A device joins an account by scanning a QR code, or by following the same
string as a deep link. The payload is one URI:

```
kypost://native-pair?sub=&hash=&srv=&reg=&pt=&pin=
```

Built by `frontend/src/pages/security/pairingLink.ts:15`. Every client
registers as the system handler for the `kypost://` scheme — Flatpak's
`x-scheme-handler/kypost`, Android's `native-pair` intent filter.

| Param | Meaning | Required |
| --- | --- | --- |
| `sub` | Subscriber id | yes |
| `hash` | Subscriber hash | no |
| `srv` | `SERVER_BASE_URL` — the public URL of the server | no |
| `reg` | Registration endpoint | no |
| `pt` | Single-use signed pairing token | no |
| `pin` | Leaf SPKI certificate pin | no |

**A client MUST ignore parameters it does not recognise.** This is what makes
the payload extensible, and `pin` is the first test of it: a client that
predates `pin` and skips over it pairs exactly as it did before.

### `pin=` — certificate pinning, and why absent is not a failure

The registration call is the one request that carries the pairing token, the
push endpoint and the WebPush keys together. Without a pin the client discloses
all of it inside a trust-on-first-use window — the certificate is only trusted
*after* the secrets are already gone. On a network with a locally trusted CA
(enterprise MDM, a user-installed root, a hostile captive portal), an
interceptor reads the token, registers its own device first, and hands back
credentials it controls. Hostname validation does not help; this is what
pinning is for. See `backend/internal/api/pairing_pin.go:1-16`.

Client requirements:

- **Absent `pin` MUST mean trust-on-first-use**, not an error. The server omits
  it whenever it cannot establish the serving certificate — a deployment behind
  a private CA gets no pin, and that operator's answer is not a broken pairing.
  (`server_notifications.go:374-377` only sets it for `https://` endpoints.)
- **A `pin` that does not match MUST fail closed.** Refuse to register. A pin
  the client cannot vouch for is worse than none, so the server only publishes
  pins it probed itself.
- **Decode the value as a percent-encoded string.** It is base64, so it
  contains `+`, `/` and `=`. A bare `+` in a query string decodes to a space,
  which corrupts roughly half of all pins — and since a malformed pin fails
  closed rather than degrading to TOFU, getting this wrong breaks pairing
  outright. Use a real URI parser.
- The format is OkHttp's `CertificatePinner.pin()` — base64 SHA-256 of the leaf
  SPKI (`pairing_pin.go:54`).

### Registration

`POST /api/notifications/native/register`, authenticated by the pairing token
from `pt` rather than by a device credential — registration is what creates the
device, so there is no device secret yet (`server.go:651-655`).

The response carries `subscriberId`, `serverBaseUrl`, `registerEndpoint`,
`pullEndpoint`, `deliveryMode`, `pairingTtlSeconds` and `configured`
(`server_notifications.go:378-386`).

`deliveryMode` is learned here, and that has a consequence a client must handle
— see §4.

---

## 2. Device enrollment — **NORMATIVE**

Enrollment seals the account's PGP private key to a paired device. The full
normative spec is
[`docs/superpowers/specs/2026-08-04-device-enrollment-design.md`](superpowers/specs/2026-08-04-device-enrollment-design.md);
the reference implementation is `frontend/src/lib/deviceEnrollment.ts`, and the
Android side is `EnrollmentCodeFormat.kt` in the Android repo.

**The security of this feature is one comparison.** The server stores and serves
the device's public key, so the server is the party that can substitute its own
and then open anything sealed to it. The device derives a short code from the
key in its own keystore, which the server cannot influence; the browser derives
it from the key the server handed over. If they differ, the server substituted.

- **The browser MUST verify before sealing, and the check MUST gate the seal**
  rather than merely report on it. Verifying on the device is too late: by then
  the browser has already sealed to the attacker's key.
- Do not model this on server-side number matching. There the server knows the
  right answer; here the server is the adversary, and a server-side check would
  be decoration.

### Code derivation

```
code = crockford32( first 70 bits of
         SHA-256( rawPubKey ‖ uint16BE(len(deviceIdUtf8)) ‖ deviceIdUtf8 ‖ uint64BE(bucket) ) )
```

| Constant | Value | Source |
| --- | --- | --- |
| Public key | raw 65-byte uncompressed SEC1 point, `0x04 ‖ X(32) ‖ Y(32)` | `deviceEnrollment.ts:59` |
| Bucket | `floor(unixSeconds / 120)` | `deviceEnrollment.ts:27,110` |
| Code length | 14 characters | `deviceEnrollment.ts:53` |
| Code bits | 70, five per character, most-significant first | `deviceEnrollment.ts:54` |
| Alphabet | Crockford base32, `0123456789ABCDEFGHJKMNPQRSTVWXYZ` | `deviceEnrollment.ts:30` |

Two details are load-bearing across implementations:

- **Hash the raw 65 bytes, never the base64 text.** Hashing the transport
  encoding makes padding or alphabet drift a silent mismatch — which presents to
  the user as "this server is hostile", the most alarming message in the
  product.
- **70 bits, not 50.** There is no commitment step: nothing the browser
  contributes enters the preimage, so the search is entirely offline and this is
  a work factor rather than a per-attempt probability. An adversary who can
  write the device table grinds a key or `deviceId` whose code collides at a
  chosen future bucket, then waits for it.

### Verification window

Accept the **current bucket and the immediately preceding one, and never a
future one** (`deviceEnrollment.ts:258-259`). The phone may render just before a
boundary the browser has already crossed. Accepting a window that has not
started lets an attacker precompute into it.

### Display and transcription — **NORMATIVE**

- Group as `4-3-4-3`: `5R9K-6FW-A18A-8YP` (`deviceEnrollment.ts:204`). Every
  client that displays the code must group identically. A display disagreement
  between two screens showing the same code reads to the user as the codes not
  matching, which is this feature's one alarm.
- Normalise typed input by Crockford's decode rules before comparing:
  uppercase, strip whitespace and `-`, `I`/`L` → `1`, `O` → `0`
  (`deviceEnrollment.ts:184`).
- Compare without early return (`deviceEnrollment.ts:228`).

### Envelope retrieval

`GET /api/pgp/device/envelope` returns `{slot, envelope}` for
`device:<deviceId>`, or 404 with `{"error": "no envelope sealed for this
device"}` (`pgp_device_enrollment.go:93-114`). Expired envelopes read as absent
rather than being served.

Also on this surface: `POST /api/pgp/device/enrollment-key` publishes the
device's public key, and `POST /api/pgp/device/enrollment-state` reports
progress.

---

## 3. Device credentials

After registration a device authenticates every ongoing request — mail sync,
contacts sync, App Pull, push-MFA approval, self-deregistration — with two
headers:

```
X-Kypost-Device-Id:     <client-chosen id>
X-Kypost-Device-Secret: <minted at registration>
```

`backend/internal/api/device_auth.go:14-25`. Each device has its own secret.
**There is no account-wide shared secret and no query-parameter fallback.**

`deviceId` requirements (`device_auth.go:207-246`):

- ASCII only, from `[a-zA-Z0-9._:-]`. Not a style rule — the id enters the
  enrollment hash preimage, and if any implementation normalises differently
  (NFC vs NFD) the derived codes never match. An encoding bug would present to
  the user as an attack.
- At most 128 bytes as an id (`maxDeviceIDLen`), and the id becomes the
  `device:<id>` envelope slot name, so the two bounds must agree.

Minted secrets are a fixed 192-bit random value.

---

## 4. Push delivery modes

Two modes, account-wide (`backend/internal/state/store.go`, `DeliveryModePush` / `DeliveryModePull`):

| Mode | Path |
| --- | --- |
| `push` (default) | server → Cloudflare Worker relay → FCM/APNs → device |
| `pull` | device polls `GET /api/notifications/native/pull` over plain HTTPS; the relay is not involved at all |

**Every client MUST implement `pull`.** It is the mode that works with no
Firebase, no relay, and no third-party infrastructure in the notification path
— it is what a self-hoster who does not want notification metadata leaving their
server uses, and it is the fallback when the relay is unavailable. Note that
`deliveryMode` is account-wide, not per-device: flipping it to `pull` moves
every one of that user's devices, which is why a Firebase-free build reaches for
UnifiedPush rather than for `pull` alone.

Server-side notes a client should know:

- **Every notification is written to the pull queue in both modes**
  (`processor/push_dispatch.go`, `SendNativePushToDevices`). A client in
  `push` mode SHOULD poll `GET /api/notifications/native/pull` with its saved
  cursor when it has received no push for a while, so a relay outage degrades
  to delayed delivery instead of silence, with no server-side mode change.
- Each queued entry records the devices it was addressed to and the pull
  endpoint serves a device only its own entries (push-MFA challenges go to
  approver devices only). The cursor is the account-wide sequence, so a device
  advances past entries meant for others.
- The pull queue is bounded at 100 entries per user; the oldest are dropped
  (`state/store.go`, `maxPullNotifications`). A device offline long enough
  loses the tail.
- Notification content defaults to a bare "You have a new email." with no
  sender, subject or keyword. Previews are opt-in per account.
- `deliveryMode` is delivered at registration (§1) and also on the pairing and
  preferences endpoints (`server_notifications.go:383,656,685,883`).
  `PUT /api/notifications/native/mode` changes it.

### UnifiedPush: the WebPush key exchange is REQUIRED

A device registering with `transport: "unifiedpush"` SHOULD send the WebPush
(RFC 8291) subscription keys its connector generated for the endpoint, as two
extra fields on the registration request:

| Field | Value |
| --- | --- |
| `p256dh` | the uncompressed P-256 public point, 65 bytes, base64 |
| `auth` | the 16-byte auth secret, base64 |

Both or neither. A partial pair is rejected with `400`
(`processor.ValidateWebPushKeys`), as is a `p256dh` that is not a point on the
curve. Padded and unpadded, standard and URL alphabets are all accepted — the
check mirrors what the sender would later accept, so validation can never refuse
material that would have worked.

Two things follow from sending them, and neither is optional in practice:

1. **The payload is encrypted.** With keys stored, the server sends aes128gcm
   ciphertext (`processor.UnifiedPushSender`). Without them it falls back to the
   plaintext JSON POST it has always sent, so an older client keeps working —
   but the notification's title and body then cross the distributor's broker in
   the clear. A public broker is a third party; treat the fallback as a
   compatibility shim, not a supported configuration.
2. **Push-MFA depends on it.** `api.MFATransportEligible` allows an MFA
   challenge over UnifiedPush only for a device that supplied keys. A challenge
   carries the sign-in IP, the user agent and the match digits, so a keyless
   UnifiedPush device is excluded and its user cannot approve logins from it.

The VAPID identity is the one already used for browser Web Push; here it only
signs the `Authorization` JWT, which most distributors do not check.

**The known gap:** a device that registered in `push` mode and is waiting on FCM
does not learn about a server-side flip to `pull` — the change does not reach
it. Closing that needs an automatic switch plus a client-side heartbeat, tracked
as issue #137. Until then, a mode change requires the device to re-check.

---

## 5. Contact sync

`GET` and `POST /api/contacts/sync`, both on device credentials
(`contacts_handlers.go:512`).

- `GET ?since=<cursor>` returns changes after that cursor.
- `POST` pushes local changes. At most 500 changes per request
  (`contacts_handlers.go:510`); over that the server answers 413 with
  `{"error", "maxChanges"}`. **A client MUST batch** rather than assume its
  local set fits.
- Request bodies are read under a 1 MiB limit; a larger body also answers 413,
  with `{"error", "maxChanges", "maxBytes"}`. Split the batch on any 413; a
  single change that alone exceeds `maxBytes` cannot be pushed. Malformed
  JSON stays 400.

---

## 6. PGP behaviour

A client that handles mail must, at minimum:

- Treat a **broken key pin as a refusal to send**, never a downgrade.
  `AllowPickupFallback` does not override it
  (`server_mail_send.go:635`).
- Distinguish *present* from *usable* on a key. A key record can carry
  `Usable:false`, and collapsing that into "we have a key" produced a real bug
  (`server_mail_send.go:203`).
- Render the enrollment envelope flow of §2 for E2E key custody.

See [`docs/E2E_PGP.md`](E2E_PGP.md) for the full model, and
[`docs/WKD_Publishing.md`](WKD_Publishing.md) for key discovery.

**Calendar invites.** `GET /api/mail/attachments` lists every `text/calendar`
part. An iMIP invite carried as an undisposed `multipart/alternative` part
(Google, Outlook) is listed after the real attachments as
`{"name":"invite.ics","mimeType":"text/calendar","calendarMethod":"REQUEST"}`
— existing indexes do not move. `calendarMethod` is the object's uppercase
`METHOD` (`REQUEST`, `CANCEL`, `REPLY`, ...), absent when missing or not a
plain token; attached `.ics` files with `mimeType` `text/calendar` carry it too.
Downloads serve `Content-Type: text/calendar` with `Content-Disposition:
attachment` and `nosniff`. Parse the bytes as untrusted input. Inbox rows set
`hasAttachments: true` for a message with such a part (IMAP: from one batched
`BODYSTRUCTURE` fetch per list request, only for messages with no other
attachment), so a client may fetch attachments only when it is true. Rows
cached before the server had this keep their old value until re-warmed; a
server without it reports `false` for invite-only mail.

**RSVP.** `POST /api/mail/send` accepts `calendarReply: {"ics": "<iCalendar>"}`
and sends it as a `text/calendar; method=REPLY; charset=UTF-8` part in
`multipart/alternative` beside the body (inside `multipart/mixed` when there
are attachments). The object must be ≤64 KiB UTF-8 with no control
characters, one `VCALENDAR` with exactly one top-level `METHOD:REPLY` and
exactly one `VEVENT`; line endings are normalised to CRLF. The server does
not check UID/SEQUENCE/ATTENDEE — copy them from the invite. A refusal is 400
with the reason; `encrypt` or `sign` with `calendarReply` is 400 (an
organizer's calendar cannot read a PGP-wrapped reply). Address it to the
invite's ORGANIZER; drafts ignore the field. A successful send that carried
the part answers `"calendarReply": true` beside `ok`/`sentSaved`/`warning`.
A server without RSVP support ignores the field and sends a plain email with
no `calendarReply` in the response: treat a 200 without it as "RSVP not
delivered" and tell the user.

---

## 7. Inbox listing and message bodies

Opt-in native mailboxes use opaque string `messageId` references of the form
`n1:<mailbox-reference-generation>:<internal-id>`. Copy the exact string into
body/attachment/PGP reads, inbox actions and webmail links; never convert it to
a number or construct it from an internal UID. This format is identity, not
authorization: existing account/device/folder admission still applies. Offline
restore rotates the generation independently of encryption namespaces; prior or
foreign generations and bare decimal native references return 400 before reads.
Actions retain the batch response and report each rejected ID in `failed`, with
no mutation. Refresh that mailbox on stale-reference errors, never retry using
a stripped numeric suffix. Persisted notification history keeps its original
references, so tapping an old notification may require a fresh sync.

A KyPost administrator identity owns no native mailbox. Mail routes answer it,
by session or device credential, with 403 and `"administratorIdentity": true`
(message "administrator identities have no mailbox; use your everyday
identity"). This is not a credential failure: keep the session and device
pairing, show the message, and do not retry; access returns if the identity is
demoted. 401 keeps its existing meaning.

Existing external IMAP message IDs and cursors remain unchanged. Native
mailboxes retain numeric internal IDs and return live full
snapshots (`delta:false`, `cursor:0`) for every inbox request, including positive
`since` and classic requests. Clients replace that requested window and must not
interpret it as an empty delta. Source/database mismatches answer 409 with an
`error` explaining that switching is disabled; do not retry against another
source or erase local state to bypass it. Native source selection is explicit; existing linked IMAP accounts stay external. Durable scoped native deltas
and live client acceptance remain activation gates.

`GET /api/inbox` returns message bodies by default and will keep doing so — the
Android and Qt clients read `body` off the list rows today, and removing it
would break them silently.

A client that renders bodies only in an opened message should send **`bodies=0`**
and fetch each body on demand from **`GET /api/mail/body?messageId=<opaque-reference>&mailbox=<path>`**,
which answers `{"body": "...", "bodyMode": "html"|"plain"}`
(`backend/internal/api/mail_body.go`). Missing messages return 404, oversized
messages return 413, and an adapter-reported MIME parsing failure returns 422
with `error`; original mail is retained. Treat 422 as an unreadable body,
not a successful empty message. Metadata listing can still show that message.

The reason is size. Measured against a 500-message window of ordinary HTML mail
(`backend/internal/api/inbox_payload_size_test.go`, run with `-v`):

| | uncompressed | gzip |
| --- | --- | --- |
| default (`bodies` unset) | 13.3 MiB | 1.5 MiB |
| `bodies=0` | 183.9 KiB | 3.1 KiB |

The browser re-requests that window every 15 seconds, so the default costs
~53 MiB/min on an idle open tab.

Two things a client must keep in mind when it opts out:

- **`bodyMode` comes with the body, and only from the same response.** Do not
  re-derive it by sniffing the text — RFC 5322's own `<user@example.com>`
  address form parses as an unknown tag and the address disappears
  (`adapters/imap/client.go:1480`).
- **PGP mail still needs `/api/mail/pgp-payload`.** `/api/mail/body` returns
  what the server can see, which for an encrypted message is nothing under
  either protection mode (§6). A signed message whose verification fails must
  fall back to the server's copy rather than showing the reader nothing, so
  fetch both.

Responses from `writeJSON` are gzipped when the client sends `Accept-Encoding:
gzip` and the payload is at least 1 KiB (`backend/internal/api/gzip.go`). A
client that does not send the header gets identical bytes to before.

**Older mail.** `GET /api/inbox?mailbox=<path>&limit=N&before=<messageId>`
returns the next `limit` messages older than `messageId` (exactly as a list row
gave it), newest first, as `{tabs, byTab, hasMore, nextBefore}`. Rows are
metadata only — no `body`, `bodyMode`, `hasAttachments` or PGP flags, and an
encrypted message shows its outer subject — like `/api/mail/search`; open a
message through `/api/mail/body`. `hasMore` says older mail remains;
`nextBefore` (absent on an empty page) is the `before` for the next page. The
page has no `cursor`/`delta`/`removed`, ignores `since`, and never changes the
cursor window. A malformed or stale reference answers 400; refresh the window.

[`docs/INBOX_PAYLOAD_HANDOFF.md`](INBOX_PAYLOAD_HANDOFF.md) is the porting
guide: what each client has to change, and the three things that break if you
only do the obvious half.

---

## 8. Anti-phishing: the `kypost://` scheme in mail

Every client registers as the system handler for `kypost://`. That means an
`<a href="kypost://native-pair?srv=https://evil.example&pt=...">` inside a
received message is a one-tap account takeover attempt
(`backend/internal/processor/phish_scan.go:20-22`).

The server scans inbound mail for this and flags it. **A client rendering HTML
mail must not silently follow or auto-activate `kypost://` links from message
bodies** — including the uppercased `KYPOST://` form, which some parsers miss
(`frontend/src/lib/emailHtml.ts:65`).

---

## 9. Compatibility matrix

Platforms align to 0.4.0 at launch and drift afterwards against this table.
Update it in the same change that breaks or adds a contract above.

| Contract | Server | Browser | Android | Linux (Qt) | Apple (macOS/iOS) |
| --- | --- | --- | --- | --- | --- |
| Pairing URI, unknown-param tolerance | 0.3.0 | 0.3.0 | 0.3.3 | 0.2.0 | 0.4.0 |
| `pin=` published / honoured | 0.3.0 | 0.3.0 | 0.3.3 | ❌ TOFU instead | 0.4.0 |
| Enrollment code, 14 chars / 70 bits | 0.3.0 | 0.3.0 | 0.3.3 | ✅ | ✅ |
| Device credential headers | 0.3.0 | n/a | 0.3.3 | ✅ | ✅ |
| `pull` delivery mode | 0.3.0 | n/a | 0.3.3 | ✅ | ✅ |
| Contact sync, 500-change batching | 0.3.0 | n/a | ❌ sends one request | unverified | 0.4.0 |
| `bodies=0` + `/api/mail/body` | 0.4.0 | 0.4.0 | not adopted | not adopted | not adopted |
| Native mailbox selection (`/api/mailboxes`, `X-KyPost-Mailbox`) | unreleased | unreleased | not adopted | not adopted | not adopted |

The Apple client is unreleased; `0.4.0` is the version it will first ship as,
set in `MARKETING_VERSION`. It is one target building both macOS and iOS, so
there is no useful way to split the column.

> Linux was reported ungrouped on 2026-08-25. That report was wrong: it read
> `Settings.qml`'s raw property binding without following
> `PgpEnrollmentController.cpp:107`, which applies `formatEnrollmentCode`
> before the value reaches QML. The helper has been present since `e92b16b`.

Linux evidence, verified against the client tree at `e1a1a9c` (paths relative
to the `kypost-Linux` repo root):

- Pairing URI, unknown-param tolerance — `app/pairing/PairingController.cpp:130-148`
- `pin=` **not** honoured — `app/pairing/PairingController.cpp:141-144` reads `sub`, `srv`, `pt`, `reg` and stops. `core/net/CertificatePinSink.cpp` captures a pin from the registration reply's own handshake, which is TOFU done carefully; it is not the published pin.
- Enrollment code: 14 chars / Crockford / 65-byte key — `core/pgp/DeviceEnrollmentCrypto.cpp:17,127,144-158`
- Enrollment display grouping (`4-3-4-3`) — `core/pgp/DeviceEnrollmentCrypto.cpp:156-162`, `app/pgp/PgpEnrollmentController.cpp:107`
- Enrollment bucket size 120 s — `app/pgp/PgpEnrollmentController.cpp:108`
- `transport` sent explicitly, `"unifiedpush"` — `core/net/NativeRegistrationClient.cpp:43`
- Device credential headers — `core/net/RelayAuth.h:22-23`
- Contact sync — `core/net/ContactSyncClient.cpp:215`
- Delivery modes, `push`/`pull` — `app/pairing/PairingController.h:129-130`

Apple evidence, verified against `kypost-for-Mac` at `26230d3` (paths relative
to that repo root):

- Pairing URI, unknown-param tolerance — `KyPost/Presentation/Shared/Navigation/DeepLinkHandler.swift:72-111`
- `pin=` honoured — `KyPost/Data/Networking/SpkiPin.swift` normalises the
  published `sha256/<base64>` to the lowercase hex the delegate compares, and
  `DeviceRegistrationService` arms it on the transport **before** the
  registration POST, since that request is what discloses the pairing token. A
  malformed pin is refused rather than silently downgraded to TOFU, matching
  Android. Added 2026-08-27; it read four parameters and ignored this one
  before that.
- Enrollment code: 14 chars / Crockford / 120 s buckets — `KyPost/Domain/Security/DeviceEnrollmentCode.swift`
- Enrollment display grouping (`4-3-4-3`) — `DeviceEnrollmentCode.swift:92-105`, corrected 2026-08-27; it was two groups of seven before that
- Device credential headers — `KyPost/Data/Networking/RelayAuth.swift`
- Delivery modes, `push`/`pull` — `KyPost/Domain/Push/PullPollingScheduler.swift`
- Contact sync, 500-change batching — `KyPost/Domain/Repositories/ContactSyncRepository.swift`
  pages at the limit, holding `baseCursor` still across pages and reconciling
  after each one. Added 2026-08-27; it sent one unbounded request before that.

**Android does not batch this either**, contrary to the `0.3.3` this row
carried until 2026-08-27. `ContactSyncRepository.kt:67` pushes the whole
pending list in one request, there is no `chunked`/`windowed` anywhere in its
contacts path, and `ContactSyncClient.kt` maps 413 through the generic
`Retryable` branch — so an address book over the limit does not fail once and
stop, it retries forever. The Apple client is currently the only one that
pages.

`unverified` remains honest for the one row still marked that way: only the
contact-sync pull path was read, and the push-path 500-change batching limit
has not been checked. For `pin=`, verification found a real gap rather than an
absence of information — Linux never honours a provided pin and always falls
back to trust-on-first-use, which costs what §1 describes on a network with a
locally trusted CA.

---

## Changing any of this

1. If a **NORMATIVE** section changes, it is a wire-format break. Move the
   version tag in the relevant spec, and land the client changes before the
   server change reaches a release.
2. Additive parameters are safe *because* clients ignore what they do not
   recognise. Keep it that way — never make an existing field's absence an
   error.
3. Update the matrix in the same change.

## Native primary-address outbound compatibility

In explicit native mode, ordinary compose and client-prepared PGP retain their
existing request/authentication contracts. Send responses add `outboxId` while
`ok:true` still means confirmed primary SMTP acceptance; 503 means unconfirmed
primary submission, even if intent was persisted. Inspect the owner-scoped
`GET /api/mail/outbox/{id}` before creating another intent. Sending twice cannot
repair pending Sent filing. Converted PGP generation/device-enrollment gates and
client custody remain unchanged. Additively, the existing optional `from` field
may name any `active` alias an administrator gave the caller's mailbox (case is
ignored); omitted or empty still means the primary. Any other `from`, including
a released or another mailbox's address, stays 403, and client-prepared PGP MIME
must carry that same `From`. Native pickup/system sends remain pending; see
[NATIVE_OUTBOX.md](NATIVE_OUTBOX.md). Existing external IMAP is unchanged.

## Native mailbox selection (additive)

A native user may own extra mailboxes an administrator created. Old clients
are unchanged: without the header below every route serves the primary mailbox.

- `GET /api/mailboxes` (session or device credential) answers
  `{"mailboxes":[{"id","kind":"primary"|"extra","addresses":[{"address","kind":"primary"|"alias"}]}]}`
  with the primary first and only `active` addresses. Disabled mailboxes are
  omitted; a non-native account gets an empty list. The primary's `id` is the
  account's user ID. Each mailbox also carries `quotaBytes` and `usedBytes`
  (absent when the server cannot read it), additive; clients may show usage
  and warn at 80% and 95%, as the web client does.
- Mailbox-scoped routes accept `X-KyPost-Mailbox: <id>`: `/api/inbox` and
  `/api/inbox/folders`, `/api/inbox/actions`, `/api/mail/search`,
  `/api/mail/draft`, `/api/mail/send`, `/api/mail/send-pgp`,
  `/api/mail/outbox/{id}`, `/api/mail/body`, `/api/mail/pgp-payload`,
  `/api/mail/attachments`, `/api/mail/attachment`, `/api/rules/run`,
  `/api/decisions` and `/api/export/folders` (web export and import, which
  name the mailbox in their `POST /api/export`, `POST /api/import` and
  `POST /api/import/imap` bodies; the IMAP grant's folder and start routes
  take the mailbox from the grant). An
  absent header or the primary's ID selects the primary. An unknown, foreign or
  disabled mailbox answers `404 {"error":"mailbox not found"}`, identical for
  all three: drop the mailbox from the local list and refresh
  `GET /api/mailboxes`; do not retry. Message references are per mailbox; never
  send one to another mailbox. `from` names an active address of the selected
  mailbox (omitted means its primary address).
- Every other route (devices, pairing, notifications, contacts, CardDAV, PGP
  keys, settings, rule definitions, labels, import status and cancel) is per
  user and ignores the header;
  `/api/labels` reports labels discovered in the primary mailbox only.
- `PUT /api/pgp/incoming` with `enabled:true` answers 409 with an explanatory
  `error` while the user has any additional mailbox: incoming encryption covers
  the primary only. Show the text; do not retry.
- Push data and pull notifications for native mail carry an additive `mailbox`
  field (the mailbox ID; web push payloads too). Select that mailbox before
  opening the referenced message. Older notifications have no field: they
  belong to the primary.
- Android adopts selection first; other clients keep the primary-only view.

## Native CardDAV recovery

Native account CardDAV Basic auth returns the existing 401 challenge while a
restore hold is present, including when the password was cached. Offline native
restore revokes the historical CardDAV app password; after qualified recovery,
configure a new app password in each CardDAV client. Contact data remains retained.
Legacy IMAP accounts keep their existing CardDAV behavior. This does not authorize
restore hold release; see [RESTORE.md](RESTORE.md).
