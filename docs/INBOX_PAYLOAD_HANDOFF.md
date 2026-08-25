# The inbox payload handoff: `bodies=0` across clients

## Why this exists

`GET /api/inbox` sends every message body in the window. The list rows render
none of them — only the opened message shows text — so a client displaying one
message downloads five hundred.

Measured against a 500-message window of ordinary HTML mail
(`backend/internal/api/inbox_payload_size_test.go`, run with `go test
./internal/api/ -run TestInboxPayloadSize -v`):

| | uncompressed | gzip |
| --- | --- | --- |
| default (`bodies` unset) | **13.3 MiB** | 1.5 MiB |
| `bodies=0` | 183.9 KiB | **3.1 KiB** |

Per-message body size drives this almost linearly: at 120 KiB average bodies the
default window is 79.0 MiB. `bodies=0` is flat at 3.1 KiB because what remains
is metadata, and metadata compresses.

The browser re-requests the window every 15 seconds, so the default also costs
~53 MiB/min on an idle open tab. Every client that polls pays the same.

The server side shipped with this document. **No client is required to change** —
the default response is unchanged, byte for byte, for a client that does not opt
in. This is what to do when you want the other 99%.

---

## What the server now offers

Two changes, both additive. The normative wording is
[`PLATFORM_BASELINE.md` §7](PLATFORM_BASELINE.md); this is the porting guide.

**1. `GET /api/inbox?bodies=0`** omits `body` and `bodyMode` from every row, on
every path — warm cache, live fetch, and both halves of the `since=` delta.

**2. `GET /api/mail/body?messageId=<uid>&mailbox=<path>`** returns one body:

```json
{ "body": "<p>…</p>", "bodyMode": "html" }
```

`bodyMode` is `"html"`, `"plain"`, or absent. Same auth as the rest of the mail
surface (session cookie or device credentials), same `messageId`+`mailbox` pair
the attachment endpoints already take — so whatever builds your attachment URL
builds this one. Errors: `400` bad `messageId`, `404` no such message, `413`
message too large to hold in memory, `502` IMAP failed.

**3.** Unrelated but free: JSON responses of 1 KiB or more are gzipped when the
request carries `Accept-Encoding: gzip`. If your HTTP stack sets that header
(URLSession and Qt Network both do by default; OkHttp does unless you set it
yourself), you already have the middle column of the table above with no code
change at all. **Check this before doing anything else** — it may be enough.

---

## What a client has to change

Two edits and three traps.

### The two edits

1. Append `&bodies=0` to the inbox request.
2. When a message is opened and its body is absent, `GET /api/mail/body` and
   render the result.

### Trap 1 — `bodyMode` travels with the body, and only with it

Take `bodyMode` from the same response as the body. **Do not sniff the text to
decide whether it is HTML.** A plain-text message containing
`<user@example.com>` — RFC 5322's own address form — parses as an unknown tag
and the address is deleted from what the user sees. The server already knows
the answer from the MIME parse; carry it
(`backend/internal/adapters/imap/client.go:1480`).

An absent `bodyMode` means "the server does not know", not "plain".

### Trap 2 — PGP mail still needs `/api/mail/pgp-payload`

`/api/mail/body` returns what the server can see, which for an encrypted
message is nothing under either protection mode — the server decrypts for
nobody now (`backend/internal/api/pgp_receive.go:54`). That is not a
regression: the inbox list carried nothing for those messages either.

The trap is the **signed-but-not-encrypted** case. A signed message whose
verification fails must fall back to the server's copy rather than costing the
reader the message — so fetch the body even for PGP mail, and keep it as the
fallback. Do not skip the body fetch on `pgpSigned`.

### Trap 3 — every path that renders a body, not just the reader

Grep for every consumer of the row's `body` field before you strip it. In the
browser these were not all in the reader:

- **Drafts.** Opening a draft goes straight into the composer without ever
  passing through the reader, so it needed its own fetch.
- **Reply / forward / print.** These quote the body. They worked only because
  they run on an already-opened message.
- **Search results.** These never carried a body at all
  (`backend/internal/api/server_inbox.go:992` builds them from `Overview`), so
  opening a search result showed "No message body available." Wiring the fetch
  to *selection* rather than to the inbox list fixed a bug that predates this
  work. Check whether your client has it too.

### One more thing

An in-flight or failed body fetch must not render as an empty message. "No
message body available." is only true when the server answered and had nothing;
a spinner and an error are different facts and the user can act on them.

---

## Per-platform starting points

The browser implementation is the reference:
`frontend/src/pages/ReadPage.tsx` (`fetchMessageBody`, the body effect, and the
draft branch of `openEmailDetails`) with
`frontend/src/pages/ReadPage.lazyBody.test.tsx` covering the traps above.

| | Browser | Android | Linux (Qt) | Mac (Swift) |
| --- | --- | --- | --- | --- |
| Inbox request | `ReadPage.loadInbox` | — | `MailRepository.cpp` | `RelayMailSource.endpoint()` |
| Row model with `body` | `read/types.ts` `InboxEmail` | — | `MailRepository::cachedEmails` | `RelayEmailDTO` |
| Status | **done** | not adopted | not adopted | not adopted |

The Linux and Mac cells come from the security-audit checkouts, not from a
current source read — the client repos are not in this checkout. Treat them as
where to start looking, not as verified line references. The Android column is
blank for the same reason and worse: nothing here has read it.

Two things worth knowing before you start:

- **The Mac client's `RelayEmailDTO.body` is already `String?`.** A `bodies=0`
  response decodes without a model change; it just arrives as `nil`, and
  `toDomain()`'s `body ?? ""` turns it into an empty message. So the opt-in is
  safe to add incrementally, but adding *only* step 1 ships an app where every
  message is blank. Land both edits together.
- **The Linux client's `since=` delta path is dead code.** A prior audit
  verified empirically that the stored cursor is never written in production, so
  every folder load sends no `since` and gets a full snapshot
  (`kypost-Linux/run-2/findings.json`). Do not assume the delta path already
  saves you anything.

---

## What not to do

**Do not drop `body` from the default response.** It is wire contract that three
shipped clients read. The opt-in exists so they keep working untouched until
each one chooses to move; a server-side default flip breaks every installed copy
of an app that has not shipped an update yet.

**Do not cache bodies indefinitely to avoid the fetch.** The point is not to
move the 13.3 MiB from the network into a database. Fetch on open, hold it while
the message is open, and let it go.

**Do not batch-prefetch the visible rows' bodies.** A screen of rows is 10-20
messages and the user opens one. Prefetching turns a 3.1 KiB list into a
300 KiB one to save a round trip the user usually does not make.

---

## After this: the `since=` cursor

`bodies=0` fixes the size of a load. It does not fix the *number* of loads —
the browser still re-sends the whole window every 15 seconds, and gets 3.1 KiB
back every time.

The server already implements a cursor protocol that answers **95 bytes** when
nothing has changed (`GET /api/inbox?since=<cursor>`, measured in
`TestInboxDeltaPayloadSize`). No shipped client uses it, in any platform. It is
the next thing worth doing and it is worth more than this was — but it is a
separate change with its own correctness questions (per-mailbox cursors, and
what a client does when the server's window has moved past it), so it is not in
this one.
