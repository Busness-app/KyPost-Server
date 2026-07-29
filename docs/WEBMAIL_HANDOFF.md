# The webmail handoff: launch mechanism across clients

## Why this exists

Every client that is not the browser has the same hole: a `client`-custody
account's private key lives only in webmail, so an encrypted message cannot be
read in the native app. All of them degrade the same way — mark the row, and
offer a link that opens webmail. `E2E_PGP.md` specifies *when* to do that
(items 1-8 of "What mobile apps must implement"). It says nothing about *how*
to open the link, and that turns out to matter.

`kypost-android` is changing its two first-party handoffs — reading a
client-protected message, and finishing a client-custody send — to open in a
Chrome Custom Tab. This document records what transfers to `kypost-Linux` and
`kypost-for-Mac`, and, more usefully, what does not.

The two handoffs are the same everywhere:

| | Android | Linux (Qt/QML) | Mac (Swift) |
|---|---|---|---|
| Read a client-protected message | `EmailDetailActivity.renderPgpBar` | `EmailDetail.qml:595` | `EmailDetailView.resolveWebmailURL` |
| Finish a client-custody send | `ComposeActivity.showHandoffDialog` | `MailController.cpp:582` | `SendEmailUseCase.webmailDraftsURL` |

## The headline: do not port Custom Tabs

There is no desktop equivalent, and the friction they remove is
mobile-specific.

On Android, leaving the app means a task switch: the app drops out of the
foreground, the user lands in a separate entry in the recents list, and coming
back is a deliberate act. A Custom Tab removes that — it is the user's real
browser, in a real browser process, rendered *over* the calling activity, with
the browser's own cookie jar (so the webmail session is already there) and no
ability for the app to read its contents.

On Linux and macOS, none of that applies. Alt-Tab and ⌘-Tab are free, windows
coexist, and `xdg-open` / `NSWorkspace` already hand the URL to the user's
default handler — which is the correct target precisely because that is where
the webmail session lives. **Keep using them.**

**Do not build an embedded `QtWebEngine` view or a `WKWebView` for webmail.**
Android ruled out an in-app WebView on two grounds: it shares no session with
the user's browser, and it would put an account-password field inside the app.
Both objections hold exactly as written on desktop. A Custom Tab escapes them
because it is not a WebView — that escape hatch exists on Android only.

## What does transfer

### 1. Native-handler precedence — free on desktop, do not implement it

Android has to do real work here. `CustomTabsIntent.launchUrl` targets a
browser and does **not** honour verified app links, so a user with the webmail
PWA installed would silently lose it. Android therefore probes for a
non-browser handler and ranks it above a Custom Tab.

On desktop this is already the platform's job: `xdg-open` and
`NSWorkspace.open` route to the user's default handler for that URL, including
a Chrome-installed PWA. There is nothing to add. Recorded so nobody
re-derives the problem and builds a solution for it.

### 2. The first-party origin guard — the genuinely portable piece

A URL built from the pairing should be *checked* to still belong to the
pairing before it is handed anywhere. Current state differs per client, and
one of the differences is a real gap:

- **Linux — strongest.** `webmailReadBase` (`app/mail/PgpMessagePresentation.cpp`)
  requires valid, non-relative, `https`, non-empty host, and explicitly clears
  any query and fragment carried by the base URL.
- **Android — adding one.** `isFirstPartyWebmailUrl` compares scheme, host and
  port against the pairing's `serverUrl`, enforced again at the launcher.
- **Mac — has a gap.** `webmailReadComponents`
  (`KyPost/Domain/Models/PgpMessageState.swift:100`) guards only
  `scheme != nil, host != nil`. It does not require `https`, and it does not
  clear a fragment on the base URL — `components.path += "/read"` then
  overwrites `queryItems`, but an existing fragment survives into the link.

The Mac gap is defence-in-depth rather than a live exploit: `DeepLinkHandler`
already refuses a pairing whose `srv` is not `https`
(`DeepLinkHandler.swift:85`), so in practice the base is https. But the
builder is the last place that can guarantee it, `PgpQrClient` and
`PinnedSessionDelegate` both check the scheme at their own boundaries, and
this one should too — for the same reason Linux does it in the builder
*and* Android does it again in the launcher.

**Guard placement is deliberately redundant.** The builder guarantees the URL
you constructed is sane; the launcher guarantees the URL you are about to hand
out is still the one you constructed. Do both. They fail differently.

### 3. Check the launch result — do not pre-flight it

Android is *removing* a pre-flight check. `Intent.resolveActivity` returns
null for an implicit `https` intent under `minSdk 31` package-visibility
filtering even when a browser is installed, so the read path could tell a user
"no webmail" when they had one — stalling the only route a client-custody
account has to the message. The rule that replaces it: **attempt the launch
and handle the failure**, never predict it.

Desktop equivalent — check the return value, because these calls can fail:

- **Linux, compose path** — `MailController.cpp:582` already checks
  `QDesktopServices::openUrl`'s `bool`. Correct; keep it.
- **Linux, read path** — `EmailDetail.qml:595` calls
  `Qt.openUrlExternally(root.email.webmailUrl)` and discards the result. It
  returns `bool`. A failed `xdg-open` — no default browser configured, a
  broken desktop entry, a sandboxed portal refusal — is currently silent, and
  this is the *only* route to that message. Surface it.
- **Mac** — check the result of `NSWorkspace.open` / the `openURL` completion
  handler on both paths, for the same reason.

### 4. Sender-controlled links stay on a separate path

Android's webmail links get a Custom Tab; links inside a message body
deliberately do not, and get `CATEGORY_BROWSABLE` plus a separate browser
instead. The reason is that a Custom Tab renders inside the app's task wearing
the app's toolbar colour, so a page opened in one reads as part of the app —
the right frame for the user's own webmail, and precisely the wrong one for a
URL chosen by whoever sent the email.

Desktop already keeps these apart: Linux gates body links through the
safe-scheme allowlist in `app/qml/utils/format.js` before
`Qt.openUrlExternally`, and Mac has `RichTextHTML.allowedLinkSchemes`. Keep
them apart. Do not refactor webmail links and body links through one shared
"open a URL" helper — the whole point is that they are different trust
classes, and a shared helper is how a future change accidentally upgrades one
to the other's treatment.

## Per-client action list

**kypost-Linux** — one change:

- `app/qml/pages/EmailDetail.qml:595` — check `Qt.openUrlExternally`'s return
  and show a failure message rather than a dead button.

**kypost-for-Mac** — two changes:

- `KyPost/Domain/Models/PgpMessageState.swift:100` — require
  `scheme?.lowercased() == "https"` in `webmailReadComponents`, and clear the
  fragment on the base, matching Linux's `webmailReadBase`.
- Both handoff sites — check the open result and surface a failure.

**Neither** should port Custom Tabs, add native-handler precedence, or
introduce an embedded web view for webmail.

## What none of the clients should do: on-device PGP decryption

`E2E_PGP.md`'s superseded section sketched a port of the browser's crypto to
Qt (GPGME or Sequoia) and Android (Bouncy Castle). That remains deferred, and
the reasoning is the same for desktop as for mobile — see
`kypost-android/docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md`
for the full analysis. In short:

- The envelope is wrapped under a key derived from the **account password**,
  which pairing deliberately never learns. Unwrapping on device means
  introducing account-password entry on a device that has never needed it.
- Rewrapping from the device is closed off by design:
  `POST /api/pgp/identity/rewrap` is `withAuth` (session only) and
  `run4_security_fixes_test.go:334` asserts a paired device cannot call it.
- It is **not** an offline win — ciphertext is fetched per message from
  `/api/mail/pgp-payload`, so it needs the network regardless.

The prerequisite that would change this calculus is rewrapping the envelope
under a **separate PGP passphrase** instead of the account password. That is a
browser change (`frontend/src/lib/keyVault.ts`) plus a server flag, not server
cryptography — the server holds only a scrypt hash and cannot derive the
wrapping key. It is worth doing on its own merits regardless of any client:
`E2E_PGP.md` lists "admin password reset destroys the key" as inherent to the
model, and it is inherent only because the wrapping secret *is* the account
password.

## Verification

Each client, with a **client-custody** account:

1. Open an encrypted message showing the lock marker. Use the handoff. Expect
   the user's default browser or PWA, already logged in, on that message.
2. Compose from the same account, trigger the handoff, confirm the draft is
   present in webmail's Drafts.
3. Break the launcher deliberately — on Linux, unset the default browser
   (`xdg-settings set default-web-browser` to something absent) — and confirm
   the UI reports a failure rather than doing nothing.
4. Open a message containing an ordinary link. Confirm it goes out through the
   sender-link path, not the webmail path.
